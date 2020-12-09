import meraki as mer
import pandas as pd
import pickle
import numpy as np
import multiprocessing
import argparse
import random
import math
import time
import netaddr
import csv
import os
import urllib.request
from scapy.layers.inet import IP, TCP, UDP
from tqdm import tqdm
from tqdm.utils import _term_move_up
from netaddr import *
from tabulate import tabulate
from multiprocessing import Pool
from scapy.all import *
from openpyxl import load_workbook
# For the DNS query we may have to do
import dns.resolver
from dns.exception import DNSException
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

# Verbosity
global VERBOSE
VERBOSE = False

# Border for our progress bars
global TERMSIZE
TERMSIZE = 1
try:
    TERMSIZE = int((os.get_terminal_size()).columns)
except OSError as e:
    # Couldnt get the size of the terminal so leaving it at the default of 15
    TERMSIZE = 15

# Multiprocessing speeds
SLOW, MEDIUM, FAST, HOLDONTOYOURBUTTS = 1, 1, 1, 1
coreCount = multiprocessing.cpu_count()
if coreCount == 1:
    SLOW, MEDIUM, FAST, HOLDONTOYOURBUTTS = 1, 1, 1, 1
else:
    if coreCount <= 8:
        SLOW = 1
        MEDIUM = math.floor(coreCount * .5)
        FAST = math.floor(coreCount * .75)
        HOLDONTOYOURBUTTS = coreCount - 1
    else:
        SLOW = 4
        MEDIUM = 6
        FAST = 8
        # I have found that by doing -1 I am making sure to leave room for the overhead and thus improving performance
        HOLDONTOYOURBUTTS = coreCount - 1

# Logs go into a log directory and are $(unix time).log
LOGDIR = os.path.join(os.getcwd(), "logs")
LOGFILEPATH = os.path.join(LOGDIR, str(int(time.time())) + ".log")
# Meraki api calls generate a lot of cruff so we will jam them into here
MERLOGDIR = os.path.join(os.getcwd(), "meraki_logs")
if not os.path.isdir(LOGDIR):
    os.mkdir(LOGDIR)
    LOGFILE = open(LOGFILEPATH, "w")
else:
    LOGFILE = open(LOGFILEPATH, "w")
if not os.path.isdir(MERLOGDIR):
    os.mkdir(MERLOGDIR)

# Creating Excel Directory
if not os.path.isdir('excel'):
    os.mkdir('excel')


# Controls verbose output
# Thanks to this stack overflow post I am able to upgrade this function to handle tqdm progress bars
# https://stackoverflow.com/questions/53874150/python-tqdm-is-there-a-way-to-print-something-between-a-progress-bar-and-what
def printv(m, pbar=None):
    if type(m) is list:
        m = "[" + ', '.join(str(x) for x in m) + "]"
    if VERBOSE:
        if pbar is not None:
            border = "=" * (TERMSIZE)
            clear_border = _term_move_up() + "\r" + " " * len(border) + "\r"
            pbar.write(clear_border + "VERBOSE: %s" % m)
            pbar.write(border)
        else:
            print("VERBOSE: " + m)
        LOGFILE.write("VERBOSE: " + m + "\n")
    else:
        LOGFILE.write("VERBOSE: " + m + "\n")


# This saves an incredible amount of time as gathering client data can take 5-10 minutes on a larger scale
def load_sites(filename):
    sites = pickle.load(open(filename, "rb"))
    return sites


# Used when checking if a string is an int
def is_int(x):
    try:
        num = int(x)
    except ValueError:
        return False
    return True


# client data is the only actual data that can go stale, saving our site variable to a file saves time in future runs
def save_sites(filename, sites):
    pickle.dump(sites, open(filename, "wb"))


def get_vpn_rules(dashboard, organizationId, pbar=None):
    orgRules = []
    printv("Gathering Site-to-Site firewall rules for the organization", pbar)
    try:
        for x, acl in enumerate(
                dashboard.appliance.getOrganizationApplianceVpnVpnFirewallRules(organizationId)['rules'][:-1]):
            # Cleaning up the dict and formatting it accordingly
            tmp = {'#': "VPN-" + str(x + 1).zfill(2), 'comment': acl['comment'], 'policy': acl['policy']}
            # Formatting values
            if 'any' in acl['srcCidr'].lower():
                tmp['srcCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['srcCidr'] = [IPNetwork(network) for network in acl['srcCidr'].split(",")]
            if 'any' in acl['destCidr'].lower():
                tmp['dstCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['dstCidr'] = [IPNetwork(network) for network in acl['destCidr'].split(",")]
            orgRules.append(tmp)
    except mer.exceptions.APIError as e:
        orgRules = None
    return orgRules


def get_org_remote_vpn_participants(dashboard, organizationId, networkId):
    # This shows us what each site is connected to on the S2S VPN
    orgVpnData = dashboard.appliance.getOrganizationApplianceVpnStats(organizationId=organizationId)
    siteVpnData = None
    siteVpnData = [network for network in orgVpnData if network['networkId'] == networkId]
    if siteVpnData is not None:
        siteVpnData = siteVpnData[0]
    peers = [(peer['networkId'], peer['networkName']) for peer in siteVpnData['merakiVpnPeers']]
    peers.append((siteVpnData['networkId'], siteVpnData['networkName']))
    return peers


def get_device_clients(dashboard, device, clientsPBar, n=1.0):
    clientsPBar.set_description("Gathering client data on %s" % device['name'])
    clientData = [c for c in dashboard.devices.getDeviceClients(device['serial'])]
    clientsPBar.update(n)
    clientsPBar.set_description("Gathering LLDP/CDP data on %s" % device['name'])
    portData = dashboard.devices.getDeviceLldpCdp(device['serial'])
    if 'ports' in portData:
        for port, data in portData['ports'].items():
            client = {
                'description': None,
                'dhcpHostname': None,
                'id': None,
                'ip': None,
                'mac': None,
                'mdnsName': None,
                'switchport': port,
                'usage': {'sent': 0.0, 'recv': 0.0},
                'user': None,
                'vlan': None
            }
            # Checking for any LLDP data
            if 'lldp' in portData['ports']:
                if 'managementAddress' in portData['ports'][port]['lldp']:
                    client['ip'] = portData['ports'][port]['lldp']['managementAddress']
                if 'systemName' in portData['ports'][port]['lldp']:
                    client['description'] = portData['ports'][port]['lldp']['systemName']
                if 'portId' in portData['ports'][port]['lldp']:
                    if ":" in portData['ports'][port]['lldp']['portId']:
                        macAddr = portData['ports'][port]['lldp']['portId']
                        macAddr = str(':'.join(macAddr[i:i + 2] for i in range(0, 12, 2))).upper()
                        client['mac'] = macAddr
            # Checking for any CDP data
            if 'cdp' in portData['ports'][port]:
                if client['mac'] is None and 'deviceId' in portData['ports'][port]['cdp']:
                    macAddr = portData['ports'][port]['cdp']['deviceId']
                    macAddr = str(':'.join(macAddr[i:i + 2] for i in range(0, 12, 2))).upper()
                    client['mac'] = macAddr
                else:
                    if 'deviceId' in portData['ports'][port]['cdp'] and client['description'] is None:
                        macAddr = portData['ports'][port]['cdp']['deviceId']
                        macAddr = str(':'.join(macAddr[i:i + 2] for i in range(0, 12, 2))).upper()
                        client['description'] = macAddr
                if client['ip'] is None and 'address' in portData['ports'][port]['cdp']:
                    client['ip'] = portData['ports'][port]['cdp']['address']
            if client['ip'] is not None:
                clientData.append(client)
    device['clients'] = clientData
    clientsPBar.update(n)
    return device


def get_acls(dashboard, networkId, pbar=None):
    # MS ACLs
    msACL = []
    printv("Gathering ACL rules on the MS switches", pbar)
    try:
        for x, acl in enumerate(dashboard.switch.getNetworkSwitchAccessControlLists(networkId)['rules']):
            # Cleaning up the dict and formatting it accordingly
            tmp = {}
            tmp['#'] = "MS-" + str(x + 1).zfill(2)
            tmp['comment'] = acl['comment']
            tmp['policy'] = acl['policy']
            # Formatting values
            if 'any' in acl['srcCidr'].lower():
                tmp['srcCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['srcCidr'] = [IPNetwork(network) for network in acl['srcCidr'].split(",")]
            if 'any' in acl['dstCidr'].lower():
                tmp['dstCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['dstCidr'] = [IPNetwork(network) for network in acl['dstCidr'].split(",")]
            msACL.append(tmp)
    except mer.exceptions.APIError as e:
        # printv("meraki.exceptions.APIError: MX L3 firewall, getNetworkL3FirewallRules - 4prompt Not Found")
        # printi("This network does not have an MX appliance")
        msACL = []
    # MX Firewall
    mxFW = []
    printv("Gathering Firewalls rules on the MX appliances", pbar)
    try:
        for x, acl in enumerate(
                dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(networkId)['rules'][:-1]):
            # Cleaning up the dict and formatting it accordingly
            tmp = {}
            tmp['#'] = "MX-" + str(x + 1).zfill(2)
            tmp['comment'] = acl['comment']
            tmp['policy'] = acl['policy']
            # Formatting values
            if 'any' in acl['srcCidr'].lower():
                tmp['srcCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['srcCidr'] = [IPNetwork(network) for network in acl['srcCidr'].split(",")]
            if 'any' in acl['destCidr'].lower():
                tmp['dstCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['dstCidr'] = [IPNetwork(network) for network in acl['destCidr'].split(",")]
            mxFW.append(tmp)
    except mer.exceptions.APIError as e:
        # printv("meraki.exceptions.APIError: MX L3 firewall, getNetworkL3FirewallRules - 4prompt Not Found")
        # printi("This network does not have an MX appliance")
        mxFW = []
    return msACL, mxFW


def get_vlan_name(v, sites):
    if v == '6.6.6.6/6':
        return "Internet"
    for site in sites:
        for vlan in site['VLANS']:
            if vlan['subnet'] in IPNetwork(v):
                return vlan['name']
    return 'Unknown'


# Next we get our service names from ports csv from iana
# The functionality and purpose of this did not make it to v1.0 but may in the future
def get_port_data(filename):
    columns = ['Port Number', 'Transport Protocol', 'Description']
    url = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'
    portData = pd.read_csv(url, usecols=columns)
    pickle.dump(portData, open('portData.pkl', "wb"))
    return portData


# https://stackoverflow.com/questions/55929578/python-using-pyshark-to-parse-pcap-file
# https://github.com/secdevopsai/Packet-Analytics/blob/master/Packet-Analytics.ipynb
# Modifying the code found in this guide to get our PCAP changed into a dataframe
def pcap_to_csv(filename: str):
    pcap = rdpcap(filename)

    # Collect field names from IP/TCP/UDP (These will be columns in DF)
    ip_fields = [field.name for field in IP().fields_desc]
    tcp_fields = [field.name for field in TCP().fields_desc]
    udp_fields = [field.name for field in UDP().fields_desc]

    dataframe_fields = ip_fields + ['time'] + tcp_fields

    # Create blank DataFrame
    df = pd.DataFrame(columns=dataframe_fields)
    for packet in pcap[IP]:
        # Field array for each row of DataFrame
        field_values = []
        # Add all IP fields to dataframe
        for field in ip_fields:
            if field == 'options':
                # Retrieving number of options defined in IP Header
                field_values.append(len(packet[IP].fields[field]))
            else:
                field_values.append(packet[IP].fields[field])

        field_values.append(packet.time)

        layer_type = type(packet[IP].payload)
        for field in tcp_fields:
            try:
                if field == 'options':
                    field_values.append(len(packet[layer_type].fields[field]))
                else:
                    field_values.append(packet[layer_type].fields[field])
            except:
                field_values.append(None)

        # Add row to DF
        df_append = pd.DataFrame([field_values], columns=dataframe_fields)
        df = pd.concat([df, df_append], axis=0)

    # Adjusting the time values
    df['time'] = df['time'].apply(lambda x: float(x))
    df.reset_index(drop=True, inplace=True)
    df.sort_values('time')
    df.reset_index(drop=True, inplace=True)

    # Converting the protocol numbers to name
    # https://stackoverflow.com/questions/37004965/how-to-turn-protocol-number-to-name-with-python
    table = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
    df['proto'] = df['proto'].apply(lambda x: x if x not in table else table[x])

    # Renaming our columns to match the names we will eventually expect
    columnMap = {
        'src': 'Source address',
        'dst': 'Destination address',
        'dport': 'Destination Port',
        'proto': 'IP Protocol',
        'time': 'Receive Time',
    }
    df.rename(columns=columnMap, inplace=True)
    df['Application'] = 'None'

    # Saving the dataframe to CSV
    f = filename.split(".")[0] + ".csv"
    df.to_csv(f, index=False)

    return f


# Setting up our multiprocessing speed
def get_speed(length: int) -> int:
    if length < 1000:
        return SLOW
    elif 1000 <= length < 50000:
        return MEDIUM
    elif 50000 <= length <= 500000:
        return FAST
    else:
        return HOLDONTOYOURBUTTS


def convert_to_bytes(dfBytes, to, bsize=1024):
    a = {'k': 1, 'm': 2, 'g': 3, 't': 4, 'p': 5, 'e': 6}
    r = float(dfBytes)
    return dfBytes / (bsize ** a[to])


def get_ip_data_caller(chunk):
    sites = pickle.load(open('sites.pkl', "rb"))
    discovered = dict()
    chunk['temp'] = chunk.apply(get_ip_data, sites=sites, discovered=discovered, axis=1)
    chunk[['SrcSite', 'SrcLocation', 'SrcVlanID', 'SrcVlanName',
           'SrcVlanSubnet', 'SrcVlanLocation', 'DstSite', 'DstLocation',
           'DstVlanID', 'DstVlanName', 'DstVlanSubnet', 'DstVlanLocation']] = \
        chunk.temp.str.split(";", expand=True)
    del chunk['temp']
    return chunk


# This will take the IP and output which site (network) they are in, their vlan info, and their location if possible
def get_ip_data(row, sites, discovered):
    # Information that we need
    srcDone = False
    srcData = {
        'srcIp': row['SrcIP'],
        'srcSite': None,
        'srcLocation': None,
        'srcVlanId': None,
        'srcVlanName': None,
        'srcVlanSubnet': None,
        'srcVlanLocation': None
    }

    dstDone = False
    dstData = {
        'dstIp': row['DstIP'],
        'dstSite': None,
        'dstLocation': None,
        'dstVlanId': None,
        'dstVlanName': None,
        'dstVlanSubnet': None,
        'dstVlanLocation': None
    }

    # Checking if we already discovered source
    if row['SrcIP'] in discovered:
        srcData = {
            'srcSite': discovered[row['SrcIP']]['Site'],
            'srcLocation': discovered[row['SrcIP']]['Location'],
            'srcVlanId': discovered[row['SrcIP']]['VlanId'],
            'srcVlanName': discovered[row['SrcIP']]['VlanName'],
            'srcVlanSubnet': discovered[row['SrcIP']]['VlanSubnet'],
            'srcVlanLocation': discovered[row['SrcIP']]['VlanLocation']
        }
        srcDone = True

    # Checking if we already discovered destination
    if row['DstIP'] in discovered:
        dstData = {
            'dstSite': discovered[row['DstIP']]['Site'],
            'dstLocation': discovered[row['DstIP']]['Location'],
            'dstVlanId': discovered[row['DstIP']]['VlanId'],
            'dstVlanName': discovered[row['DstIP']]['VlanName'],
            'dstVlanSubnet': discovered[row['DstIP']]['VlanSubnet'],
            'dstVlanLocation': discovered[row['DstIP']]['VlanLocation']
        }
        dstDone = True

    # First thing that we need to handle are the public IP-es
    # (addr.dst notin 10.0.0.0/8) OR (addr.dst notin 172.16.0.0/12) OR (addr.dst notin 192.168.0.0/16)
    if not srcDone and not srcData['srcIp'].is_private():
        srcData['srcSite'] = 'Internet'
        srcData['srcLocation'] = 'None'
        srcData['srcVlanId'] = 'None'
        srcData['srcVlanName'] = 'None'
        # For when we build out our firewall rules we will use this IPNetwork to define the internet
        srcData['srcVlanSubnet'] = IPNetwork('6.6.6.6/32')
        srcData['srcVlanLocation'] = 'None'
        srcDone = True
    if not dstDone and not dstData['dstIp'].is_private():
        dstData['dstSite'] = 'Internet'
        dstData['dstLocation'] = 'None'
        dstData['dstVlanId'] = 'None'
        dstData['dstVlanName'] = 'Internet'
        # For when we build out our firewall rules we will use this IPNetwork to define the internet
        dstData['dstVlanSubnet'] = IPNetwork('6.6.6.6/32')
        dstData['dstVlanLocation'] = 'None'
        dstDone = True

    # If for some reason both the source and destination are internet addresses then this row is done
    # This will also trigger if we have already processed the previous two IPes
    if srcDone and dstDone:
        if 'dstIp' in dstData:
            del dstData['dstIp']
        if 'srcIp' in srcData:
            del srcData['srcIp']
        return ';'.join([str(v) for v in srcData.values()] + [str(v) for v in dstData.values()])

    for site in sites:

        # Checking to see if we need to even look at this site
        skipSrc = False
        skipDst = False
        if not srcDone:
            if not any(cidr for cidr in site['Cidrs'] if srcData['srcIp'] in cidr):
                skipSrc = True
        else:
            skipSrc = True
        if not dstDone:
            if not any(cidr for cidr in site['Cidrs'] if dstData['dstIp'] in cidr):
                skipDst = True
        else:
            skipDst = True
        if skipSrc and skipDst:
            continue

        # First thing we will go through are our VLANs since those yield the most amount of information
        for vlan in site['VLANS']:
            if (srcData['srcVlanName'] is not None or skipSrc) and (dstData['dstVlanName'] is not None or skipDst):
                # printv("breaking 1")
                break
            # Source VLAN Information
            if not skipSrc and srcData['srcVlanName'] is None:
                # printv("checking source")
                if srcData['srcIp'] in vlan['subnet']:
                    # printv("%s is in the vlan" % str(srcData['srcIp']))
                    srcData['srcSite'] = site['Name']
                    srcData['srcVlanId'] = vlan['vlanId']
                    srcData['srcVlanName'] = vlan['name'].strip()
                    srcData['srcVlanSubnet'] = vlan['subnet']
                    srcData['srcVlanLocation'] = vlan['location']
            # Destination VLAN Information
            if not skipDst and dstData['dstVlanName'] is None:
                # printv("checking dest")
                if dstData['dstIp'] in vlan['subnet']:
                    # printv("%s is in the vlan" % str(dstData['dstIp']))
                    dstData['dstSite'] = site['Name']
                    dstData['dstVlanId'] = vlan['vlanId']
                    dstData['dstVlanName'] = vlan['name'].strip()
                    dstData['dstVlanSubnet'] = vlan['subnet']
                    dstData['dstVlanLocation'] = vlan['location']

        # Now we can try and get the location of the device by using the site client data
        for device in site['Devices']:
            srcLocation = []
            dstLocation = []
            if (srcData['srcLocation'] is not None or skipSrc) and (dstData['dstLocation'] is not None or skipDst):
                break
            for client in device['clients']:
                if (srcData['srcLocation'] is not None or skipSrc) and (dstData['dstLocation'] is not None or skipDst):
                    break
                # Source Location
                if not skipSrc and srcData['srcLocation'] is None and \
                        client['ip'] is not None and \
                        srcData['srcIp'] == IPNetwork(client['ip']):
                    srcLocation.append(str(device['name'] + "-" + str(client['switchport'])))
                # Destination Location
                if not skipDst and dstData['dstLocation'] is None and \
                        client['ip'] is not None and \
                        dstData['dstIp'] == IPNetwork(client['ip']):
                    dstLocation.append(str(device['name'] + "-" + str(client['switchport'])))
            if len(srcLocation) != 0:
                srcData['srcLocation'] = " / ".join(srcLocation)
            if len(dstLocation) != 0:
                dstData['dstLocation'] = " / ".join(dstLocation)

        # Lastly we check if we have all the information we need and thus can stop checking other sites
        if (srcData['srcLocation'] is not None) and (dstData['dstLocation'] is not None) and \
                (srcData['srcVlanName'] is not None) and (dstData['dstVlanName'] is not None):
            break

    # Now we do one final check before we return our data
    # If we were unable to get the information we needed then we will replace the None values with 'Unknown'
    for k, v in dstData.items():
        if v is None:
            # printv("dst %s was None" % k)
            if k == 'dstSite':
                # Because the ACL/FW/VPN section requires this to actually be set we are going to make a few assumptions
                # If this was a public IP then it would have been caught above
                # Thus this has to be a private IP and thus it has to be within the same site as the Source
                # This is of course not 100%. Maybe the IP is supposed to be in another site
                # However, it is safer to assume it is in the same site then guess which one it is
                dstData['dstSite'] = srcData['srcSite']
            else:
                dstData[k] = 'Unknown'
    for k, v in srcData.items():
        if v is None:
            # printv("src %s was None" % k)
            if k == 'srcSite':
                # See above
                srcData['srcSite'] = dstData['dstSite']
            else:
                srcData[k] = 'Unknown'
    # Lastly, since we are capturing from WDC, if both are unknown then they both are WDC
    if dstData['dstSite'] is None and srcData['srcSite'] is None:
        dstData['dstSite'] = 'WDC'
        srcData['srcSite'] = 'WDC'

    if 'dstIp' in dstData:
        del dstData['dstIp']
    if 'srcIp' in srcData:
        del srcData['srcIp']
    discovered[row['SrcIP']] = {
        'Site': srcData['srcSite'],
        'Location': srcData['srcLocation'],
        'VlanId': srcData['srcVlanId'],
        'VlanName': srcData['srcVlanName'],
        'VlanSubnet': srcData['srcVlanSubnet'],
        'VlanLocation': srcData['srcVlanLocation']
    }
    discovered[row['DstIP']] = {
        'Site': dstData['dstSite'],
        'Location': dstData['dstLocation'],
        'VlanId': dstData['dstVlanId'],
        'VlanName': dstData['dstVlanName'],
        'VlanSubnet': dstData['dstVlanSubnet'],
        'VlanLocation': dstData['dstVlanLocation']
    }
    ipData = ';'.join([str(v) for v in srcData.values()] + [str(v) for v in dstData.values()])
    return ipData


def update_port_info_caller(chunk):
    portData = pickle.load(open('portData.pkl', 'rb'))
    chunk['PortData'] = chunk.apply(update_port_info, portData=portData, axis=1)
    return chunk


# Making sure port info is correct
def update_port_info(row, portData):
    app = []
    app = [
        p for p in portData
        if str(p['Port Number']) == str(row['DstPort']) and str(p['Transport Protocol']) == str(row['Protocol'])
    ]
    if len(app) == 0:
        return 'Unknown'
    else:
        app = app[0]
    if app['Description'] == 'Unassigned':
        return 'Unknown'
    else:
        return app['Description']
    return 'Unknown'


def get_packet_path_data_caller(chunk):
    sites = pickle.load(open('sites.pkl', 'rb'))
    chunk = chunk.apply(get_packet_path_data, sites=sites, axis=1)
    return chunk


def get_packet_path_data(row, sites):
    # Import Information:
    # There is a gotcha here that we need to be looking out for and that is the fact that ACL is stateless
    # This means that the ACL rule list needs to explicitly allow for the communication to go both ways
    # The MX FW and S2S VPN is stateful so if it allows the packet in then it will allow it back out

    '''
      # Source ACL Out
      # Source ACL In
      # Source Firewall
      # Organization Site to Site
      # Destination Firewall
      # Destination ACL In
      # Destination ACL Out
    '''
    src = row['SrcSite']
    dst = row['DstSite']
    srcIp = row['SrcIP']
    dstIp = row['DstIP']

    # External to Internal or External to External
    if src == "Internet":
        if dst != "Internet":
            # In this case the packet will go through the MX FW and then the MS ACL
            site = [site for site in sites if site['Name'] == dst][0]
            aclList = site['ACL']
            fwList = site['Firewall']
            outImpact, outRuleNumber = get_rule_list_impact(srcIp, dstIp, aclList)
            inImpact, inRuleNumber = get_rule_list_impact(dstIp, srcIp, aclList)
            fwImpact, fwRuleNumber = get_rule_list_impact(srcIp, dstIp, fwList)
            data = "External -> Internal; None; None; None; None; None; None; None; None; %s; %s; %s; %s; %s; %s" % \
                   (fwImpact, fwRuleNumber, inImpact, inRuleNumber, outImpact, outRuleNumber)
            row['temp'] = data
            return row
        else:
            # I honestly have no clue how to handle this one. Ima just put None.
            # Yeah....1 week later still no clue
            data = "External -> External; None; None; None; None; None; None; None; None; None; None; None; None; " \
                   "None; None "
            row['temp'] = data
            return row
    # Internal to Internal
    elif src == dst:
        # Since the source and destination are in the same site we only need to feed the aux function one ACL list
        aclList = [site for site in sites if site['Name'] == src][0]['ACL']
        outImpact, outRuleNumber = get_rule_list_impact(srcIp, dstIp, aclList)
        inImpact, inRuleNumber = get_rule_list_impact(dstIp, srcIp, aclList)
        data = "Internal -> Internal; %s; %s; %s; %s; None; None; None; None; None; None; %s; %s; %s; %s" % \
               (outImpact, outRuleNumber, inImpact, inRuleNumber, outImpact, outRuleNumber, inImpact, inRuleNumber)
        row['temp'] = data
        return row
    # Internal to External
    elif src != "Internet" and dst == "Internet":
        # In this case the packet will go through the MS ACL and then the MX FW
        site = [site for site in sites if site['Name'] == src]
        if len(site) == 0:
            printv("------")
            printv(src)
            printv(dst)
            printv(srcIp)
            printv(dstIp)
            printv("------")
            raise Exception('SOMETHING BAD HAS HAPPENED')
        else:
            site = site[0]
        aclList = site['ACL']
        fwList = site['Firewall']
        outImpact, outRuleNumber = get_rule_list_impact(srcIp, dstIp, aclList)
        inImpact, inRuleNumber = get_rule_list_impact(dstIp, srcIp, aclList)
        fwImpact, fwRuleNumber = get_rule_list_impact(srcIp, dstIp, fwList)
        data = "Internal -> External; %s; %s; %s; %s; %s; %s; None; None; None; None; None; None; None; None" % \
               (outImpact, outRuleNumber, inImpact, inRuleNumber, fwImpact, fwRuleNumber)
        row['temp'] = data
        return row
    # Site to Site
    else:
        # Site to Site will involve the most amount of processing as it has to hit every bump on the road
        srcSite = [site for site in sites if site['Name'] == src]
        if len(srcSite) == 0:
            printv("------")
            printv(src)
            printv(dst)
            printv(srcIp)
            printv(dstIp)
            printv("------")
            raise Exception('SOMETHING BAD HAS HAPPENED')
        else:
            srcSite = srcSite[0]
        dstSite = [site for site in sites if site['Name'] == dst]
        if len(dstSite) == 0:
            printv("------")
            printv(src)
            printv(dst)
            printv(srcIp)
            printv(dstIp)
            printv("------")
            raise Exception('SOMETHING BAD HAS HAPPENED')
        else:
            dstSite = dstSite[0]
        organization = [site for site in sites if site['Name'] == 'Organization'][0]
        srcAclList = srcSite['ACL']
        srcFwList = srcSite['Firewall']
        dstAclList = dstSite['ACL']
        dstFwList = dstSite['Firewall']
        s2sList = organization['VPN Rules']
        # Source ACL out and in
        srcOutImpact, srcOutRuleNumber = get_rule_list_impact(srcIp, dstIp, srcAclList)
        srcInImpact, srcInRuleNumber = get_rule_list_impact(dstIp, srcIp, srcAclList)
        # Source FW
        srcFwImpact, srcFwRuleNumber = get_rule_list_impact(srcIp, dstIp, srcFwList)
        # Organization S2S VPN
        orgImpact, orgRuleNumber = get_rule_list_impact(srcIp, dstIp, s2sList)
        # Destination FW
        dstFwImpact, dstFwRuleNumber = get_rule_list_impact(srcIp, dstIp, dstFwList)
        # Destination ACL in and out
        dstInImpact, dstInRuleNumber = get_rule_list_impact(srcIp, dstIp, dstAclList)
        dstOutImpact, dstOutRuleNumber = get_rule_list_impact(dstIp, srcIp, dstAclList)
        data = "Site -> Site; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s" % \
               (
                   srcOutImpact, srcOutRuleNumber, srcInImpact, srcInRuleNumber, srcFwImpact, srcFwRuleNumber,
                   orgImpact, orgRuleNumber,
                   dstFwImpact, dstFwRuleNumber, dstInImpact, dstInRuleNumber, dstOutImpact, dstOutRuleNumber
               )
        row['temp'] = data
        return row


def get_rule_list_impact(source, destination, ruleList):
    for rule in ruleList:
        # If the source is impacted by the rule then we check the destination
        if any(network for network in rule['srcCidr'] if source in network):
            # If the destination is also impacted then the rule has impact
            if any(network for network in rule['dstCidr'] if destination in network):
                return rule['policy'], rule['#'].split("-")[1]
    # One way or another it should hit a rule so it hitting this return is actually really bad
    return None, None


def format_df_values_caller(chunk, networks=None):
    # Let's say you have a VLAN that the people in HR use, 10.10.10.0/24
    # These people are going to be talking out to the internet constantly
    # If you want to reduce clutter you can change all the public IP-es talking to and from those VLANs to 1 network
    # So instead of having 10.10.10.0/24 listed as talking to 100s of public IP-es
    # it will instead be listed in the data as talking to 6.6.6.6/6
    # For me I did not care if certain VLANs were talking to the internet only that they were in the first place
    # Using the example above we would set ipes to [IPNetwork(10.10.10.0/24)]
    # Maybe someday I will make this a command line argument but alas 24 hours in the day
    ipes = None
    # We have to make this array like this because of how pandas .isin function works
    if ipes is not None:
        ipes = [str(ip) for network in networks for ip in list(network)]
    else:
        ipes = []
    return format_df_values(chunk, ipes)


# See https://github.com/picnicsecurity/Meraki-Traffic-Analyzer#Tailoring-the-Code for an explaination on this code and its purpose
def format_df_values(chunk, ipes):
    col = 'SrcIP'
    # Look...dont judge. This is just something you are going to have to accept and move on
    chunk.loc[
        (chunk[col].isin(ipes)),
        'DstIP'
    ] = chunk.loc[
        (chunk[col].isin(ipes)),
        'DstIP'
    ].apply(
        lambda x: IPNetwork('6.6.6.6/32') if not IPNetwork(x).is_private() else x
    )
    col = 'DstIP'
    # Keep moving
    chunk.loc[
        (chunk[col].isin(ipes)),
        'SrcIP'
    ] = chunk.loc[
        (chunk[col].isin(ipes)),
        'SrcIP'
    ].apply(
        lambda x: IPNetwork('6.6.6.6/32') if not IPNetwork(x).is_private() else x
    )
    chunk['SrcIP'] = chunk['SrcIP'].apply(lambda x: IPNetwork(x))
    chunk['DstIP'] = chunk['DstIP'].apply(lambda x: IPNetwork(x))
    return chunk


def resolve_ip_caller(chunk):
    # This is where we will store previously looked up values
    discovered = dict()
    if os.path.isfile('dns_servers.pkl'):
        servers = pickle.load(open('dns_servers.pkl', "rb"))
    else:
        servers = ['1.1.1.1', '1.0.0.1']
    chunk = chunk.apply(resolve_ip, discovered=discovered, servers=servers, axis=1)
    return chunk


def resolve_ip(row, discovered, servers):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = servers
    resolver.timeout = 1
    resolver.lifetime = 1
    src = row['SrcIP']
    dst = row['DstIP']
    # SOURCE
    tmp = str(src).strip().split("/")[0].split(".")
    tmp.reverse()
    inaddr = ".".join(tmp) + ".in-addr.arpa"
    if inaddr in discovered:
        row['SrcName'] = discovered[inaddr]
    else:
        try:
            result = resolver.query(inaddr, 'PTR')
            name = str(result[0].to_text())[:-1]
            row['SrcName'] = name
            # discovered[inaddr] = name
        except DNSException as e:
            row['SrcName'] = 'Unknown'
            # discovered[inaddr] = 'Unknown'
    # DESTINATION
    tmp = str(dst).strip().split("/")[0].split(".")
    tmp.reverse()
    inaddr = ".".join(tmp) + ".in-addr.arpa"
    if inaddr in discovered:
        row['DstName'] = discovered[inaddr]
    else:
        try:
            result = resolver.query(inaddr, 'PTR')
            name = str(result[0].to_text())[:-1]
            row['DstName'] = name
            discovered[inaddr] = name
        except DNSException as e:
            row['DstName'] = 'Unknown'
            discovered[inaddr] = 'Unknown'
    return row


# This is where the true magic happens. Without this function, our program would take literally forever to finish
# In the next version I will add support for **kwargs so that we can bypass the need to have these "caller" functions. Itll also give us a lot more features
def parallelize_workload(data, function, n_cores):
    printv("%s is being called with %d cores" % (function.__name__, n_cores))

    if n_cores == 1:
        pbar = tqdm(total=n_cores + 2)
        pbar.set_description('Parallel Workload Status')
        data = function(data)
        while pbar.n < pbar.total:
            pbar.update()
        pbar.close()
        return data
    else:
        pbar = tqdm(total=n_cores + 2)
        pbar.set_description('Parallel Workload Status')
        dfSplit = np.array_split(data, n_cores)
        pool = Pool(n_cores)
        poolMap = []

        # Inner function to help display status
        def status_update(retval):
            poolMap.append(retval)
            pbar.update()

        for chunk in dfSplit:
            pool.apply_async(func=function, args=[chunk], callback=status_update)

        pool.close()
        pool.join()
        pbar.update()
        data = pd.concat(poolMap)
        while pbar.n < pbar.total:
            pbar.update()
        pbar.close()
        return data


# A site is defined as a Meraki network
# This loads up a bunch of data about all of the sites of the organization into a variable for use throughout the script
def get_sites(dashboard, organizationId, networks, get_clients=False):
    sites = []

    # First thing we do is gather some globals
    organization = dashboard.organizations.getOrganization(organizationId)
    s2sRules = get_vpn_rules(dashboard, organizationId, None)
    organizationWide = {
        'Name': 'Organization',
        'Organization Name': organization['name'],
        'VPN Rules': s2sRules,
        'NetworkID': organization['id'],
        'Devices': [],
        'Clients': [],
        'VLANS': [],
        'Peers': [],
        'VPNSubnets': [],
        'ACL': [],
        'Firewall': [],
        'Cidrs': []
    }
    sites.append(organizationWide)

    for network in networks:

        sitesPBar = tqdm(range(0, 100), leave=True)
        sitesPBar.set_description("Processing %s" % network['name'])

        # Site Name and ID
        printv("Gathering identifiers", sitesPBar)
        siteName = network['name']
        networkId = network['id']
        sitesPBar.update(20)

        # VPN Subnets
        if "appliance" in network["productTypes"]:
            tic = time.perf_counter()
            printv("Gathering VPN data", sitesPBar)
            peers = get_org_remote_vpn_participants(dashboard, organizationId, networkId)
            sitesPBar.update(10)
            vpnSubnets = [
                IPNetwork(subnet['localSubnet'])
                for subnet in dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn(networkId)['subnets']
                if subnet['useVpn']
            ]
            toc = time.perf_counter()
            printv(f"Gathering VPN data took {toc - tic:0.4f} seconds to process", sitesPBar)
            sitesPBar.update(10)
        else:
            sitesPBar.update(20)

        # VLANs
        if "switch" in network["productTypes"]:
            tic = time.perf_counter()
            printv("Gathering VLAN data from switch stacks", sitesPBar)
            vlanList = []
            checkedSerials = []
            cidrList = []
            # Grabbing VLANs from any MS series switches starting with switch stacks
            try:
                for stack in dashboard.switch.getNetworkSwitchStacks(networkId):
                    for serial in stack['serials']:
                        checkedSerials.append(serial)
                    for vlan in dashboard.switch.getNetworkSwitchStackRoutingInterfaces(networkId=networkId,
                                                                                        switchStackId=stack['id']):
                        vlan['subnet'] = IPNetwork(vlan['subnet'])
                        if vlan['subnet'] in vpnSubnets:
                            vlan['inVpn'] = True
                        else:
                            vlan['inVpn'] = False
                        vlan['MS'] = True
                        vlan['location'] = stack['name']
                        cidrList.append(vlan['subnet'])
                        vlanList.append(vlan)
            except mer.exceptions.APIError as e:
                # This error will be thrown when dealing with networks that do not have switch stacks
                # In the context of my organization this is our AWS Virtual MX
                printv("No switch stacks in this network", sitesPBar)

            sitesPBar.update(2.5)
            # Next we check for any layer 3 interfaces on switches that are not in stacks

            # Gathering the devices
            ttic = time.perf_counter()
            printv("Gathering VLAN data from switches", sitesPBar)
            devices = [device for device in dashboard.networks.getNetworkDevices(networkId=networkId)
                       if 'MS' in device['model'] or 'MR' in device['model']]
            for device in devices:
                if 'name' not in device:
                    device['name'] = device['mac']
            devices.sort(key=lambda x: x['name'], reverse=True)
            sitesPBar.update(2.5)
            ttoc = time.perf_counter()
            printv(f"Gathering devices took {ttoc - ttic:0.4f} seconds to process", sitesPBar)

            # Checking for layer 3 interfaces
            for device in devices:
                if device['serial'] in checkedSerials or 'MS' not in device['model']:
                    continue
                else:
                    for vlan in dashboard.switch.getDeviceSwitchRoutingInterfaces(device['serial']):
                        vlan['subnet'] = IPNetwork(vlan['subnet'])
                        if vlan['subnet'] in vpnSubnets:
                            vlan['inVpn'] = True
                        else:
                            vlan['inVpn'] = False
                        vlan['MS'] = True
                        vlan['location'] = device['name']
                        cidrList.append(vlan['subnet'])
                        vlanList.append(vlan)
            sitesPBar.update(2.5)
        else:
            sitesPBar.update(7.5)

        # Lastly we get any VLANs that might be on the MX
        if "appliance" in network["productTypes"]:
            printv("Gathering VLAN data from MX security appliances", sitesPBar)
            try:
                for vlan in dashboard.appliance.getNetworkApplianceVlans(networkId):
                    vlan['vlanId'] = vlan['id']
                    vlan['subnet'] = IPNetwork(vlan['subnet'])
                    if vlan['subnet'] in vpnSubnets:
                        vlan['inVpn'] = True
                    else:
                        vlan['inVpn'] = False
                    vlan['MS'] = False
                    vlan['location'] = 'Appliance'
                    cidrList.append(vlan['subnet'])
                    vlanList.append(vlan)
            except mer.exceptions.APIError:
                printv("No VLANs exist on security appliance and or no security appliance exists", sitesPBar)
            sitesPBar.update(2.5)
            toc = time.perf_counter()
            printv(f"Gathering VLAN data took {toc - tic:0.4f} seconds to process", sitesPBar)
        else:
            sitesPBar.update(2.5)

        # This can shave off a couple of iterations by allowing us to determine if an ip is even going to be in a site
        # Rather than going over 80 VLANs we instead go over 10 cidrs. Having to do 10 extra iterations is worth it
        # if we can save ourself from having to do 70 more
        # You will see this come into play in the get_ip_data function
        printv("Consolidating site's subnets into CIDR list", sitesPBar)
        cidrs = cidr_merge(cidrList)
        sitesPBar.update(10)

        tic = time.perf_counter()
        clientsFound = False
        if not get_clients:
            printv("Gathering client data from the site's devices", sitesPBar)
            if os.path.isfile('sites.pkl.old'):
                printv("Loading previous clients data", sitesPBar)
                sites_bkp = load_sites('sites.pkl.old')
                site_bkp = [site for site in sites_bkp if site['Name'] == siteName]
                if len(site_bkp) > 0:
                    clients = site_bkp[0]['Clients']
                    for device in site_bkp[0]['Devices']:
                        # Getting current matching device
                        dev = [d for d in devices if d['mac'] == device['mac']]
                        if len(dev) > 0:
                            dev[0]['clients'] = device['clients']
                    devs = [d for d in devices if 'clients' not in d]
                    if len(devs) > 0:
                        # This is one of things you are just going to have to accept and move on
                        n = float(str("{:.2f}".format((10 / (len(devs) * 2)))))
                        for device in devices:
                            if 'clients' not in device:
                                printv("%s did not have any client data backed up" % device['name'], sitesPBar)
                                device = get_device_clients(dashboard, device, sitesPBar, n)
                    clientsFound = True
                    sitesPBar.update(10)
                else:
                    printv("No client data for this site found and so we will have to get that data now", sitesPBar)
            else:
                printv("No sites pickle found and so we will have to get that data now", sitesPBar)

        if not clientsFound:
            if len(devices) > 0:
                n = float(str("{:.2f}".format((10 / (len(devices) * 2)))))
            else:
                n = 1.0
            printv("Gathering client data from the site's devices", sitesPBar)
            for device in devices:
                device = get_device_clients(dashboard, device, sitesPBar, n)
            sitesPBar.update(10)
        # In case our floats didnt get us perfectly to the 70% we are supposed to be at
        sitesPBar.n = 70
        sitesPBar.refresh()
        sitesPBar.set_description("Processing %s" % network['name'])
        toc = time.perf_counter()
        printv(f"Gathering device client data took {toc - tic:0.4f} seconds to process", sitesPBar)

        # I have been getting random 502 Bad Gateway errors with this api call which is unfortunate
        # This would be the much more ideal way of getting the clients on the network
        # The 'clients' property I added on to each device is messy at best but until this works its our only option
        if "appliance" in network["productTypes"] or "switch" in network["productTypes"]:
            tic = time.perf_counter()
            printv("Gathering a sample of the network client data", sitesPBar)
            clients = dashboard.networks.getNetworkClients(networkId)
            sitesPBar.update(10)
            toc = time.perf_counter()
            printv(f"Gathering network client data took {toc - tic:0.4f} seconds to process", sitesPBar)

            # Getting ACL and Firewall Rules
            tic = time.perf_counter()
            printv("Gathering MS ACL and MX Firewall data", sitesPBar)
            msACL, mxFW = get_acls(dashboard, networkId, sitesPBar)
            sitesPBar.update(20)
            toc = time.perf_counter()
            printv(f"Gathering ACL and FW data took {toc - tic:0.4f} seconds to process", sitesPBar)
        else:
            sitesPBar.update(30)

        printv("Creating site dictionary", sitesPBar)
        site = {
            'Name': siteName,
            'NetworkID': networkId,
            'Devices': devices,
            'Clients': clients,
            'VLANS': vlanList,
            'Peers': peers,
            'VPNSubnets': vpnSubnets,
            'ACL': msACL,
            'Firewall': mxFW,
            'Cidrs': cidrs
        }
        sites.append(site)
        sitesPBar.close()
        print(("-" * (TERMSIZE)) + "\n")
    return sites


# excempt_ipes is variable that will get added in the next version. If you have hosts in your network that you are well aware of, like Naigos or Splunk,
# that make a lot of noise, you can filter them out automatically with this variable
def enrich_traffic_data(filename, columns, pretty=False, DNS=False, excempt_ipes=[]):
    ttic = time.perf_counter()
    columnMap = {
        'Receive Time': 'Timestamp',
        'Source address': 'SrcIP',
        'Destination address': 'DstIP',
        'IP Protocol': 'Protocol',
        'Destination Port': 'DstPort'
    }
    if 'Application' in columns:
        columnMap['Application'] = 'PortInfo'

    ###                    ###
    ### DATAFRAME CREATION ###
    ###                    ###
    # We start our pandas journey by making our dataframe
    tic = time.perf_counter()
    trafficDataFrame = pd.read_csv(filename, usecols=list(columnMap.keys()), low_memory=False)
    printv("Current length dataset is %d" % len(trafficDataFrame))
    # Renaming our columns using the above dict so that others hopefully only need to make adjustments in one spot
    trafficDataFrame.rename(columns=columnMap, inplace=True)
    # Removing any rows that are all NaN or where either SrcIP or DstIP are NaN
    trafficDataFrame.dropna(how='all', inplace=True)
    trafficDataFrame = trafficDataFrame[trafficDataFrame['SrcIP'].notna()]
    trafficDataFrame = trafficDataFrame[trafficDataFrame['DstIP'].notna()]
    toc = time.perf_counter()
    printv(f"Loading and formatting dataset took {toc - tic:0.4f} seconds to process")
    printv("Current length dataset is %d" % len(trafficDataFrame))
    printv("Initial Dataframe Memory Usage")
    printv(f"{convert_to_bytes(trafficDataFrame.memory_usage(index=True, deep=True).sum(), 'm', bsize=1024):0.4f} mb")

    ###                   ###
    ### FORMATTING VALUES ###
    ###                   ###
    # Changing our list of IPes into IPNetwork objects
    printv("Formatting the IP Section")
    tic = time.perf_counter()
    printv("Length of all the IPes %d" % (len(trafficDataFrame['SrcIP']) + len(trafficDataFrame['DstIP'])))
    speed = get_speed(len(trafficDataFrame))
    tic = time.perf_counter()
    trafficDataFrame = parallelize_workload(data=trafficDataFrame, function=format_df_values_caller, n_cores=speed)
    toc = time.perf_counter()
    printv(f"Formatting the IPes took {toc - tic:0.4f} seconds to process")
    '''
     # I ran out of time to add this feature but in the future I would like to make best guesses at what 
     # service is being used. If we see that it is TCP 80 then we can guess it is HTTP for example
    '''
    if 'Application' in columnMap:
        del columnMap['Application']
        del trafficDataFrame['PortInfo']
    del trafficDataFrame['Protocol']
    del trafficDataFrame['DstPort']
    del columnMap['IP Protocol']
    del columnMap['Destination Port']
    '''
    trafficDataFrame['PortInfo'].replace(
        [['incomplete', 'insufficient-data', 'unknown-udp', 'Unknown-udp',
          'unknown-tcp', 'Unknown-tcp', 'Unknown', 'unknown']],
        'Unknown',
        regex=True,
        inplace=True
    )
    '''
    toc = time.perf_counter()
    printv(f"Formatting the dataset took {toc - tic:0.4f} seconds to process")

    ###                     ###
    ### REMOVING DUPLICATES ###
    ###                     ###
    # Now we further reduce down our trafficDataFrame by grouping the objects on SrcIP->DstIP @ DstPort w/ Protocol
    printv("Traffic DataFrame memory usage before duplicates are grouped (n=%d)" % len(trafficDataFrame))
    printv(f"{convert_to_bytes(trafficDataFrame.memory_usage(index=True, deep=True).sum(), 'm', bsize=1024):0.4f} mb")
    tic = time.perf_counter()
    # First thing we will need to do is drop our 'Receive Time'/'Timestamp' column
    del trafficDataFrame['Timestamp']
    del columnMap['Receive Time']
    dfPivot = pd.pivot_table(
        trafficDataFrame, index=list(columnMap.values()), aggfunc='size', fill_value=0
    ).reset_index(level=-1)
    dfPivot.rename(columns={0: 'Count'}, inplace=True)
    dfPivot.columns.name = None
    dfPivot = dfPivot.reset_index()
    trafficDataFrame = dfPivot[['Count', 'SrcIP', 'DstIP']]
    toc = time.perf_counter()
    printv(f"Grouping the dataset took {toc - tic:0.4f} seconds to process")
    printv("Duplicates Grouped (n=%d)" % len(trafficDataFrame))
    printv(f"{convert_to_bytes(dfPivot.memory_usage(index=True, deep=True).sum(), 'm', bsize=1024):0.4f} mb")
    # Lastly we cleanup by deleting the temporary data frame and triggering a garbage collection
    lst = [dfPivot]
    del dfPivot
    del lst
    # Putting the biggest talkers at the top of the list
    printv("Sorting the dataset by count (n=%d)" % len(trafficDataFrame))
    tic = time.perf_counter()
    trafficDataFrame = trafficDataFrame.sort_values('Count', ascending=False)
    trafficDataFrame.reset_index(drop=True, inplace=True)
    toc = time.perf_counter()
    printv(f"Sorting the dataset took {toc - tic:0.4f} seconds to process")

    ###         ###
    ### IP DATA ###
    ###         ###
    # Setting up our multiprocessing speed
    speed = get_speed(len(trafficDataFrame))
    printv("Setting the multiprocessing speed to %d" % speed)
    newCols = [
        'SrcSite', 'SrcLocation', 'SrcVlanID', 'SrcVlanName', 'SrcVlanSubnet', 'SrcVlanLocation',
        'DstSite', 'DstLocation', 'DstVlanID', 'DstVlanName', 'DstVlanSubnet', 'DstVlanLocation'
    ]
    for col in newCols:
        trafficDataFrame[col] = 'None'
        trafficDataFrame.loc[:, col] = None
    tic = time.perf_counter()
    trafficDataFrame = parallelize_workload(data=trafficDataFrame, function=get_ip_data_caller, n_cores=speed)
    # trafficDataFrame = get_ip_data_caller(trafficDataFrame)
    trafficDataFrame = trafficDataFrame.sort_values('Count', ascending=False)
    toc = time.perf_counter()
    printv(f"Getting IP Data took {toc - tic:0.4f} seconds to process")
    printv("IP Data has been fleshed out. Moving on to traffic flow rules")
    # We need to reorder the newly obtained information into their correct places
    trafficDataFrame = trafficDataFrame[
        [
            'Count',
            'SrcIP', 'SrcSite', 'SrcLocation', 'SrcVlanID', 'SrcVlanName', 'SrcVlanSubnet', 'SrcVlanLocation',
            'DstIP', 'DstSite', 'DstLocation', 'DstVlanID', 'DstVlanName', 'DstVlanSubnet', 'DstVlanLocation'
        ]
    ]

    ###              ###
    ### TRAFFIC FLOW ###
    ###              ###
    # Now it is time to move on to the traffic flow section
    # First we will make our new columns
    # Yes I am aware that this is a metric shit ton of columns but there is a metric shit ton that goes on to get
    # your packets from point a to point b so if you are tracing down issues, this information will be critical
    newCols = [
        'PathType',
        'Src ACL Out Impact', 'Src ACL Out Rule', 'Src ACL In Impact', 'Src ACL In Rule',
        'Src Firewall Impact', 'Src Firewall Rule',
        'Org VPN Impact', 'Org VPN Rule',
        'Dst Firewall Impact', 'Dst Firewall Rule',
        'Dst ACL In Impact', 'Dst ACL In Rule', 'Dst ACL Out Impact', 'Dst ACL Out Rule'
    ]
    for col in newCols:
        trafficDataFrame[col] = 'None'
        trafficDataFrame.loc[:, col] = None

    # Setting up our multiprocessing speed
    speed = get_speed(len(trafficDataFrame))
    printv("Setting the multiprocessing speed to %d" % speed)

    # Taking our as trimmed down as possible list and sending it through the enrichantor
    tic = time.perf_counter()
    trafficDataFrame = parallelize_workload(data=trafficDataFrame, function=get_packet_path_data_caller, n_cores=speed)
    # trafficDataFrame = get_packet_path_data_caller(trafficDataFrame)
    toc = time.perf_counter()
    printv(f"Getting Traffic Flow Data Parallel took {toc - tic:0.4f} seconds to process")
    # Now we perform just a sprinkle of black magic
    trafficDataFrame[newCols] = trafficDataFrame.temp.str.split(";", expand=True)
    del trafficDataFrame['temp']

    ###      ###
    ### DNS  ###
    ###      ###
    newCols = ['SrcName', 'DstName']
    for col in newCols:
        trafficDataFrame[col] = 'None'
        trafficDataFrame.loc[:, col] = None
    if DNS:
        printv("Starting DNS Queries")
        tic = time.perf_counter()
        # This is a little tricky since the work needing to be done is simple
        # This means that I could in theory spin up a bunch of processes and get it done quicker
        # However, since I use a dictionary in each process to keep track of looked up values to reduce time
        # If I slice the dataframe up into smaller pieces then I dam reducing the chances of that having an impact
        # The best solution I can come up with is to slice it into more but first sort it by IP
        # This will have the highest chance for the dict to have its highest impact while still saturating our cores
        trafficDataFrame = trafficDataFrame.sort_values('SrcIP')
        speed = int(multiprocessing.cpu_count() * 1.25)
        trafficDataFrame = parallelize_workload(data=trafficDataFrame, function=resolve_ip_caller, n_cores=speed)
        # trafficDataFrame = resolve_ip_caller(trafficDataFrame)
        trafficDataFrame = trafficDataFrame.sort_values('Count', ascending=False)
        toc = time.perf_counter()
        printv(f"Getting DNS information took {toc - tic:0.4f} seconds to process")

    printv("Enrichment process finished")
    ttoc = time.perf_counter()
    printv("--- " * 5)
    printv(f"Dataset took {ttoc - ttic:0.4f} seconds to process")
    printv("--- " * 5)

    if pretty:
        slices = [
            ['Count', 'SrcIP', 'DstIP'],
            ['SrcSite', 'SrcLocation', 'SrcVlanID', 'SrcVlanName', 'SrcVlanSubnet', 'SrcVlanLocation'],
            ['DstSite', 'DstLocation', 'DstVlanID', 'DstVlanName', 'DstVlanSubnet', 'DstVlanLocation'],
            ['PathType'],
            ['Src ACL Out Impact', 'Src ACL Out Rule', 'Src ACL In Impact', 'Src ACL In Rule', 'Src Firewall Impact',
             'Src Firewall Rule'],
            ['Org VPN Impact', 'Org VPN Rule'],
            ['Dst Firewall Impact', 'Dst Firewall Rule', 'Dst ACL In Impact', 'Dst ACL In Rule', 'Dst ACL Out Impact',
             'Dst ACL Out Rule']
        ]
        if DNS:
            slices[0] = ['Count', 'SrcIP', 'SrcName', 'DstIP', 'DstName']
            # This puts everything in order
            columnList = [item for slice in slices for item in slice]
            trafficDataFrame = trafficDataFrame[columnList]
        for slice in slices:
            temp = trafficDataFrame.head(15)[slice]
            temp.reset_index(inplace=True)
            temp.rename(columns={'index': '#'}, inplace=True)
            print(tabulate(temp.to_dict('records'), headers="keys", tablefmt="fancy_grid"))

    return trafficDataFrame


def format_df_for_excel(df, sites, filename):
    # The dataframe we are being passed is the one from the enrich_traffic_data function
    # Since we are making rules based on their VLAN and not IP, the first we need to do is modify the dataframe
    tic = time.perf_counter()
    printv("Flattening dataset (n=%d)" % len(df))
    df.loc[df['SrcVlanSubnet'] == 'Unknown', 'SrcVlanSubnet'] = df.loc[df['SrcVlanSubnet'] == 'Unknown', 'SrcIP']
    df.loc[df['DstVlanSubnet'] == 'Unknown', 'DstVlanSubnet'] = df.loc[df['DstVlanSubnet'] == 'Unknown', 'DstIP']
    if type(df['SrcVlanSubnet'][0]) is not str:
        df['SrcVlanSubnet'] = df['SrcVlanSubnet'].apply(lambda x: str(x))
        df['DstVlanSubnet'] = df['DstVlanSubnet'].apply(lambda x: str(x))
    df.rename(columns={
        'SrcVlanSubnet': 'Source',
        'DstVlanSubnet': 'Destination'
    },
        inplace=True
    )
    df = df[['Count', 'Source', 'SrcSite', 'Destination', 'DstSite', 'PathType']]
    traffic_df = df.groupby(
        ['Source', 'SrcSite', 'Destination', 'DstSite', 'PathType'],
        as_index=False
    )['Count'].agg('sum')
    traffic_df.sort_values(by=['Count'], ascending=False, inplace=True)
    traffic_df.reset_index(inplace=True, drop=True)
    traffic_df = traffic_df[['Count', 'Source', 'SrcSite', 'Destination', 'DstSite', 'PathType']]
    toc = time.perf_counter()
    printv(f"Flattening dataset took {toc - tic:0.4f} seconds to process")
    mergers = dict()
    '''
    You can further flatten your data by grouping VLANS
    Lets say you have 192.168.1.0/24 and 192.168.2.0/24 and that those two subnets are the same department
    Then you would put into this mergers dict the following
    '192.168.1.0/24': '192.168.1.0/23',
    '192.168.2.0/24': '192.168.1.0/23'
    '''
    if len(list(mergers.values())) > 0:
        tic = time.perf_counter()
        printv("Merging CIDRs (n=%d)" % len(traffic_df))
        traffic_df['Source'] = traffic_df['Source'].apply(lambda x: mergers[x] if x in mergers else x)
        traffic_df['Destination'] = traffic_df['Destination'].apply(lambda x: mergers[x] if x in mergers else x)
        df = traffic_df.groupby(
            ['Source', 'SrcSite', 'Destination', 'DstSite', 'PathType'],
            as_index=False
        )['Count'].agg('sum')
        df.sort_values(by=['Count'], ascending=False, inplace=True)
        df.reset_index(inplace=True, drop=True)
        traffic_df = df[['Count', 'Source', 'SrcSite', 'Destination', 'DstSite', 'PathType']]
        toc = time.perf_counter()
        printv(f"Consolidating cidr took {toc - tic:0.4f} seconds to process")
    printv("Performing extra steps")
    del traffic_df['PathType']
    traffic_df['Source Name'] = traffic_df['Source'].apply(get_vlan_name, sites=sites)
    traffic_df['Dest Name'] = traffic_df['Destination'].apply(get_vlan_name, sites=sites)
    traffic_df = traffic_df[['Count', 'Source', 'Source Name', 'SrcSite', 'Destination', 'Dest Name', 'DstSite']]
    filepath = os.path.join(
        os.path.join(os.getcwd(), 'excel'), '%s_%d.xlsx' % (filename.split(".")[0], int(time.time()))
    )
    traffic_df.to_excel(filepath, index=False, header=True)
    return traffic_df, filepath


def set_excel_vlan_sheets(df, excel_df, excel_file):
    vlans = []
    for v in set(list(excel_df['Source'].unique()) + list(excel_df['Destination'].unique())):
        if IPNetwork(v) not in IPNetwork('169.254.0.0/16') and v != '6.6.6.6/6' and len(list(IPNetwork(v))) != 1:
            vlans.append(IPNetwork(v))
    vlans.sort()
    excel_doc = pd.ExcelWriter(excel_file, engine='openpyxl')
    book = load_workbook(excel_file)
    excel_doc.book = book
    excel_doc.sheets = dict((ws.title, ws) for ws in book.worksheets)
    excel_df.to_excel(excel_doc, sheet_name='Main', header=True, index=False)
    vlan_pbar = tqdm(vlans)
    vlan_pbar.set_description("Working with VLAN : ")
    for vlan in vlan_pbar:
        vlan_pbar.set_description("Working with VLAN %s: " % str(vlan))
        sheet_name = str(vlan).replace("/", " |")
        ipes = [str(ip) for ip in list(vlan)]
        df['SrcIP'] = df['SrcIP'].apply(lambda x: str(x).split("/")[0])
        df['DstIP'] = df['DstIP'].apply(lambda x: str(x).split("/")[0])
        vdf = pd.concat([df.loc[df['SrcIP'].isin(ipes)], df.loc[df['DstIP'].isin(ipes)]]).drop_duplicates()
        vdf = vdf[['Count', 'SrcIP', 'SrcName', 'SrcLocation', 'DstIP', 'DstName', 'DstLocation']]
        vdf.reset_index(inplace=True, drop=True)
        vdf.to_excel(excel_doc, index=False, header=True, sheet_name=sheet_name)
        vlan_pbar.update()
    excel_doc.save()


if __name__ == "__main__":
    # Getting our parser started
    parser = argparse.ArgumentParser()

    ###      ###
    ### ARGS ###
    ###      ###
    parser.add_argument(
        '-f', '--TrafficData',
        help='CSV or PCAP File',
        required=True
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Prints verbose output to the console',
        required=False
    )
    parser.add_argument(
        '--apikey',
        help='API key for Meraki Dashboard API',
        required=False,
        type=str
    )
    parser.add_argument(
        '--reloadSites',
        action='store_true',
        help='Reloads the sites variable but does not reload the clients data unless the --reload-clients flag is set',
        required=False
    )
    parser.add_argument(
        '--reloadClients',
        action='store_true',
        help='Reloads the client data inside the sites variable. This can take, at the minimum, several minutes',
        required=False
    )
    parser.add_argument(
        '--resolveDNS',
        action='store_true',
        help='Will make an attempt to resolve IP addresses against provided DNS server',
        required=False
    )
    parser.add_argument(
        '--DNSServers',
        help='Comma separated list of the servers running DNS for your network',
        required=False,
    )
    parser.add_argument(
        '--PrintTopData',
        action='store_true',
        help='Comma separated list of the servers running DNS for your network',
        required=False,
    )

    # Getting our passed in args
    args = parser.parse_args()

    ###                ###
    ### SETTING VALUES ###
    ###                ###
    pd.set_option('display.max_columns', None)
    tic = time.perf_counter()

    if args.verbose:
        VERBOSE = True

    apikey = None
    if args.apikey:
        apikey = args.apikey
    else:
        try:
            with open("apikey", "r") as key:
                apikey = key.readline().strip()
        except:
            print("The apikey file does not exist")
            exit(-1)

    if not os.path.isfile(args.TrafficData):
        print("%s is not a valid file" % args.TrafficData)
        exit(-1)

    columns = [
        'Source address', 'Destination address', 'Destination Port', 'IP Protocol', 'Receive Time'
    ]
    csv = True
    datafile = args.TrafficData
    with open(datafile, 'r') as f:
        try:
            tester = f.readline()
        except:
            csv = False
    if csv:
        printv("Checking the CSV for the proper columns")
        tester = tester.strip()
        cols = tester.split(",")
        for column in columns:
            if column == 'Application':
                columns.append('Application')
                continue
            if column not in cols:
                print("%s was not found in CSV and is required")
                print("We are expecting the following columns:")
                print("Source address, Destination address, Destination Port, IP Protocol, Receive Time, Application")
                exit(-1)
    else:
        printv("Converting the PCAP to CSV")
        datafile = pcap_to_csv(args.TrafficData)

    dnsServers = []
    if args.resolveDNS:
        if args.DNSServers is None:
            print("You must specify DNS Servers if you want to resolve IP addresses. Example:")
            print("--DNSServers=1.1.1.1,1.0.0.1")
            exit(-1)
        else:
            for server in str(args.DNSServers).split(","):
                try:
                    temp = IPNetwork(server)
                    dnsServers.append(server)
                except:
                    print("%s is not a valid DNS Server" % server)
    pickle.dump(dnsServers, open('dns_servers.pkl', "wb"))

    printv("Gathering Meraki variables")
    dashboard = None
    try:
        dashboard = mer.DashboardAPI(
            api_key=apikey,
            print_console=False,
            maximum_retries=3,
            wait_on_rate_limit=True,
            log_path=MERLOGDIR,
            retry_4xx_error=True,
        )
    except:
        print("Could not initial the Dashboard API")
        exit(-1)
    organizations = dashboard.organizations.getOrganizations()
    if len(organizations) == 1:
        organization = organizations[0]
        orgID = organization['id']
    else:
        print("Please select an organization to work with:")
        for x, org in enumerate(organizations):
            print("%d) %s" % (x + 1, org['name']))
        while True:
            choice = input("=> ")
            if not is_int(choice) and int(choice) not in range(1, len(organizations) + 1):
                print("Invalid Choice %d", int(choice))
            else:
                organization = organizations[int(choice) - 1]
                orgID = organization['id']
                break
    networks = dashboard.organizations.getOrganizationNetworks(orgID)
    printv("Meraki variables set")

    if args.reloadSites:
        printv("Generating data for %s sites" % organization['name'])
        print(("-" * (TERMSIZE)) + "\n")
        os.rename('sites.pkl', 'sites.pkl.old')
        sites = get_sites(dashboard, orgID, networks, get_clients=args.reloadClients)
        save_sites('sites.pkl', sites)
    else:
        if os.path.isfile('sites.pkl'):
            sites = load_sites('sites.pkl')
        else:
            printv("No pickled site data found")
            printv("Generating data for %s sites" % organization['name'])
            print(("-" * (TERMSIZE)) + "\n")
            sites = get_sites(dashboard, orgID, networks, get_clients=True)
            save_sites('sites.pkl', sites)

    toc = time.perf_counter()
    printv(f"Gathering all the preflight information took {toc - tic:0.4f} seconds to process")

    # Now that we have everything setup we can start the program
    print(("-" * (TERMSIZE)))
    print(("-" * (TERMSIZE)))
    printv("Sending traffic flow data through the enrichnator")
    print(("-" * (TERMSIZE)))
    print(("-" * (TERMSIZE)))

    df = enrich_traffic_data(filename=datafile, columns=columns, pretty=args.PrintTopData, DNS=args.resolveDNS)
    print(("-" * (TERMSIZE)) + "\n")

    # Next we build our Excel document
    printv("Building Excel documents for the report")
    excel_df, excel_file = format_df_for_excel(df, sites, datafile)
    printv("Excel document made: %s" % excel_file)
    printv("Adding sheets to our document")
    set_excel_vlan_sheets(df, excel_df, excel_file)
    printv("Done")
