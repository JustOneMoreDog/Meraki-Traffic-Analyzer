


# Meraki Traffic Analyzer

## I dont want to read the manual just tell me what to do
```
sudo apt-get install wireshark
sudo apt-get install tshark
git clone https://github.com/picnicsecurity/Meraki-Traffic-Analyzer.git
cd Meraki-Traffic-Analyzer
python3 -m pip install -r requirements.txt
python3 MTA.py -v -f your_csv_data.csv --PrintTopData
python3 MTA.py -v -f your_pcap_data.csv --PrintTopData
```

## Contents
* [Summary](#Summary)
* [Speed](#Speed)
* [Setup](#Setup)
	* [Dependencies](#Installing-Dependencies)
	* [API Key](#API-Key-Setup)
	* [Formatting Data](#Formatting-your-data)
		* [PCAP](#PCAP)
		* [CSV](#CSV)
* [Example Usage](#Example-Usage)
	* [Arguments](#Arguments)
	* [First Run](#First-Run)
	* [Using CSV](#Using-CSV)
	* [Using PCAP](#Using-PCAP)
	* [Refreshing the sites variable](#Refreshing-the-sites-variable)
* [Files and Directories Created](#Files-and-Directories-Created)
* [Tailoring the code to your environment](#Tailoring-the-Code)
* [Missing Features](#Missing-Features)

## Summary
This script will take in a PCAP or CSV and output an enriched CSV and formatted Excel file. It will look at each traffic log entry and or packet, and with the help of the Dashboard API, give you the VLAN information for the IP addresses, the location of the IP addresses on your Meraki network, if and which ACL/FW/VPN rules are applying to the IP addresses, and optionally, a DNS query on the IP addresses. 

This script can ingest a CSV of traffic log entries, like those from a Palo Alto, and then spit out enriched CSV and Excel files for further analysis. I have also setup this script to handle PCAP files that you would get if you did a [packet capture from the Dashboard](https://documentation.meraki.com/General_Administration/Cross-Platform_Content/Packet_Capture_Overview).  

To learn more about the `sites` variable that is used throughout this script, see my [Meraki Dashboard API Script Starter](https://github.com/picnicsecurity/Meraki-Dashboard-API-Script-Starter) repository.

##  Speed
I did all of my testing on an Ubuntu 20.04 VM on a Dell PowerEdge R330 with an Intel Xeon E3-1280 3.90GHz CPU and 32GB of RAM. With this setup I was able process 23 million log entries, with DNS lookup turned on, in 5 minutes 13 seconds.  This script uses parallel processing that dynamic adjusts itself based on the size of your dataset. If you enable the verbosity flag then you will see how long each critical section of code takes. There are of course small areas in which I could increase performance but I am currently satisfied with the speed.

## Setup

### Installing Dependencies
```
git clone https://github.com/picnicsecurity/Meraki-Traffic-Analyzer.git
cd Meraki-Traffic-Analyzer
sudo apt-get install wireshark
sudo apt-get install tshark
# sudo apt-get update && sudo apt-get upgrade # optional
python3 -m pip install -r requirements.txt
```

### API Key Setup

 You can pass your [Dashboard API Key](https://documentation.meraki.com/General_Administration/Other_Topics/The_Cisco_Meraki_Dashboard_API) in using the `--apikey` parameter but I do not recommend this for security reasons. The better way is to put it into a locked down file called `apikey`. By default the script will assume that your key is in a file in the same directory called `apikey`. The .gitignore will automatically ignore this file in an effort to prevent unintentional key leakage.
 
### Formatting your data

#### PCAP

You can feed this directly into the script and it will handle all of the formatting for you. See [Meraki's documentation](https://documentation.meraki.com/General_Administration/Cross-Platform_Content/Packet_Capture_Overview) on how to do a packet capture from the Dashboard.

#### CSV

If you are passing in a CSV then you need to make sure you have the columns listed below. These columns do not need to be in the same order but they do need to exist
- Note: `Application` is the only optional column. Making a best guess at the application being used was a feature that did not make the initial release. If I have time in the future I will add it in. Most of the code is there but  I ran out of time to test it so it was omitted.
```
Receive Time,Source address,Destination address,Destination Port,Application,IP Protocol
2020/10/05 02:07:40,10.1.1.73,63.251.228.101,123,ntp,udp
``` 

## Example Usage

### Arguments 
```
python3 MTA.py                                        
usage: MTA.py [-h] -f TRAFFICDATA [-v] [--apikey APIKEY] [--reloadSites] [--reloadClients] [--resolveDNS]
              [--DNSServers DNSSERVERS] [--PrintTopData]
```
### First Run
Running this script fresh as if you had just pulled it down. Note that the first run will take the longest since it will require the sites data to be collected. The rate limit on the Dashboard API inhibits our ability to speed this up hence why we Pickle the data after we get it.
```
adam@MD-PYCHARM-01:~/PycharmProjects/Meraki-Traffic-Analyzer$ python3 MTA.py -v \
-f sorted_data_sample.csv \
--resolveDNS --DNSServers 10.10.10.10,10.10.10.20
                                                                   
VERBOSE: Checking the CSV for the proper columns                                  
VERBOSE: Gathering Meraki variables                                               
VERBOSE: Meraki variables set                                                     
VERBOSE: No pickled site data found                                               
VERBOSE: Generating data for PicnicSecurity sites                            
--------------------------------------------------------------------------------------------------------------                                                       

VERBOSE: Gathering identifiers                                                    
VERBOSE: Gathering VPN data                                                       
VERBOSE: Gathering VPN data took 0.9180 seconds to process                        
VERBOSE: Gathering VLAN data from switch stacks                                   
VERBOSE: Gathering VLAN data from switches                                        
VERBOSE: Gathering devices took 0.5001 seconds to process                         
VERBOSE: Gathering VLAN data from MX security appliances                          
VERBOSE: Gathering VLAN data took 7.1896 seconds to process                       
VERBOSE: Consolidating site's subnets into CIDR list                              
VERBOSE: Gathering client data from the site's devices                            
VERBOSE: Gathering device client data took 33.1416 seconds to process             
VERBOSE: Gathering a sample of the network client data                            
VERBOSE: Gathering network client data took 2.1380 seconds to process             
VERBOSE: Gathering MS ACL and MX Firewall data                                    
VERBOSE: Gathering ACL rules on the MS switches                                   
VERBOSE: Gathering Firewalls rules on the MX appliances                           
VERBOSE: Gathering ACL and FW data took 0.7610 seconds to process                 
VERBOSE: Creating site dictionary                                                 
==============================================================================================================                                                       
Processing CA: 100%|███████████████████████████████████████████████████████| 100/100 [00:44<00:00,  2.26it/s]                                                       
--------------------------------------------------------------------------------------------------------------                                                       
VERBOSE: Gathering identifiers                                                    
VERBOSE: Gathering VPN data                                                       
VERBOSE: Gathering VPN data took 0.9970 seconds to process                        
VERBOSE: Gathering VLAN data from switch stacks                                   
VERBOSE: Gathering VLAN data from switches                                        
VERBOSE: Gathering devices took 2.0811 seconds to process                         
VERBOSE: Gathering VLAN data from MX security appliances                          
VERBOSE: Gathering VLAN data took 27.2023 seconds to process                      
VERBOSE: Consolidating site's subnets into CIDR list                              
VERBOSE: Gathering client data from the site's devices                            
VERBOSE: Gathering device client data took 638.7474 seconds to process            
VERBOSE: Gathering a sample of the network client data                            
VERBOSE: Gathering network client data took 15.3696 seconds to process            
VERBOSE: Gathering MS ACL and MX Firewall data                                    
VERBOSE: Gathering ACL rules on the MS switches                                   
VERBOSE: Gathering Firewalls rules on the MX appliances                           
VERBOSE: Gathering ACL and FW data took 1.1641 seconds to process                 
VERBOSE: Creating site dictionary                                                 
==============================================================================================================                                                       
Processing MD: 100%|███████████████████████████████████████████████████████| 100/100 [11:23<00:00,  6.83s/it]                                                       
--------------------------------------------------------------------------------------------------------------                                                       
VERBOSE: Gathering identifiers                                                    
VERBOSE: Gathering VPN data                                                       
VERBOSE: Gathering VPN data took 0.9799 seconds to process                        
VERBOSE: Gathering VLAN data from switch stacks                                   
VERBOSE: No switch stacks in this network                                         
VERBOSE: Gathering VLAN data from switches                                        
VERBOSE: Gathering devices took 0.4579 seconds to process                         
VERBOSE: Gathering VLAN data from MX security appliances                          
VERBOSE: No VLANs exist on security appliance and or no security appliance exists 
VERBOSE: Gathering VLAN data took 177.3842 seconds to process                     
VERBOSE: Consolidating site's subnets into CIDR list                              
VERBOSE: Gathering client data from the site's devices                            
VERBOSE: Gathering device client data took 0.0003 seconds to process              
VERBOSE: Gathering a sample of the network client data                            
VERBOSE: Gathering network client data took 0.3985 seconds to process             
VERBOSE: Gathering MS ACL and MX Firewall data                                    
VERBOSE: Gathering ACL rules on the MS switches                                   
VERBOSE: Gathering Firewalls rules on the MX appliances                           
VERBOSE: Gathering ACL and FW data took 138.3256 seconds to process               
VERBOSE: Creating site dictionary                                                 
==============================================================================================================                                                       
Processing AWS: 100%|███████████████████████████████████████████████████████| 100/100 [05:17<00:00,  3.17s/it]                                                       
--------------------------------------------------------------------------------------------------------------                                     

VERBOSE: Gathering all the preflight information took 1331.7198 seconds to process                                                                                   
--------------------------------------------------------------------------------------------------------------                                                       
--------------------------------------------------------------------------------------------------------------                                                       
VERBOSE: Sending traffic flow data through the enrichnator                                                                                                           
--------------------------------------------------------------------------------------------------------------                                                       
--------------------------------------------------------------------------------------------------------------                                                       
VERBOSE: Current length dataset is 10000                                          
VERBOSE: Loading and formatting dataset took 0.0211 seconds to process                                                                                               
VERBOSE: Current length dataset is 8364                                           
VERBOSE: Initial Dataframe Memory Usage                                           
VERBOSE: 2.3095 mb                                                                
VERBOSE: Formatting the IP Section                                                
VERBOSE: Length of all the IPes 16728                                             
VERBOSE: format_df_values_caller is being called with 4 cores                                                                                                        
Parallel Workload Status: 100%|█████████████████████████████████████████████████| 6/6 [00:00<00:00, 73.14it/s]                                                       
VERBOSE: Formatting the IPes took 0.0831 seconds to process                                                                                                          
VERBOSE: Formatting the dataset took 0.0836 seconds to process                                                                                                       
VERBOSE: Traffic DataFrame memory usage before duplicates are grouped (n=8364)                                                                                       
VERBOSE: 1.5634 mb                                                                
VERBOSE: Grouping the dataset took 0.0974 seconds to process                                                                                                         
VERBOSE: Duplicates Grouped (n=2963)                                              
VERBOSE: 0.3392 mb                                                                
VERBOSE: Sorting the dataset by count (n=2963)                                    
VERBOSE: Sorting the dataset took 0.0005 seconds to process                                                                                                          
VERBOSE: Setting the multiprocessing speed to 4                                   
VERBOSE: get_ip_data_caller is being called with 4 cores                                                                                                             
Parallel Workload Status: 100%|█████████████████████████████████████████████████| 6/6 [00:10<00:00,  1.80s/it]                                                       
VERBOSE: Getting IP Data took 10.7815 seconds to process                                                                                                             
VERBOSE: IP Data has been fleshed out. Moving on to traffic flow rules                                                                                               
VERBOSE: Setting the multiprocessing speed to 4                                   
VERBOSE: get_packet_path_data_caller is being called with 4 cores                                                                                                    
Parallel Workload Status: 100%|█████████████████████████████████████████████████| 6/6 [00:00<00:00, 10.56it/s]                                                       
VERBOSE: Getting Traffic Flow Data Parallel took 0.5701 seconds to process                                                                                           
VERBOSE: Starting DNS Queries                                                     
VERBOSE: resolve_ip_caller is being called with 10 cores                                                                                                             
Parallel Workload Status: 100%|███████████████████████████████████████████████| 12/12 [00:19<00:00,  1.66s/it]                                                       
VERBOSE: Getting DNS information took 19.9505 seconds to process                                                                                                     
VERBOSE: Enrichment process finished                                              
VERBOSE: --- --- --- --- ---                                                      
VERBOSE: Dataset took 31.5533 seconds to process                                  
VERBOSE: --- --- --- --- ---                                                      
--------------------------------------------------------------------------------------------------------------                                                       

VERBOSE: Building Excel documents for the report                                  
VERBOSE: Flattening dataset (n=2963)                                              
VERBOSE: Flattening dataset took 0.0122 seconds to process                                                                                                           
VERBOSE: Performing extra steps                                                   
VERBOSE: Excel document made: /home/adam/PycharmProjects/Meraki-Traffic-Analyzer/excel/sorted_data_sample_1605556860.xlsx                                            
VERBOSE: Adding sheets to our document                                            
Working with VLAN 10.10.20.0/24: : 100%|████████████████████████████████████| 68/68 [00:00<00:00, 88.79it/s]                                                       
VERBOSE: Done                                                                     
```
### Using CSV
Now that the sites data has been Pickled we can call the script again and the preflight will only take a few seconds
```
adam@MD-PYCHARM-01:~/PycharmProjects/Meraki-Traffic-Analyzer$ python3 MTA.py -v \
-f sorted_data_sample.csv \
--resolveDNS --DNSServers 10.10.10.10,10.10.10.20

VERBOSE: Checking the CSV for the proper columns
VERBOSE: Gathering Meraki variables
VERBOSE: Meraki variables set
VERBOSE: Gathering all the preflight information took 1.5432 seconds to process
--------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------
VERBOSE: Sending traffic flow data through the enrichnator
--------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------
VERBOSE: Current length dataset is 10000
VERBOSE: Loading and formatting dataset took 0.0185 seconds to process
VERBOSE: Current length dataset is 8364
VERBOSE: Initial Dataframe Memory Usage
VERBOSE: 2.3095 mb
VERBOSE: Formatting the IP Section
VERBOSE: Length of all the IPes 16728
VERBOSE: format_df_values_caller is being called with 4 cores
Parallel Workload Status: 100%|█████████████████████████████████████████████████| 6/6 [00:00<00:00, 34.73it/s]
VERBOSE: Formatting the IPes took 0.1749 seconds to process
VERBOSE: Formatting the dataset took 0.1753 seconds to process
VERBOSE: Traffic DataFrame memory usage before duplicates are grouped (n=8364)
VERBOSE: 1.5634 mb
VERBOSE: Grouping the dataset took 0.0930 seconds to process
VERBOSE: Duplicates Grouped (n=2963)
VERBOSE: 0.3392 mb
VERBOSE: Sorting the dataset by count (n=2963)
VERBOSE: Sorting the dataset took 0.0004 seconds to process
VERBOSE: Setting the multiprocessing speed to 4
VERBOSE: get_ip_data_caller is being called with 4 cores
Parallel Workload Status: 100%|█████████████████████████████████████████████████| 6/6 [00:10<00:00,  1.75s/it]
VERBOSE: Getting IP Data took 10.5145 seconds to process
VERBOSE: IP Data has been fleshed out. Moving on to traffic flow rules
VERBOSE: Setting the multiprocessing speed to 4
VERBOSE: get_packet_path_data_caller is being called with 4 cores
Parallel Workload Status: 100%|█████████████████████████████████████████████████| 6/6 [00:00<00:00, 10.28it/s]
VERBOSE: Getting Traffic Flow Data Parallel took 0.5854 seconds to process
VERBOSE: Starting DNS Queries
VERBOSE: resolve_ip_caller is being called with 10 cores
Parallel Workload Status: 100%|███████████████████████████████████████████████| 12/12 [00:19<00:00,  1.62s/it]
VERBOSE: Getting DNS information took 19.5397 seconds to process
VERBOSE: Enrichment process finished
VERBOSE: --- --- --- --- --- 
VERBOSE: Dataset took 30.9755 seconds to process
VERBOSE: --- --- --- --- --- 
--------------------------------------------------------------------------------------------------------------

VERBOSE: Building Excel documents for the report
VERBOSE: Flattening dataset (n=2963)
VERBOSE: Flattening dataset took 0.0120 seconds to process
VERBOSE: Performing extra steps
VERBOSE: Excel document made: /home/adam/PycharmProjects/Meraki-Traffic-Analyzer/excel/sorted_data_sample_1605623275.xlsx
VERBOSE: Adding sheets to our document
Working with VLAN 10.10.20.0/24: : 100%|████████████████████████████████████| 68/68 [00:00<00:00, 89.95it/s]
VERBOSE: Done
```

### Using PCAP
Once the script has converted the PCAP to a Pandas Dataframe, it will then save the data to a CSV for future analysis
```
adam@MD-PYCHARM-01:~/PycharmProjects/Meraki-Traffic-Analyzer$ python3 MTA.py -v \
-f packet_capture.pcap \
--resolveDNS --DNSServers 10.10.10.20,10.10.10.30

VERBOSE: Converting the PCAP to CSV
VERBOSE: Gathering Meraki variables
VERBOSE: Meraki variables set
VERBOSE: Gathering all the preflight information took 2.1653 seconds to process
--------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------
VERBOSE: Sending traffic flow data through the enrichnator
--------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------
VERBOSE: Current length dataset is 122
VERBOSE: Loading and formatting dataset took 0.0050 seconds to process
VERBOSE: Current length dataset is 122
VERBOSE: Initial Dataframe Memory Usage
VERBOSE: 0.0259 mb
VERBOSE: Formatting the IP Section
VERBOSE: Length of all the IPes 244
VERBOSE: format_df_values_caller is being called with 1 cores
Parallel Workload Status: 100%|████████████████████████████████████████████████| 3/3 [00:00<00:00, 251.25it/s]
VERBOSE: Formatting the IPes took 0.0135 seconds to process
VERBOSE: Formatting the dataset took 0.0138 seconds to process
VERBOSE: Traffic DataFrame memory usage before duplicates are grouped (n=122)
VERBOSE: 0.0149 mb
VERBOSE: Grouping the dataset took 0.0043 seconds to process
VERBOSE: Duplicates Grouped (n=12)
VERBOSE: 0.0015 mb
VERBOSE: Sorting the dataset by count (n=12)
VERBOSE: Sorting the dataset took 0.0003 seconds to process
VERBOSE: Setting the multiprocessing speed to 1
VERBOSE: get_ip_data_caller is being called with 1 cores
Parallel Workload Status: 100%|█████████████████████████████████████████████████| 3/3 [00:00<00:00, 21.98it/s]
VERBOSE: Getting IP Data took 0.1371 seconds to process
VERBOSE: IP Data has been fleshed out. Moving on to traffic flow rules
VERBOSE: Setting the multiprocessing speed to 1
VERBOSE: get_packet_path_data_caller is being called with 1 cores
Parallel Workload Status: 100%|█████████████████████████████████████████████████| 3/3 [00:00<00:00, 74.21it/s]
VERBOSE: Getting Traffic Flow Data Parallel took 0.0407 seconds to process
VERBOSE: Starting DNS Queries
VERBOSE: resolve_ip_caller is being called with 10 cores
Parallel Workload Status: 100%|██████████████████████████████████████████████| 12/12 [00:00<00:00, 142.22it/s]
VERBOSE: Getting DNS information took 0.0859 seconds to process
VERBOSE: Enrichment process finished
VERBOSE: --- --- --- --- --- 
VERBOSE: Dataset took 0.3065 seconds to process
VERBOSE: --- --- --- --- --- 
--------------------------------------------------------------------------------------------------------------

VERBOSE: Building Excel documents for the report
VERBOSE: Flattening dataset (n=12)
VERBOSE: Flattening dataset took 0.0074 seconds to process
VERBOSE: Performing extra steps
VERBOSE: Excel document made: /home/adam/PycharmProjects/Meraki-Traffic-Analyzer/excel/_1605623486.xlsx
VERBOSE: Adding sheets to our document
Working with VLAN 10.10.20.0/24: : 100%|███████████████████████████████████████| 3/3 [00:00<00:00, 134.32it/s]
VERBOSE: Done
```

#### Refreshing the sites variable

Unless you are in a constantly changing network, the information in the sites variable won't go stale quickly. However, if you have added a switch,  VLAN, ACL, etc, then you are going to want to update the sites variable. If you are not concerned about the client data, then you can omit updating that information and save a bunch of time. This script will save only the two most recent versions of the `sites` variable.
* Note: If you want to update the client data as well use the `--reloadClients` flag along with the `--reloadSites` flag
```
adam@WDC-PYCHARM-01:~/PycharmProjects/Meraki-Traffic-Analyzer$ python3 MTA.py -v \
-f packet_capture.pcap \
--resolveDNS --DNSServers 10.10.10.10,10.10.10.20 \
--reloadSites
``` 

## Files and Directories Created

```
├── apikey # This where you store your apikey
├── dns_servers.pkl # This is a pickled list of the DNS servers you pass in
├── excel # The directory where we store the outputted excel files
│   ├── sorted_data_sample_1604945336.xlsx # Naming structure is "$(csv_file_name)_$(unix time stamp).xlsx"
├── logs # All the verbose output goes into these files regardless of if you use the -v or not
│   ├── 1604939073.log
├── meraki_logs # When building the sites variable we make a bunch of Meraki Dashboard API calls and this is where we store the logs for those calls 
│   ├── meraki_api__log__2020-11-09_11-28-39.log
├── MTA.py # The main script
├── packet_capture.pcap # An example PCAP file
├── README.md 
├── requirements.txt
├── sites.pkl # Your sites data
├── sites.pkl.old # Your previous iteration of the sites data
├── sorted_data_sample.csv # An example CSV file
```

## Tailoring the Code
There are several places in the code where you can add customizations to make the data better fit your environment
* [Parallel Processing Speed](https://github.com/picnicsecurity/Meraki-Traffic-Analyzer/blob/main/MTA.py#L41)
	* If you have an even more massive dataset then you can make adjustments accordingly. Just remember to account for the overhead required to make multiple processes.
* [Changing how public IP Address are handled](https://github.com/picnicsecurity/Meraki-Traffic-Analyzer/blob/main/MTA.py#L424)
	* For the scope of what I needed to get done, I did not care what public IP-es were being visited only that an IP was talking out to the internet. As such, I change all the public IP-es to `IPNetwork('6.6.6.6/6')` so that when I perform a [consolidation at a VLAN level](), I am just shown what VLANs are talking to the Internet. If you do no want this to happen then change [line 432](https://github.com/picnicsecurity/Meraki-Traffic-Analyzer/blob/main/MTA.py#L432) and [line 441](https://github.com/picnicsecurity/Meraki-Traffic-Analyzer/blob/main/MTA.py#L432) to `row['SrcIP']` and `row['DstIP']` respectively.
* [Changing which VLANs have their communication to the internet consolidated](https://github.com/picnicsecurity/Meraki-Traffic-Analyzer/blob/main/MTA.py#L746)
	* In my environment I have VLANs that are designed specifically to talk to to the internet. These are your standard work office VLANs and guest WiFi. If you have those type of VLANs, then you should change the `networks` variable to a list of those VLANs. That list would look something like `networks=[IPNetwork('10.10.10.0/24'), IPNetwork('10.10.20.0/24'), IPNetwork('10.10.30.0/24')]`. Now the code will change any public IP taking to or being talked at by these VLANs to `IPNetwork('6.6.6.6/6')`. 
* [Adding site data for AWS networks](https://github.com/picnicsecurity/Meraki-Traffic-Analyzer/blob/main/MTA.py#L944)
	* If you have an AWS Virtual MX then this is where you would add the data for that site. The code for that would look something like:
		```
		if siteName == 'AWS':
			# Special AWS Conditional
			awsVlan = {
				'interfaceId': '',
				'name': 'EC2',
				'subnet': IPNetwork('10.20.30.0/24'), # The subnet of your EC2 for your VPC
				'interfaceIp': '',
				'multicastRouting': '',
				'vlanId': '',
				'ospfSettings': {
					'area': 'ospfDisabled'
				},
				'inVpn': True,
				'MS': False,
				'location': 'AWS vMX100'
			}
			vlanList.append(awsVlan)
			cidrList.append(awsVlan['subnet'])
		```

## Missing Features
* [Taking a best guess at the application being used](https://github.com/picnicsecurity/Meraki-Traffic-Analyzer/blob/main/MTA.py#L264)
	* Since we know what port is being accessed and if it is being accessed with TCP or UDP, we can make a best guess at the application being used (ie DNS, HTTP, etc). I was having issues with getting the Pandas merge to work though so I left that feature out for this version.  
* [Adding `**kwargs` to the `parallelize_workload` function](https://github.com/picnicsecurity/Meraki-Traffic-Analyzer/blob/main/MTA.py#L836)
	* I have a bunch of [something_something_caller](https://github.com/picnicsecurity/Meraki-Traffic-Analyzer/blob/main/MTA.py#L783) functions in my code. These are what the `parallelize_workload` calls on each chunk of the data. I can remove all of these functions if I just use `**kwargs`. This would also add a lot more customizations. However, I have not used `**kwargs` in any of my functions before so I did not want to tackle that this version
* Add `--DontConsolidateInternet` flag
	* For context see [Tailoring the Code](#Tailoring-the-Code). I would like to give the user the ability to say if they want all public IP-es to be changed to `IPNetwork('6.6.6.6/6') or not.  
