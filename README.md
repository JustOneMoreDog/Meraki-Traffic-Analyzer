

# Meraki-Traffic-Analyzer
Performing in-depth traffic analysis with the Meraki Dashboard API

## Contents
* [Summary](#Summary)
* [Speed](#Speed)
* [Setup](#Setup)
	* [Dependencies](#Setup)
	* [API Key](#Setup)
	* [PCAP](#Setup)
	* [CSV](#Setup)
* [Example Usage](#Example-Usage)

## Summary
This script will take in a PCAP or CSV and output an enriched CSV and formatted Excel file. It will look at each traffic log entry and or packet, and with the help of the Dashboard API, give you the VLAN information for the IP addresses, the location of the IP addresses on your Meraki network, if and which ACL/FW/VPN rules are applying to the IP addresses, and optionally, a DNS query on the IP addresses. 
In Meraki you have 3 places where you can define the flow of network traffic; Switch ACL, Appliance Firewall, and Appliance Site-to-Site VPN Firewall. I was recently tasked with locking down these lists and this script is a result of that project. I used a Palo Alto to setup mirrors all over the network and collect data. This script ingests those traffic logs and then spits out enriched CSV and Excel files for further analysis. I have also setup this script to handle PCAP files that you would get if you did a packet capture from the Dashboard.  
To learn more about the `sites` variable that is used throughout this script, see my [Meraki Dashboard API Script Starter](https://github.com/picnicsecurity/Meraki-Dashboard-API-Script-Starter) repository.

##  Speed
I did all of my testing on an Ubuntu 20.04 VM on a Dell PowerEdge R330 with an Intel Xeon E3-1280 3.90GHz CPU and 32GB of RAM. With this setup I was able process 23 million log entries, with DNS lookup turned on, in 5 minutes 13 seconds.  This script uses parallel processing that dynamic adjusts itself based on the size of your dataset. If you enable the verbosity flag then you will see how long each critical section of code takes. There are of course small areas in which I could increase performance but I am currently satisfied with the speed.

## Setup
 * Install Dependencies
    ```
    python3 -m pip install -r requirements.txt
    sudo apt-get install wireshark
    sudo apt-get install tshark
    ```
 * API Key Setup
	 - You can pass your [Dashboard API Key](https://documentation.meraki.com/General_Administration/Other_Topics/The_Cisco_Meraki_Dashboard_API) in using the `--apikey` parameter but I do not recommend this for security reasons. The better way is to put it into a locked down file called `apikey`. By default the script will assume that your key is in a file in the same directory called `apikey`. The .gitignore will automatically ignore this file in an effort to prevent unintentional key leakage.
 * Format your data
    - PCAP
        - You can feed this directly into the script and it will handle all of the formatting for you
    - CSV
        - If you are passing in a CSV then you need to make sure you have the following columns
        - These columns do not need to be in the same order but they do need to exist
	        - Note: Application is the only optional column. Making a best guess at the application being used was a feature that did not make the initial release. If I have time in the future I will add it in. Most of the code is there but  I ran out of time to test it so it was omitted.
        
|  | Source address | Destination address | Destination Port | IP Protocol | Receive Time | Application |
|--|--|--|--|--|--|--|--|
| Example | 192.168.5.50 | 192.168.6.60 | 80 | TCP | 2020/10/05 02:07:40 | web-browsing | 
```
Receive Time,Source address,Destination address,Destination Port,Application,IP Protocol
2020/10/05 02:07:40,10.1.1.73,63.251.228.101,123,ntp,udp
```
     
## Example Usage
```
python3 MTA.py                                        
usage: MTA.py [-h] -f TRAFFICDATA [-v] [--apikey APIKEY] [--reloadSites] [--reloadClients] [--resolveDNS]
              [--DNSServers DNSSERVERS] [--PrintTopData]
```
Running this script fresh as if you had just pulled it down. Note that the first run will take the longest since it will require the sites data to be collected. The rate limit on the Dashboard API inhibits our ability to speed this up hence why we Pickle the data after we get it.
```
adam@WDC-PYCHARM-01:~/PycharmProjects/Meraki-Traffic-Analyzer$ python3 MTA.py -f new_sorted_data.csv -v --resolveDNS --DNSServers 10.10.10.10,10.10.10.11                                                                       
VERBOSE: Checking the CSV for the proper columns                                                         
VERBOSE: Gathering Meraki variables                                                                      
VERBOSE: Meraki variables set                                                                            
VERBOSE: No pickled site data found                                                                      
VERBOSE: Generating data for PicnicSecurity sites                                                   
--------------------------------------------------------------------------------------------------------------------------------------------                                                                       

VERBOSE: Gathering identifiers                                                                           
VERBOSE: Gathering VPN data                                                                              
VERBOSE: Gathering VPN data took 2.2054 seconds to process                                               
VERBOSE: Gathering VLAN data from switch stacks                                                          
VERBOSE: Gathering VLAN data from switches                                                               
VERBOSE: Gathering devices took 0.5720 seconds to process                                                
VERBOSE: Gathering VLAN data from MX security appliances                                                 
VERBOSE: Gathering VLAN data took 9.4498 seconds to process                                              
VERBOSE: Consolidating site's subnets into CIDR list                                                     
VERBOSE: Gathering client data from the site's devices                                                   
VERBOSE: Gathering device client data took 43.0276 seconds to process                                    
VERBOSE: Gathering a sample of the network client data                                                   
VERBOSE: Gathering network client data took 2.0893 seconds to process                                    
VERBOSE: Gathering MS ACL and MX Firewall data                                                           
VERBOSE: Gathering ACL rules on the MS switches                                                          
VERBOSE: Gathering Firewalls rules on the MX appliances                                                  
VERBOSE: Gathering ACL and FW data took 0.7532 seconds to process                                        
VERBOSE: Creating site dictionary                                                                        
============================================================================================================================================                                                                       
Processing CA: 100%|█████████████████████████████████████████████████████████████████████████████████████| 100/100 [00:57<00:00,  1.74it/s]                                                                       
--------------------------------------------------------------------------------------------------------------------------------------------                                                                       
VERBOSE: Gathering identifiers                                                                           
VERBOSE: Gathering VPN data                                                                              
VERBOSE: Gathering VPN data took 0.7347 seconds to process                                               
VERBOSE: Gathering VLAN data from switch stacks                                                          
VERBOSE: Gathering VLAN data from switches                                                               
VERBOSE: Gathering devices took 1.4861 seconds to process                                                
VERBOSE: Gathering VLAN data from MX security appliances                                                 
VERBOSE: Gathering VLAN data took 30.6100 seconds to process                                             
VERBOSE: Consolidating site's subnets into CIDR list                                                     
VERBOSE: Gathering client data from the site's devices                                                   
VERBOSE: Gathering device client data took 640.4964 seconds to process                                   
VERBOSE: Gathering a sample of the network client data                                                   
VERBOSE: Gathering network client data took 15.9908 seconds to process                                   
VERBOSE: Gathering MS ACL and MX Firewall data                                                           
VERBOSE: Gathering ACL rules on the MS switches                                                          
VERBOSE: Gathering Firewalls rules on the MX appliances                                                  
VERBOSE: Gathering ACL and FW data took 0.9378 seconds to process                                        
VERBOSE: Creating site dictionary                                                                        
============================================================================================================================================                                                                       
Processing MD: 100%|█████████████████████████████████████████████████████████████████████████████████████| 100/100 [11:28<00:00,  6.89s/it]                                                                       
--------------------------------------------------------------------------------------------------------------------------------------------                                                                       
VERBOSE: Gathering identifiers                                                                           
VERBOSE: Gathering VPN data                                                                              
VERBOSE: Gathering VPN data took 0.7646 seconds to process                                               
VERBOSE: Gathering VLAN data from switch stacks                                                          
VERBOSE: No switch stacks in this network                                                                
VERBOSE: Gathering VLAN data from switches                                                               
VERBOSE: Gathering devices took 0.4190 seconds to process                                                
VERBOSE: Gathering VLAN data from MX security appliances                                                 
VERBOSE: No VLANs exist on security appliance and or no security appliance exists                        
VERBOSE: Gathering VLAN data took 170.8584 seconds to process                                            
VERBOSE: Consolidating site's subnets into CIDR list                                                     
VERBOSE: Gathering client data from the site's devices                                                   
VERBOSE: Gathering device client data took 0.0004 seconds to process                                     
VERBOSE: Gathering a sample of the network client data                                                   
VERBOSE: Gathering network client data took 1.1509 seconds to process                                    
VERBOSE: Gathering MS ACL and MX Firewall data                                                           
VERBOSE: Gathering ACL rules on the MS switches                                                          
VERBOSE: Gathering Firewalls rules on the MX appliances                                                  
VERBOSE: Gathering ACL and FW data took 98.6410 seconds to process                                       
VERBOSE: Creating site dictionary                                                                        
============================================================================================================================================                                                                       
Processing AWS: 100%|█████████████████████████████████████████████████████████████████████████████████████| 100/100 [04:31<00:00,  2.71s/it]                                                                       
--------------------------------------------------------------------------------------------------------------------------------------------                                                                                                                                             
VERBOSE: Gathering all the preflight information took 975.6765 seconds to process    
                                                                                                                             
--------------------------------------------------------------------------------------------------------------------------------------------                                                                       
--------------------------------------------------------------------------------------------------------------------------------------------                                                                       
VERBOSE: Sending traffic flow data through the enrichnator                                               
--------------------------------------------------------------------------------------------------------------------------------------------                                                                       
--------------------------------------------------------------------------------------------------------------------------------------------                                                                       
VERBOSE: Current length dataset is 23368590                                                              
VERBOSE: Loading and formatting dataset took 26.9496 seconds to process                                                                                                                                            
VERBOSE: Current length dataset is 20045853                                                              
VERBOSE: Initial Dataframe Memory Usage                                                                  
VERBOSE: 6525.3231 mb                                                                                    
VERBOSE: Formatting the IP Section                                                                       
VERBOSE: Length of all the IPes 40091706                                                                 
VERBOSE: format_df_values_caller is being called with 7 cores                                            
Parallel Workload Status: 100%|███████████████████████████████████████████████████████████████████████████████| 9/9 [01:24<00:00,  9.42s/it]                                                                       
VERBOSE: Formatting the IPes took 85.4713 seconds to process                                             
VERBOSE: Formatting the dataset took 87.5870 seconds to process                                          
VERBOSE: Traffic DataFrame memory usage before duplicates are grouped (n=17182160)                                                                                                                                 
VERBOSE: 3211.6922 mb                                                                                    
VERBOSE: Grouping the dataset took 124.7111 seconds to process                                           
VERBOSE: Duplicates Grouped (n=131899)                                                                   
VERBOSE: 15.0948 mb                                                                                      
VERBOSE: Sorting the dataset by count (n=131899)                                                         
VERBOSE: Sorting the dataset took 0.0146 seconds to process                                              
VERBOSE: Setting the multiprocessing speed to 6                                                          
VERBOSE: get_ip_data_caller is being called with 6 cores                                                 
Parallel Workload Status: 100%|███████████████████████████████████████████████████████████████████████████████| 8/8 [01:15<00:00,  9.44s/it]                                                                       
VERBOSE: Getting IP Data took 75.6135 seconds to process                                                 
VERBOSE: IP Data has been fleshed out. Moving on to traffic flow rules                                                                                                                                             
VERBOSE: Setting the multiprocessing speed to 6                                                          
VERBOSE: get_packet_path_data_caller is being called with 6 cores                                        
Parallel Workload Status: 100%|███████████████████████████████████████████████████████████████████████████████| 8/8 [00:22<00:00,  2.77s/it]                                                                       
VERBOSE: Getting Traffic Flow Data Parallel took 22.2112 seconds to process                                                                                                                                        
VERBOSE: Starting DNS Queries                                                                            
VERBOSE: resolve_ip_caller is being called with 10 cores                                                 
Parallel Workload Status: 100%|█████████████████████████████████████████████████████████████████████████████| 12/12 [07:03<00:00, 35.27s/it]                                                                       
VERBOSE: Getting DNS information took 426.5149 seconds to process                                        
VERBOSE: Enrichment process finished                                                                     
VERBOSE: --- --- --- --- ---                                                                             
VERBOSE: Dataset took 774.6598 seconds to process                                                        
VERBOSE: --- --- --- --- ---                                                                             
--------------------------------------------------------------------------------------------------------------------------------------------                                                                       

VERBOSE: Building Excel documents for the report                                                         
VERBOSE: Flattening dataset (n=131899)                                                                   
VERBOSE: Flattening dataset took 0.1944 seconds to process                                               
VERBOSE: Performing extra steps                                                                          
VERBOSE: Excel document made: /home/adam/PycharmProjects/Meraki-Traffic-Analyzer/excel/new_sorted_data_1605553612.xlsx                                                                                             
VERBOSE: Adding sheets to our document                                                                   
Working with VLAN 10.20.20.1/24: : 100%|██████████████████████████████████████████████████████████████████| 81/81 [00:12<00:00,  6.56it/s]                                                                       
VERBOSE: Done                                                                                            
adam@WDC-PYCHARM-01:~/PycharmProjects/Meraki-Traffic-Analyzer$ 

```
Now that the sites data has been Pickled we can call the script again and the preflight will only take a few seconds
```
adam@WDC-PYCHARM-01:~/PycharmProjects/Meraki-Traffic-Analyzer$ python3 MTA.py -f sorted_data_sample.csv -v --resolveDNS --DNSServers 10.160.34.249,10.160.34.250
VERBOSE: Checking the CSV for the proper columns
VERBOSE: Gathering Meraki variables
VERBOSE: Meraki variables set
VERBOSE: Gathering all the preflight information took 1.5559 seconds to process
--------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------
VERBOSE: Sending traffic flow data through the enrichnator
--------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------
VERBOSE: Current length dataset is 10000
VERBOSE: Loading and formatting dataset took 0.0183 seconds to process
VERBOSE: Current length dataset is 8364
VERBOSE: Initial Dataframe Memory Usage
VERBOSE: 2.3095 mb
VERBOSE: Formatting the IP Section
VERBOSE: Length of all the IPes 16728
VERBOSE: format_df_values_caller is being called with 4 cores
Parallel Workload Status: 100%|███████████████████████████████████████████████████████████████████████████████| 6/6 [00:00<00:00, 33.71it/s]
VERBOSE: Formatting the IPes took 0.1803 seconds to process
VERBOSE: Formatting the dataset took 0.1807 seconds to process
VERBOSE: Traffic DataFrame memory usage before duplicates are grouped (n=8364)
VERBOSE: 1.5634 mb
VERBOSE: Grouping the dataset took 0.0991 seconds to process
VERBOSE: Duplicates Grouped (n=2963)
VERBOSE: 0.3392 mb
VERBOSE: Sorting the dataset by count (n=2963)
VERBOSE: Sorting the dataset took 0.0005 seconds to process
VERBOSE: Setting the multiprocessing speed to 4
VERBOSE: get_ip_data_caller is being called with 4 cores
Parallel Workload Status: 100%|███████████████████████████████████████████████████████████████████████████████| 6/6 [00:10<00:00,  1.80s/it]
VERBOSE: Getting IP Data took 10.8278 seconds to process
VERBOSE: IP Data has been fleshed out. Moving on to traffic flow rules
VERBOSE: Setting the multiprocessing speed to 4
VERBOSE: get_packet_path_data_caller is being called with 4 cores
Parallel Workload Status: 100%|███████████████████████████████████████████████████████████████████████████████| 6/6 [00:00<00:00,  9.31it/s]
VERBOSE: Getting Traffic Flow Data Parallel took 0.6465 seconds to process
VERBOSE: Starting DNS Queries
VERBOSE: resolve_ip_caller is being called with 10 cores
Parallel Workload Status: 100%|█████████████████████████████████████████████████████████████████████████████| 12/12 [00:16<00:00,  1.37s/it]
VERBOSE: Getting DNS information took 16.5287 seconds to process
VERBOSE: Enrichment process finished
VERBOSE: --- --- --- --- --- 
VERBOSE: Dataset took 28.3513 seconds to process
VERBOSE: --- --- --- --- --- 
--------------------------------------------------------------------------------------------------------------------------------------------

VERBOSE: Building Excel documents for the report
VERBOSE: Flattening dataset (n=2963)
VERBOSE: Flattening dataset took 0.0117 seconds to process
VERBOSE: Performing extra steps
VERBOSE: Excel document made: /home/adam/PycharmProjects/Meraki-Traffic-Analyzer/excel/sorted_data_sample_1605555089.xlsx
VERBOSE: Adding sheets to our document
Working with VLAN 10.20.20.0/24: : 100%|██████████████████████████████████████████████████████████████████| 69/69 [00:00<00:00, 89.34it/s]
VERBOSE: Done
```
