# Meraki-Traffic-Analyzer
Perform in-depth traffic analysis with the Meraki Dashboard API

# Summary
In Meraki you have 3 places where you can define the flow of network traffic; Switch ACL, Appliance Firewall, and Appliance Site-to-Site VPN Firewall. I was recently tasked with locking down these lists and this script is a result of that project. I used a Palo Alto to setup mirrors all over the network and collect data. This script ingests those traffic logs and then spits out enriched CSV and Excel files for further analysis. I have also setup this script to handle PCAP files that you would get if you did a packet capture from the Dashboard.  

## Setup
 * Install Dependencies
    ```
    python3 -m pip install -r requirements.txt
    ```
 * Format your data
    - PCAP
        - You can feed this directly into the script without issue
    - CSV
        - If you are passing in a CSV then you need to make sure you have your columns lined up
        |  | Source address | Destination address | Destination Port | IP Protocol | Receive Time | Application |
        |--|--|--|--|--|--|--|--|
        | Example | 192.168.5.50 | 192.168.6.60 | 80 | TCP | 2020/10/05 02:07:40 | web-browsing | 
     
## Examples
Need to remove the new MOTB stuff from public eyes
add new datasets to the git ignore 
add flag to consolidate down internet ip
finish documentation 
add flag to ignore a list of IPes 