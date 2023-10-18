#!/usr/bin/python3

import time, os, sys, subprocess, re, io
from subprocess import Popen, PIPE
from optparse import OptionParser
import logging
import pprint

## TODO
## 2.- Add Nikto and Gobuster to any HTTP service
## 4.- EyeWitness
## 6.- if IKEVPN ikescan
## 7.- default creds on SSH and FTP using Hydra and rockyou
## 8.- SMTP user-enumeration with smtp-user-enum -MVRFY

'''
logger = logging.getLogger('jpscan')
hdlr = logging.FileHandler('jpscan.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.WARNING)
'''

def main():
    parser = OptionParser(usage="usage: %prog -t <target-ip> [-p <ports> -r <rate> -i <interface>]")
    parser.add_option("-t", "--target", dest="target", help="target to be scanned")
    parser.add_option("-p", "--ports", dest="ports", help="Port range to be scanned, default 0-65535", default="0-65535")
    parser.add_option("-r", "--rate", dest="rate", help="Scan Rate for Massscan, default 7500", default="7500")
    parser.add_option("-i", "--interface", dest="iface", help="Interface used for the scan", default="tun0")
    parser.add_option("-w", "--wait", dest="wait", help="How long to wait for massscan results", default="5")
    parser.add_option("-6", "--6", action="store_true", dest="ipv6", help="Disabled MAC Route detection for IPv6")
    (options, args) = parser.parse_args()
    if not options.target: 
        parser.error('Target not specified')
    port_range = options.ports
    target_ip = options.target
    interface = options.iface
    rate = options.rate
    wait = options.wait
    ipv6 = options.ipv6
    targets= []

    ## Split Targets by IP
    if len(target_ip.split(','))>1:
        for ip in target_ip.split(','):
            targets.append(ip)
    else:
        targets.append(target_ip)
    
    ## Start Scanning
    for ip in targets:
        ## first run Masscan on all target ports to get list of open ports
        target_ports = masscan(ip,port_range,rate,interface,wait,ipv6)
        ## then run nmap with those custome ports
        output = nmap_scan(target_ports)
        # Run Vulnerablity Scan
        nmap_vuln_scan(target_ports)

    ##output
    ##print_results(output)


def print_results(output):
    print("--------------------------------------------")
    print("[+] JPScan Results:")
    print("--------------------------------------------")
    if len(output)==0:
        print("[-] No open ports found =(.. check your syntax")
        print("--------------------------------------------")
        return
    for ip in output:
        print("[+] Results for IP {0}".format(ip))
        for protocol in output[ip]:
            print("[{}]".format(protocol))
            for port in output[ip][protocol]:
                pprint.pprint(port)
        print("--------------------------------------------")


def store_results(output):
    print(output)
    for row in output:
        print(output[row])


#this function takes a banner string as an input and search with searchsploit
#and returns any exploit found. If banner is empty or nothing found returns "not found"
def check_banner(banner): 
    #print("[+] Searchsploit banner: {}".format(banner))
    exploits = []
    if len(banner) < 3:
        print("[-] Banner {} is not valid".format(banner))
        return ["Not found"] 
    if "RPC" in banner:
        print("[-] Banner {} is not valid, try nmap scripts".format(banner))
        return ["RPC - try nmap scripts"] 
    bann1 = banner.split(' ')[0] # split by spaces and use the first part
    bann2 = banner.split('.')[0] # split by . and use the first part
    ## trim the banner to 70% of characters for better results
    bann3 = banner[:int(len(banner)*0.7)].split(" ")
    bann3 = " ".join([bann3[0],bann3[-1]]) # first and last term of full banner
    fbanner = banner.split(" ")
    fbanner = " ".join([fbanner[0],fbanner[-1]]) # first and last term of full banner
    banner_list = [fbanner,bann3,bann2,bann1]
    for bannx in banner_list:
        cmd = 'searchsploit "{0}"'.format(bannx)
        print("[+] Executing: "+cmd)
        searchsploit = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        for line in io.TextIOWrapper(searchsploit.stdout, encoding="utf-8"):
            if "exploits" in line:
                line = line.replace("\x1b[01;31m\x1b[K","")
                line = line.replace("\x1b[m\x1b[K","")
                finding = (line.strip("\n".strip("\r"))).split("|")
                findings = [finding[0].strip(" "),finding[1]]
                exploits.append(findings)
                #print(findings)
                if len(exploits)>4:
                    break
        if len(exploits)>1:
            return exploits
    #print("[-] No Exploits found")
    return ["Not found"]


def website_bruteforce(target):
    print("try)")
    return

def nmap_vuln_scan(target_ports):
    output = {}
    for ip in target_ports:
        ports = []
        udp_ports = []
        for port in target_ports[ip]['tcp']:
            ports.append(port)
        #print(ports)
        tcpports = ','.join(ports)
        #print("tcp ports: "+tcpports)
        if len(target_ports[ip])>1:
            ## this means that there are UDP ports too
            for port in target_ports[ip]['udp']:
                udp_ports.append(port)
            #print(udp_ports)
            udpports = ','.join(udp_ports)
            #print("udp ports: "+udpports)
            cmd = "nmap -sUSVC --script vuln -T4 -pT:{0},U:{2} {1} -Pn -n --open -vvv --min-hostgroup 10 --min-parallelism 100  -oA {1}-vuln-scan".format(tcpports,ip,udpports)
        else:
            cmd = "nmap -sSVC --script vuln -T4 -pT:{0} {1} -Pn -n --open -vvv --min-hostgroup 10 --min-parallelism 100  -oA {1}-vuln-scan".format(",".join(ports),ip)
        print("--------------------------------------------")
        print("[+] Executing: "+cmd)
        nmap = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        for line in io.TextIOWrapper(nmap.stdout, encoding="utf-8"):
            if "VULNERA" in line:
                print(line.strip("\n".strip("\r")))
    return


def nmap_scan(target_ports):
    output = {}
    arr = ['udp','tcp']
    location = 55 #aprox default location of version
    for ip in target_ports:
        ports = []
        udp_ports = []
        for port in target_ports[ip]['tcp']:
            ports.append(port)
        #print(ports)
        tcpports = ','.join(ports)
        #print("tcp ports: "+tcpports)
        if len(target_ports[ip])>1:
            ## this means that there are UDP ports too
            for port in target_ports[ip]['udp']:
                udp_ports.append(port)
            #print(udp_ports)
            udpports = ','.join(udp_ports)
            #print("udp ports: "+udpports)
            cmd = "nmap -A -sU -T4 -pT:{0},U:{2} {1} -Pn -n --open -vvv --min-hostgroup 10 --min-parallelism 100 -oA {1}-full-scan".format(tcpports,ip,udpports)
        else:
            cmd = "nmap -A -T4 -pT:{0} {1} -Pn -n --open -vvv --min-hostgroup 10 --min-parallelism 100 -oA {1}-full-scan".format(",".join(ports),ip)
        print("--------------------------------------------")
        print("[+] Executing: "+cmd)
        nmap = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        for line in io.TextIOWrapper(nmap.stdout, encoding="utf-8"):
            if "VERSION" in line:
                location = line.index("VERSION") #this recalculates the location of the banner in nmap's output
            if "Discovered" in line:
                #print(line.strip("\n".strip("\r")))
                pass
            elif "open" in line:
                if any(c in line for c in arr):
                    print(line.strip("\n".strip("\r")))
                    tmp = line.split(' ')
                    port = (tmp[0].split("/"))[0]
                    prot = (tmp[0].split("/"))[1]
                    banner = line[location:].strip("\n").strip("\r")
                    if banner.strip(" ")=="":
                        banner = "Service not found"
                        exploits = ""
                    else:
                        #exploits = check_banner(banner)
                        exploits = ""
                    if ip in output:
                        if prot in output[ip]:
                            output[ip][prot].append([port,banner,exploits])
                        else:
                            output[ip][prot] = []
                            output[ip][prot].append([port,banner,exploits])
                    else:
                        output[ip] = {}
                        output[ip][prot] = []
                        output[ip][prot].append([port,banner,exploits])
    return output


def get_mac(IP):
    try:
        ping = Popen(["ping","-c 1", IP], stdout=PIPE)
        time.sleep(.500)
        pid = Popen(["arp", "-n", IP], stdout=PIPE)
        s = str(pid.communicate()[0])
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
        return mac
    except Exception as e:
        #print(e)
        print("Failed to calculate MAC, will try without it")
        return 0


def masscan(target_ip,port_range,rate,interface,wait,ipv6):
    if not ipv6:
        mac = get_mac(target_ip)
        ### TCP Scans
        if mac:
            cmd = "masscan -p{0} --wait {5} --rate={1} -e {2} --router-mac {3} {4} -v".format(port_range,rate,interface,mac,target_ip,wait)
        else:
            cmd = "masscan -p{0} --wait {4} --rate={1} -e {2} {3} -v".format(port_range,rate,interface,target_ip,wait)
    else:
        cmd = "masscan -p{0} --wait {4} --rate={1} -e {2} {3} -v".format(port_range,rate,interface,target_ip,wait)
    print("--------------------------------------------")
    print("[+] Executing: "+cmd)
    masscan = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output = {}
    count = 0
    for line in io.TextIOWrapper(masscan.stdout, encoding="utf-8"):
        if "Discovered open port" in line:
            count+=1
            tmp = line.split(' ')
            port = (tmp[3].split("/"))[0]
            prot = (tmp[3].split("/"))[1]
            ip = tmp[5]
            if ip in output:
                if prot in output[ip]:
                    output[ip][prot].append(port)
                else:
                    output[ip][prot] = []
                    output[ip][prot].append(port)
            else:
                output[ip]={}
                output[ip][prot] = []
                output[ip][prot].append(port)
            print(line.strip("\n".strip("\r")))
    print("[+] {} TCP Ports found".format(count))
    print("--------------------------------------------")
    if not ipv6:
        ## UDP Scans
        if mac:
            cmd = "masscan -pU:{0} --wait {5} --rate={1} -e {2} --router-mac {3} {4} -v".format(port_range,rate,interface,mac,target_ip,wait)
        else:
            cmd = "masscan -pU:{0} --wait {4} --rate={1} -e {2} {3} -v".format(port_range,rate,interface,target_ip,wait)
    else:
        cmd = "masscan -pU:{0} --wait {4} --rate={1} -e {2} {3} -v".format(port_range,rate,interface,target_ip,wait)
    print("[+] Executing: "+cmd)
    time.sleep(1)
    masscan2 = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    count = 0
    for line in io.TextIOWrapper(masscan2.stdout, encoding="utf-8"):
        if "Discovered open port" in line:
            count+=1
            tmp = line.split(' ')
            port = (tmp[3].split("/"))[0]
            prot = (tmp[3].split("/"))[1]
            ip = tmp[5]
            if ip in output:
                if prot in output[ip]:
                    output[ip][prot].append(port)
                else:
                    output[ip][prot] = []
                    output[ip][prot].append(port)
            else:
                output[ip]={}
                output[ip][prot] = []
                output[ip][prot].append(port)
            print(line.strip("\n".strip("\r")))
    print("[+] {} UDP Ports found".format(count))
    return output

if __name__ == "__main__":
    main()
