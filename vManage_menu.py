"""
Class with REST Api GET and POST libraries

cli example: python rest_api_lib.py vmanage_hostname username password
###This was created on Python 3###
--Make sure you run the download_modules.sh file prior to running this script--
PARAMETERS:
    vmanage_hostname : Ip address of the vmanage or the DNS name of the vmanage
    username : Username to login the vmanage
    password : Password to login the vmanage

Note: All the three arguments are manadatory
"""
################################################################################################
# Adapted from Cisco's vManage SD-WAN demo, make sure viptela is installed on your pc as it does
# most of the heavy lifting.  pip install viptela            make sure line 22 matches your file
# structure, it should be 'from directory.file import class_name'  viptela folder should be in 
# the same directory as this file
# make sure you run the download_modules.sh file prior to running this script
# ---------------------------------
# Author: Aaron Gearhart
# Date: 7/23/2019
################################################################################################
import requests
import sys, os
import json
import math
import pip
import time
from viptela.viptela import Viptela
from tabulate import tabulate
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

base_URL = 'null'


class rest_api_lib:
    def __init__(self, vmanage_ip, username, password):
        self.vmanage_ip = vmanage_ip
        self.session = {}

    def get_request(self, mount_point):
        """GET request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        print( url)
        response = self.session[self.vmanage_ip].get(url, verify=False)
        data = response.content
        return data

    def post_request(self, mount_point, payload, headers={'Content-Type': 'application/json'}):
        """POST request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        payload = json.dumps(payload)
        response = self.session[self.vmanage_ip].post(url=url, data=payload, headers=headers, verify=False)
        data = response.content


def print_data(headers, table):
    print(tabulate(table, headers, tablefmt="fancy_grid"))

def get_init_val(vmanage):
    ip = list()
    name = list()
    devices = vmanage.get_all_devices()
    for item in devices.data:
        ip.append(item['deviceId'])
        name.append(item['host-name'])
    return ip, name

def assemble_table(devices, headers):
    try:
        table = list()
        for item in devices.data:
            tr = []
            for i in range(len(headers)):
                tr.append(item[headers[i]])
            table.append(tr)
        print_data(headers, table)
    except:
        print("Error: can't assemble table, No data to present\n")

def get_headers(devices):
    try:
        headers = []
        headers = list(devices.data[0].keys())
        return headers
    except:
        print("Error: can't get headers, no data to present\n")

def get_arp(vmanage, ip):
    devices = vmanage.get_arp_table(ip)
    headers = ['if-name', 'vdevice-dataKey', 'vdevice-name', 'ip', 'lastupdated', 'state', 'vpn-id', 'uptime-date', 'vdevice-host-name', 'mac', 'uptime']
    table = list()
    for item in devices.data:
        tr = [item[headers[0]], item[headers[1]], item[headers[2]], item[headers[3]], item[headers[4]], item[headers[5]], item[headers[6]], item[headers[7]], item[headers[8]], item[headers[9]], item[headers[10]]]
        table.append(tr)
    print_data(headers, table)

def check_data(devices, headers):
    try:
        for i in headers:
            if i not in devices.data:
                headers.remove(i)
        return headers
    except:
        print("Error: can't check data, no data to present\n")

def get_uuid(vmanage):
    devices = vmanage.get_device_maps()
    uuids = list()
    for item in devices.data:
        uuids.append(item['uuid'])
    return uuids

def init_table(devices):
    ct = 0
    headers_t = get_headers(devices)
    headers_t = check_data(devices, headers_t)
    mod = math.ceil(len(headers_t)/7)
    while mod != 0:
        if ct == 0:
            assemble_table(devices, headers_t[:ct+7])
        else:
            assemble_table(devices, headers_t[ct:ct+7])
        ct= ct + 7
        mod = mod - 1

def main(args):
    if not len(args) == 3:
        print (__doc__)
        return
    global base_URL
    global vmanage
    choice = "start"
    choices = ["host-name","system-ip"]

    options = {"uptime-date":"uptime-date", "device-type":"device-type", "site-id":"site-id", "status":"status", "device-os":"device-os", "remote-tloc-address":"remote-tloc-address", 
    "local-tloc-address":"local-tloc-address", "remote-tloc-color":"remote-tloc-color", "interface-name":"if-name", "ARP-table*":"get-ARP",
    "lastupdated":"lastupdated", "reachability":"reachability", "control-connection*":"control-connection", "control-connection-history*":"cc-history", "get-interface*":"get-interface",
    "routing-table*":"routing", "running-config*":"running-config", "tunnel-stats*":"tunnel", "certificate":"certificate-validity", "timezone":"timezone", "personality":"personality",
    "device-groups":"device-groups", "board-serial":"board-serial", "platform":"platform", "state":"state", "isDeviceGeoData":"isDeviceGeoData", "state-description":"state_description",
    "version":"version", "certificate-validity":"certificate-validity", "max-controllers":"max-controllers", "connectedvManages":"connectedVManages", "controlConnections":"controlConnections",
    "system-ip":"system-ip", "bgp-neighbors*":"bgp-neighbors", "bgp-routes*":"bgp-routes", "bgp-summary*":"bgp-summary", "cellular-modem*":"cellular-modem", "cellular-network*":"cellular-network", "cellular-profiles*":"cellular-profiles",
    "cellular-radio*":"cellular-radio", "cellular-sessions*":"cellular-sessions", "cellular-status*":"cellular-status", "ipsec-localsa*":"ipsec-localsa", "ipsec-inbound*":"ipsec-inbound",
    "ipsec-outbound*":"ipsec-outbound", "omp-peers*":"omp-peers", "omp-summary*":"omp-summary", "ospf-database*":"ospf-database", "ospf-interface*":"ospf-interface", "ospf-routes*":"ospf-routes", "ospf-neighbors*":"ospf-neighbors"}
    print()
    vmanage_ip, username, password = args[0], args[1], args[2]
    base_URL = "https://%s:8443/dataservice/"%(vmanage_ip)
    print("==============================Connecting==============================\n\n")
    print("Connecting to %s vManage Server...\n"% vmanage_ip)
    vmanage = Viptela(user=username, user_pass=password, vmanage_server=vmanage_ip, vmanage_server_port=8443)
    print("++++++++++++++++++++++++++++++Connected+++++++++++++++++++++++++++++++\n\n")
    functions = dir(vmanage)
    ips, names = get_init_val(vmanage)
    print("--------------DATA POINTS--------------")
    for i in options:
        print(i)
    print("\n##########LIST OF IP ADDRESSES##########\n")
    print("\nIP............HOSTNAME\n")
    for i in range(len(ips)):
        print(ips[i] + "......" +  names[i])

    print("\n\nPlease select the data you want to retrieve from the vManage Server (Host-Name & IP are selected by default) ")
    print("Some attributes (*) will require input on which IP you want data from, ex. ARP Tables, and will create their own table ")
    print("Yes, you need to type in the '*' for the script to recognize it\n")
    while choice != "done":
        choice = str(input("Make a selection or type 'done' to stop: "))
        if choice in options and choice != "done":
            choices.append(options[choice])
            print("%s added to the cart"% options[choice])
        elif choice not in options and choice != "done":
            print("It looks like you mispelled your choice, try again")
            print()
    print()
    if "get-ARP" in choices or "remote-tloc-color" in choices or "local-tloc-address" in choices or "remote-tloc-address" in choices or "if-name" in choices:
        ip = input("\nType in the ip you want to see on the ARP table: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        get_arp(vmanage, ip)
        for i in choices:
            if i == "get-ARP" or i == "remote-tloc-color" or i == "local-tloc-address" or i == "remote-tloc-address" or i == "if-name":
                choices.remove(i)

    if "control-connection" in choices:
        ip = input("\nType in the ip you want to get control connections for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_control_connections(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("No Contronl Connection data to present\n")
        choices.remove("control-connection")

    if "cc-history" in choices:
        ip = input("\nType in the ip you want to get control connections for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_control_connections_history(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("No Control Connection History to present\n")
        choices.remove("cc-history")

    if "get-interface" in choices:
        ip = input("\nType in the ip you want to get interfaces for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_interfaces(ip)
        if devices.data != {}:
            headers_int = get_headers(devices)
            headers_ints = check_data(devices, headers_int)
            headers_ints.remove("mtu")
            headers_ints.remove("auto-neg")
            headers_ints.remove("desc")
            mod = math.ceil(len(headers_ints)/7)
            while mod != 0:
                if ct == 0:
                    assemble_table(devices, headers_ints[:ct+7])
                else:
                    assemble_table(devices, headers_ints[ct:ct+7])
                ct= ct + 7
                mod = mod - 1
        else:
            print("No interface data to present\n")
        choices.remove("get-interface")

    if "routing" in choices:
        ip = input("\nType in the ip you want the routing table for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_routing_table(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("No routing data to present\n")
        choices.remove("routing")


    if "running-config" in choices:
        uuids = get_uuid(vmanage)
        print("List of UUIDs for reference:\n")
        for i in range(len(names)):
            print(names[i], "..............", uuids[i])
        uuid = input("\nType in the UUID (Device ID) you want the running config for (copy/paste should work): ")
        while uuid not in uuids:
            uuid = input("\nTry typing in the UUID again: ")
        devices = vmanage.get_running_config(uuid)
        if devices.data != '':
            print(devices.data)
        else:
            print("No running config data to present on this UUID\n")
        choices.remove("running-config")

    if "tunnel" in choices:
        ip = input("\nType in the IP you want the tunnel statistics for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_tunnel_statistics(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get tunnel data, no data to present\n")
        choices.remove("tunnel")

    if "bgp-neighbors" in choices:
        ip = input("\nType in the IP you want bgp neighbors for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_bgp_neighbors(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get bgp neighbor data, no data to present\n")
        choices.remove("bgp-neighbors")

    if "bgp-routes" in choices:
        ip = input("\nType in the IP you want bgp routes for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_bgp_routes(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get bgp route data, no data to present\n")
        choices.remove("bgp-routes")

    if "bgp-summary" in choices:
        ip = input("\nType in the IP you want the bgp summary for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_bgp_summary(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get bgp summary data, no data to present\n")
        choices.remove("bgp-summary")

    if "cellular-modem" in choices:
        ip = input("\nType in the IP you want cellular-modem data for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_cellular_modem(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get cellular modem data, no data to present\n")
        choices.remove("cellular-modem")

    if "cellular-network" in choices:
        ip = input("\nType in the IP you want cellular network data for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_cellular_network(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get cell network data, no data to present\n")
        choices.remove("cellular-network")

    if "cellular-profiles" in choices:
        ip = input("\nType in the IP you want cellular profiles for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_cellular_profiles(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get cell profile data, no data to present\n")
        choices.remove("cellular-profiles")

    if "cellular-radio" in choices:
        ip = input("\nType in the IP you want cellular radio data for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_cellular_radio(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get cell radio data, no data to present\n")
        choices.remove("cellular-radio")

    if "cellular-sessions" in choices:
        ip = input("\nType in the IP you want cellular session data for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_cellular_sessions(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get cell session data, no data to present\n")
        choices.remove("cellular-sessions")

    if "cellular-status" in choices:
        ip = input("\nType in the IP you want cell status for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_cellular_status(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get cell status data, no data to present\n")
        choices.remove("cellular-status")

    if "ipsec-localsa" in choices:
        ip = input("\nType in the IP you want IPsec Local Security association data for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_ipsec_localsa(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get localsa data, no data to present\n")
        choices.remove("ipsec-localsa")

    if "ipsec-inbound" in choices:
        ip = input("\nType in the IP you want IPsec inbound data for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_ipsec_inbound(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get IPsec inbound data, no data to present\n")
        choices.remove("ipsec-inbound")

    if "ipsec-outbound" in choices:
        ip = input("\nType in the IP you want IPsec outbound data for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_ipsec_outbound(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get IPsec outbound data, no data to present\n")
        choices.remove("ipsec-outbound")

    if "omp-peers" in choices:
        ip = input("\nType in the IP you want OMP peer data for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_omp_peers(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get OMP peer data, no data to present\n")
        choices.remove("omp-peers")

    if "omp-summary" in choices:
        ip = input("\nType in the IP you want an OMP summary for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_omp_summary(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get OMP summary data, no data to present\n")
        choices.remove("omp-summary")

    if "ospf-database" in choices:
        ip = input("\nType in the IP you want the OSPF Database for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_ospf_database(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get OSPF Database data, no data to present\n")
        choices.remove("ospf-database")

    if "ospf-interface" in choices:
        ip = input("\nType in the IP you want the OSPF interface data for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_ospf_interfaces(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get OSPF interface data, no data to present\n")
        choices.remove("ospf-interface")

    if "ospf-routes" in choices:
        ip = input("\nType in the IP you want the OSPF routes for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_ospf_routes(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get OSPF route data, no data to present\n")
        choices.remove("ospf-routes")

    if "ospf-neighbors" in choices:
        ip = input("\nType in the IP you want the OSPF neighbor data for: ")
        while ip not in ips:
            ip = input("\nTry typing in the IP again: ")
        devices = vmanage.get_ospf_neighbours(ip)
        if devices.data != {}:
            init_table(devices)
        else:
            print("Can't get OSPF neighbor data, no data to present\n")
        choices.remove("ospf-neighbors")

    print("\n--Assembling Custom Table--\n")
    time.sleep(1)
    devices = vmanage.get_all_devices()
    ##there are two devices/choices in case one request has different data than the other##
    devices2 = vmanage.get_device_maps()
    choices2 = ["host-name","system-ip"]
    for i in choices:
        if i not in list(devices.data[0].keys()):
            choices2.append(i)
            choices.remove(i)
    assemble_table(devices, choices)
    assemble_table(devices2, choices2)


if __name__ == "__main__":
    main(sys.argv[1:])
