#!/usr/bin/env python3

import ipaddress
import json
import logging
import math
import os
import sys
import time
import xml.dom.minidom

import iptools
import requests
import urllib3.util.retry

from logging.handlers import RotatingFileHandler

# API calls

# Initialise the API
def init_api(url,
             headers=None,
             retries=3,
             backoff_factor=0.3,
             status_forcelist=(500, 502, 504),
             ):

    session = requests.Session()

    retry = urllib3.util.retry.Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )

    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,
        pool_maxsize=20,
        max_retries=retry)

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if headers != None:
        session.headers.update(headers)

    return (session, url)

# Send a GET request to the REST interface
def get(api, request):

    (session, url) = api

    try:
        response = session.get(str.format("{}{}", url, request))
    except Exception as x:
        logging.error(str.format("GET failed :({})", x.__class__.__name__))
        exit(1)

    if response.status_code == 404:
        logging.error(str.format("{} failed with 404 (not found)", request))
        exit(1)

    return response

# Initialise the session, with the API key, URL and headers
def init_session(api_key):
    return init_api("https://api.meraki.com/api/v0", {'content-type': 'application/json', 'X-Cisco-Meraki-API-Key': api_key})

# Get the devices associated with all of the networks
def get_devices(api, nets, fixed_ips={}):
    devices = []
    t = time.time()

    for net in networks:

        response = get(api, str.format("/networks/{}/devices", net))

        for dev in response.json():
            name = ""

            if dev['name']:
                name = dev['name']
            elif dev['mac'] in fixed_ips:
                name = fixed_ips[dev['mac']]['name']
            else:
                name = str.format("device-{}", dev['serial'])

            if dev['lanIp'] != None:
                dev['name'] = name
                dev['net'] = net
                dev['time'] = t
                devices.append(dev)

    return devices

# Get the fixed IP assignments associated with all of the networks
def get_fixed(api, nets):
    fixed_ips = {}
    count = 0

    # Fixed IPs are associated with VLANs
    for net in nets:

        response = get(api, str.format("/networks/{}/vlans", net))
        if response.status_code == 200:
            for vlan in response.json():
                for mac in vlan['fixedIpAssignments']:
                    name = str.format("fixed-{}", vlan['fixedIpAssignments'][mac]['ip'])
                    count += 1

                    fixed_ips[mac] = {
                        'name': name, 
                        'ip': str(vlan['fixedIpAssignments'][mac]['ip'])
                    }

    return fixed_ips

# Get the clients associated with all of the devices
def get_clients(api, devs, fixed_ips={}, timespan=60):
    clients = []

    t = time.time()
    for dev in devs:
        
        #  While timespan Approaches 1 do:
        response = get(api, str.format("/devices/{}/clients?timespan={}", dev['serial'], timespan))
        if response.status_code != 200:
            break

        for client in response.json():
            name = ""

            if client['dhcpHostname']:
                name = client['dhcpHostname']
            elif client['description']:
                name = client['description']
            elif client['mdnsName']:
                name = client['mdnsName']
            elif (client['mac'] in fixed_ips):
                name = fixed_ips[client['mac']]['name']
            else:
                name = str.format("client-{}", client['id'])
            
            duplicates = settings.get('duplicates', {})
            if name in duplicates:
                name = str.format("{}-{}", name, client['id'])
            
            if client['ip'] != None:
                client['dhcpHostname'] = name
                client['dev'] = dev
                client['time'] = t
                clients.append(client)

    return clients

# Device record handling

# Dump the records to the out_file, unless there isn't one,
# in which case, I'm not sure why we're doing it.
def dump_records(records, out_file=None):
    count = 0
    for key in sorted(records.keys()):
        if out_file != None:
            dump_record_to_file(out_file, key, records[key])
        count += 1
    return count

# Prune records from the list
def prune_records(records, too_old=None, verbose=False):
    keys = set(records.keys())
    changed = False
    for key in keys:
        if should_prune(records[key], too_old):
            if verbose:
                logging.info(str.format("pruned: -{}", key))
            del records[key]
            changed = True

    return changed

# Add a record to the list
def add_record(records, key, record, verbose=False):
    changed = False
    if key in records:
        records[key] = should_keep(records[key], record)
    else:
        records[key] = record
        changed = True
        if verbose:
            logging.info(str.format("added: +{}", key))

    return changed

# Dump a single record to the out_file
def dump_record_to_file(out_file, key, record):
    save = dict(record)
    save['ipaddress'] = None
    json.dump(save, out_file)
    out_file.write('\n')
    return

# Compare two records and decide which one to keep
def should_keep(a, b):
    if a['priority'] < b['priority']:
        # r is the better option
        r = a
    elif a['priority'] > b['priority']:
        # d is the better option
        r = b
    elif a['time'] > b['time']:
        # Keep the newer one!
        r = a
    else:
        r = b

    return r

# Is the record's time less than or equal to the prune_time?
def should_prune(record, prune_time):
    return (record['time'] <= prune_time)

# Create a record for the device
def create_record(name, ip, mac, hostname, network, priority=0, time=0, fixed=False):
    record = {
        'mName': name,
        'ip': ip,
        'mac': mac,
        'hostname': hostname,
        'network': network,
        'priority': priority,
        'time': time,
        'fixed': fixed,
    }
    return record

# Add a deivce record to the IP list
def add_device(record, verbose=False):
    return add_record(iplist, record['ip'], record, verbose)

# Prune devices that are too old
def prune_devices(too_old, verbose=False):
    return prune_records(iplist, too_old, verbose)

# Dump the device records (to a file, if need be)
def dump_devices(out_file=None):
    return dump_records(iplist, out_file)

# Uodates the cyberprobe.cfg file
def update_config(state):
    try:
        dom = xml.dom.minidom.parse(cfg)
    except Exception as e:
        logging.info(e.__cause__)
        return

    targets = dom.documentElement.getElementsByTagName("targets")[0]
    while targets.hasChildNodes():
        targets.removeChild(targets.firstChild)

    targets.appendChild(dom.createTextNode('\n'))

    for record in iplist:
        address = iplist[record]['ip']
        ip = ipaddress.ip_address(address)
        targets.appendChild(dom.createTextNode("    "))
        target = dom.createElement("target")
        target.setAttribute("address", address)
        target.setAttribute("llid", iplist[record]['hostname'])
        target.setAttribute("network", get_network_name(ip))
        target.setAttribute("class", str.format("ipv{}", ip.version))
        targets.appendChild(target)
        targets.appendChild(dom.createTextNode('\n'))

    for mac in state['fixed']:
        name = state['fixed'][mac]['name']
        address = state['fixed'][mac]['ip']
        fixed_network = settings.get('fixed_network', 'fixed')
        ip = ipaddress.ip_address(address)
        targets.appendChild(dom.createTextNode("    "))
        target = dom.createElement("target")
        target.setAttribute("address", address)
        target.setAttribute("llid", name)
        target.setAttribute("network", fixed_network)
        target.setAttribute("class", str.format("ipv{}", ip.version))
        targets.appendChild(target)
        targets.appendChild(dom.createTextNode('\n'))

    for key in cidr_ranges:
        name = cidr_ranges[key]['name']
        network = cidr_ranges[key]['network']
        targets.appendChild(dom.createTextNode("    "))
        target = dom.createElement("target")
        target.setAttribute("address", key)
        target.setAttribute("llid", "device-%i")
        target.setAttribute("network", name)
        target.setAttribute("class", str.format("ipv{}", network.version))
        targets.appendChild(target)
        targets.appendChild(dom.createTextNode('\n'))

    s = open(cfg, "w")
    s.write(dom.toprettyxml(indent="", newl=""))
    s.close()

    logging.info("Updated cyberprobe.cfg")

# Get the network name from the CIDR ranges
def get_network_name(ip):
    name = "unknown"
    for key in cidr_ranges:
        network = cidr_ranges[key]['network']
        if ip in network:
            name = cidr_ranges[key]['name']
            break

    return name

# Harvest the Meraki data
def get_data(api, state={}, timeSpan=60):

    allJson = []

    if state.get('init', 0) == 0:
        state['fixed'] = {}
        state['devices'] = []
        state['init'] = 4
        state['devMap'] = {}

        logging.info("Getting fixed IPs")
        t0 = time.time()
        state['fixed'] = get_fixed(api, networks)
        logging.info(str.format("Got fixed IPs in {} seconds", time.time()-t0))

        logging.info("Getting devices")
        t0 = time.time()
        state['devices'] = get_devices(api, networks, fixed_ips=state['fixed'])
        logging.info(str.format("Got devices in {} seconds", time.time()-t0))

        for dev in state['devices']:
            state['devMap'][dev['mac']] = False

            record = create_record(
                name=dev['serial'],
                ip=dev['lanIp'],
                mac=dev['mac'],
                hostname=dev['name'],
                network=dev['net'],
                priority=50,
                time=dev['time'],
                fixed=(dev['mac'] in state['fixed'])
            )

            allJson.append(record)

    state['init'] -= 1
    logging.info("Getting clients")
    t0 = time.time()
    clients = get_clients(api, state['devices'], timespan=timeSpan, fixed_ips=state['fixed'])
    logging.info(str.format("Got clients in {} seconds", time.time()-t0))

    for client in clients:

        if state['devMap'].get(client['mac'], True):
            allJson.append(
                create_record(name=client['id'],
                           ip=client['ip'],
                           mac=client['mac'],
                           hostname=client['dhcpHostname'],
                           network=client['dev']['net'],
                           priority=1,
                           time=client['time'],
                           fixed=(client['mac'] in state['fixed'])
                           )
            )

    return allJson, state

# Create the CIDR ranges from the config
def create_ranges(data):
    ranges = {}
    if data != {}:
        for key in data:
            ranges[key] = { "name": data[key], "network": ipaddress.ip_network(key) }
    else:
        ranges = { 
            "10.0.0.0/8": { "name": "private_range", "network": ipaddress.ip_network("10.0.0.0/8")},
            "192.168.0.0/16": { "name": "private_range", "network": ipaddress.ip_network("192.168.0.0/16")}
            }

    return ranges

# Set the logging level from the configuration
def set_up_logging():
    # Using a rotating file handler keeps the local log from filling up our disk space
    rotate = RotatingFileHandler("harvester.log", maxBytes=100000, backupCount=5)
    rotate.setLevel(logging.DEBUG)
    log_formatter = logging.Formatter(fmt="%(asctime)s : %(levelname)-8s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    rotate.setFormatter(log_formatter)
    logging.getLogger('').addHandler(rotate)

    # This will print to the console when run locally and to the systemd log when run as a service
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    formatter = logging.Formatter(fmt="meraki-harvester : %(levelname)-8s: %(message)s")
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

# Main Loop
api_key = None
iplist = {}
dirty = True
settings = None
cidr_ranges = {}
networks = None

set_up_logging()

if len(sys.argv) != 2:
    print("./meraki.py [config_file]")
    exit(1)

try:
    filename = sys.argv[1]

    logging.info("Opening settings file")

    if os.path.lexists(filename):
        with open(filename,"r") as config_file:
            settings = json.load(config_file)
    else:
        logging.error(str.format("Settings file {} not found", filename))
        exit(127)

except Exception as e:
    logging.error(e)
    exit(1)

api_key = settings.get('api_key', "")

if api_key == "":
    logging.error("API key not found")
    exit(1)

networks = settings.get('networks', [])

if networks == []:
    logging.error("Networks list is empty")
    exit(1)

cfg = settings.get('config_location', './cyberprobe.cfg')
poll_interval = settings.get('poll_interval', 60)
state_file = settings.get('state_file', './meraki.out')
init_delta = settings.get('init_delta', 3600)

cidr_ranges = create_ranges(settings.get('ranges', {}))

api = init_session(api_key)

logging.getLogger().setLevel(logging.INFO)

# init state from state file if it exits
t = 0
tSpan = init_delta

if os.path.lexists(state_file):
    m = 0
    f = open(state_file, "r")
    for line in f:
        jsonRec = json.loads(line)
        add_device(jsonRec)
        m += 1
        if (jsonRec['time'] > t):
            t = jsonRec['time']

    f.close()
    logging.info(str.format("Rest'd: {}", m))

    n = dump_devices()

    logging.info(str.format("IPs: {}", n))

    tSpan = int(math.ceil(time.time() - t)) + 1
    logging.info(str.format("Delta: {}", tSpan))

# Do the initial pull of data based on timespan of
# initDelta or Delta calculated from state restore
logging.info(str.format("Timespan: {}", tSpan))

lastTime = time.time()
jsonList, mState = get_data(api, timeSpan=tSpan+1)

for jsonRec in jsonList:
    add_device(jsonRec)

n = dump_devices()

logging.info("After Init")
logging.info(str.format("IPs: {}", n))

#
# Main loop
# Pulls state every deltaTimeSpan seconds
# purges records that are older than initDelta + 10% seconds
# outputs records de-dup'd on IP to destFile
#
flipFlop = 0
while True:

    thisTime = time.time()
    tSpan = thisTime - lastTime + 1
    lastTime = thisTime
    logging.info(str.format("Timespan: {}", tSpan))

    # Get rid of things that we haven't seen in initDelta + 10% seconds
    tooOld = thisTime - init_delta*1.1

    dirty = prune_devices(tooOld, verbose=True)

    jsonList, mState = get_data(api, state=mState, timeSpan=tSpan)

    for jsonRec in jsonList:
        dirty = add_device(jsonRec, verbose=True) or dirty

    out_file = str.format(".{}.tmp.{}", state_file, str(flipFlop & 3))
    if os.path.lexists(out_file):
        os.remove(out_file)
    f = open(out_file, 'w')
    flipFlop += 1

    if flipFlop == 1:
        dirty = True

    n = dump_devices(out_file=f)

    if dirty:
        update_config(mState)
        dirty = False

    f.close()

    logging.info(str.format("IPs: {}", n))

    if os.path.lexists(state_file):
        os.remove(state_file)
    os.rename(out_file, state_file)

    logging.info(str.format("Sleep: {}", poll_interval))
    time.sleep(poll_interval)
