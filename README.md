# meraki-harvester

A Python 3 service for harvesting Meraki data and using it to enrich `cyberprobe.cfg`.

See https://github.com/cybermaggedon/cyberprobe for information about `cyberprobe` and `cybermon`

## meraki.py

### Prerequsites

- Install `python3` and `pip3`
- Use `pip3` to install `iptools` and `requests`

### Usage

Use `meraki.json.dist` as the basis of your configuration file.

```shell
$ ./meraki.py [config_file]
```

or sometimes

```shell
$ python3 meraki.py [config_file]
```

## Deploy as a `systemd` service

### First

- Choose/create a working directory for the script.
- Copy `meraki.py` to your working directory.
- Copy `meraki.json.dist` to `meraki.json` in the working directory.
- Edit `meraki.json` as documented in the file. The `api_key` and `networks` entries are required.
- Copy the file `meraki-harvester.service.dist` to `/etc/systemd/system/meraki-harvester.service`.
- In `meraki-harvester.service`, set the `User`, `WorkingDirectory` and `ExecStart` entries as described in the file.

### Then

Perform the following to install and run the service.

```shell
# Reload `systemd`
$ sudo systemctl daemon-reload

# Enable the service
$ sudo systemctl enable meraki-harvester.service

# Start the service
$ sudo systemctl start meraki-harvester.service

# Then you can check the status of the service
$ sudo systemctl status meraki-harvester.service

# And you can stop or restart the service
$ sudo systemctl stop|restart meraki-harvester.service

# And check the log
$ sudo journalctl -u meraki-harvester.service
```

## State File JSON Record format

```text
{
   "priority" : <Integer> - internal priority of the record (lower is better)
   "mac" : <string> - MAC address of the device
   "fixed" : <boolean> - True if the device is using a reserved static IP address
   "network" : <string> - ID of the Meraki *Network* to which the device is connected
   "ip" : <string> - IP address currently assigned to the device
   "mName" : <string> - Unique persistent internal Meraki identifier for the device
   "hostname" : <string> - Current hostname used by the device
   "time" : <float> Creation time of the record in Python time.time() format
}
```

## Running some queries using the API

### Get all of the organisations attached to the account

```shell
curl -L -H 'X-Cisco-Meraki-API-Key: [key]' -H 'Content-Type: application/json' \
    -X GET 'https://api.meraki.com/api/v0/organizations'
```

### Get all of the networks attached to an organisation

```shell
curl -L -H 'X-Cisco-Meraki-API-Key: [key]' -H 'Content-Type: application/json' \
    -X GET 'https://api.meraki.com/api/v0/organizations/[organization-id]/networks'
```

### Get all of the devices attached to a network

```shell
curl -L -H 'X-Cisco-Meraki-API-Key: [key]' -H 'Content-Type: application/json' \
    -X GET 'https://api.meraki.com/api/v0/networks/[network-id]/devices'
```

### Get all of the clients attached to an device over the last day

```shell
curl -L -H 'X-Cisco-Meraki-API-Key: [key]' -H 'Content-Type: application/json' \
    -X GET 'https://api.meraki.com/api/v0/devices/[device-id]/clients?timespan=86400'
```

### Other stuff

[Meraki REST API Reference](https://documentation.meraki.com/zGeneral_Administration/Other_Topics/The_Cisco_Meraki_Dashboard_API)  
[Meraki Documentation Home](https://documentation.meraki.com/)
