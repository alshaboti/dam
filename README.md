# pegler
An attempt to connect Faucet SDN controller with BRO IDS. Such that when BRO detects malicious connections it sends events to backend python script which then update faucet.yaml configuration file with the action required.

### Network setup
We utalized docker containers with OVS and docker-ovs.  
The network includes one OVS switch (sw1) and one container for each faucet and three hosts: 
- server on port1 
- client on port2. 
- bro on port3 
Faucet configured to mirror all server in-bound packets (in port1) to bro in port3.

faucet.yaml file is as follows
```
acls:
  block_acl:
  - rule:
      actions:
        allow: false
  def_acl:
  - rule:
      actions:
        allow: true
  mirror_acl:
  - rule:
      actions:
        allow: true
        mirror: 3
dps:
  sw1:
    dp_id: 0x01
    hardware: Open vSwitch
    interfaces:
      1:
        acls_in:
        - mirror_acl
        description: web server
        name: lan2
        native_vlan: office
      2:
        acls_in:
        - def_acl
        description: web client 
        name: lan3
        native_vlan: office
      3:
        description: BRO IDS
        name: BRO
        native_vlan: office
vlans:
  office:
    description: office network
    vid: 101
```
## Build the network
You need to have docker, docker-ovs and OVS requirements installed. 
Start by sourcing `bro-test.sh` file.
```
source bro-test.sh
```
The `bro-test.sh` bash file contains scripts to: 
- create faucet, bro, server, client docker containers `create_bro_conts`.
- Create OVS and connect docker containers `create_bro_net`.  
- Check the network setup `check_bro_net`. 
- Clear all `clear_bro_net_all`. 
- Reload faucet configuration file `faucet_relaod_config`. 

## Run the test
1- On xterm window of BRO run 
```
cd pegler
bro -C -i eth1 simple-test.bro
```
2- On the other xterm Bro window run
```
cd pegler
python simple-client.py
```
3- On server xterm  run simple web server
```
python -m http.server 8000
```
4- On client/host run
```
# send http request to the server
wget http://192.168.0.1:8000
```
This connection should be mirrored by Faucet to Bro. 
Which will use netcontrol and broker frameworks to pass drop rule to simple-client.py program. 
You should be able to see `new connection!` printed out in python broker script that you run in step 2. 

Now, python script can update faucet.yaml file based on such events received from BRO. 


More abotu netControl is in here https://docs.zeek.org/en/stable/frameworks/netcontrol.html
Tested with OVS, test script modified from https://github.com/bro/bro-netcontrol/tree/master/test
