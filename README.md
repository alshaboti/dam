# pegler
Tested with OVS, test script modified from https://github.com/bro/bro-netcontrol/tree/master/test
- port1: http server, with allow and mirror to port 3
```
python -m SimpleHTTP 8000
# or
python -m http.server 8000
```
Note:
Check here to set python path for netcontrol   
https://github.com/bro/bro-netcontrol
- port2: http client, with allow all acl
```
wget http://192.168.1.10
```
- port3: Bro in this port with no faucet acl 
Start with broker listener
```
python simple-client.py
```
Then bro
```
sudo bro -C -i eth0 simple-test.bro
```

Then make a request from http client to http server. 
```
wget http://192.168.1.10
```
This connection should be mirrored by Faucet to Bro. Which will use netcontrol and broker frameworks to pass drop rule to simple-client.py program. 
```
@load base/frameworks/netcontrol

redef exit_only_after_terminate = T;

event NetControl::init()
        {
        local netcontrol_broker = NetControl::create_broker(NetControl::BrokerConfig($host=127.0.0.1, $bport=9977/tcp, $topic="bro/event/netcontrol$
        NetControl::activate(netcontrol_broker, 0);
        }

event NetControl::init_done() &priority=-5
        {
        print "Init done";
        }

event connection_established(c: connection)
    {
    NetControl::drop_address(c$id$orig_h, 15sec, "Hi there");
    }
```
More abotu netControl is in here https://docs.zeek.org/en/stable/frameworks/netcontrol.html

