#!/usr/bin/env python

# Simple command line client using the provided API. Test, e.g., with
# the provided simple-test.bro

import paramiko, os


import logging, netcontrol, pprint


def update_faucet_yaml():
   os.system("scp simple-client.py pi@192.168.3.100:/home/pi/simple-client.py") #moh@192.168.5.8:/home/moh/etc/ryu/faucet/faucet.yaml faucet.yaml")
#   with open('faucet.yaml', 'r') as file_stream:
 #    try:
  #     faucet_conf =  load(file_stream)
   #    except YAMLError as exc:
    #      print(exc)

   #self.faucet_yaml = faucet_conf

update_faucet_yaml()
print("faucet done!")

logging.basicConfig(level=logging.DEBUG)

ep = netcontrol.Endpoint("bro/event/netcontrol-example", "127.0.0.1", 9977);
pp = pprint.PrettyPrinter(indent=4)

while 1==1:
    response = ep.getNextCommand()
    pp.pprint(response.type)

    if response.type == netcontrol.ResponseType.AddRule:
        ep.sendRuleAdded(response, "")
    elif response.type == netcontrol.ResponseType.RemoveRule:
        ep.sendRuleRemoved(response, "")
    else:
        continue
    print("START")
    pp.pprint(response.rule);
    print("END!")
