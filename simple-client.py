#!/usr/bin/env python

# Simple command line client using the provided API. Test, e.g., with
# the provided simple-test.bro

import os
import re
#import paramiko
from yaml import load, dump, YAMLError, safe_dump

import logging
import netcontrol
import pprint

pp = pprint.PrettyPrinter(indent=4)


class faucet_management:
  faucet_yaml = {}

  def __init__(self):
    self.remote_faucet_host = "root@192.168.3.100"
    self.remote_faucet_file = "/etc/faucet/faucet.yaml"
    self.local_faucet_file = "./faucet.yaml"

  # get faucet yaml file using ssh client 
  def get_faucet_yaml(self):
 #    cmd = "scp " + self.remote_faucet_host + ":" + self.remote_faucet_file \
  #               + " " + self.local_faucet_file
   #  os.system(cmd)

     with open('/etc/faucet/faucet.yaml', 'r') as file_stream:
       try:
         faucet_conf =  load(file_stream)
       except YAMLError as exc:
          print(exc)

     self.faucet_yaml = faucet_conf
     return self.faucet_yaml

  # write faucet yaml file and restart fuacet using ssh
  def set_faucet_yaml(self, remote=False):
      # dump to local file
      with open("/etc/faucet/faucet.yaml", "w") as fd:
          dump(self.faucet_yaml, fd, default_flow_style=False, Dumper=noalias_dumper)
      # it works as long as you set ssh key between the two hosts
      # scp faucet.yaml to remote faucet
#      if remote:
 #        os.system("scp "+ self.local_faucet_file +" "+ self.remote_faucet_host+":"+self.remote_faucet_file)
         # reload faucet.yaml docker 
  #       os.system("ssh "+ self.remote_faucet_host + " docker kill --signal=HUP faucet_faucet_1" )


def blockSrcIp(srcIP):
   blockrule = {'rule':{'dl_type': 0x800 ,'ipv4_src':srcIP,'actions': {'allow': False}}}
   faucetYaml["acls"]["def_acl"] = [blockrule] + faucetYaml["acls"]["def_acl"]
   faucet_mng.faucet_yaml = faucetYaml
   faucet_mng.set_faucet_yaml(true)
   print("Block rule added sucessfully!")



faucet_mng = faucet_management()
faucetYaml = faucet_mng.get_faucet_yaml()
# dubuging
#print("Faucet Yaml before update\n")
#print(dump(faucetYaml,default_flow_style=False))
#test
#blockSrcIp('192.168.10.33/32')
#print("Faucet Yaml after UPdate\n")
#print(dump(faucetYaml,default_flow_style=False))
#faucet_mng.set_faucet_yaml()



logging.basicConfig(level=logging.DEBUG)
ep = netcontrol.Endpoint("bro/event/netcontrol-example", "127.0.0.1", 9977);

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
    blockSrcIp(response.rule["entity"]["ip"])
    print("END!")
