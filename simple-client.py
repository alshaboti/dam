#!/usr/bin/env python

import os
from yaml import load, dump, YAMLError, safe_dump, dumper
import json
import logging
import netcontrol
import pprint
import paramiko 
from scp import SCPClient

pp = pprint.PrettyPrinter(indent=5)

def createSSHClient(server, port, user, password):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(server, port, user, password)
    return client


def is_rule_exist(rule, acl_list):

  dump1 = json.dumps(rule, sort_keys=True)
  for r in acl_list:    
    dump2 = json.dumps(r, sort_keys=True)    
    if dump1 == dump2:
      return True
  return False
  
# def update_rule_allow(rule, acl_list):
#   # same rule but different action allow/deny  
#   dump1 = json.dumps(rule, sort_keys=True)
#   action1_allow = rule['rule']['actions']['allow']
#   for r in acl_list:    
#     if r['rule']['actions']['allow'] == action1_allow:
#         continue
#     # just to ease comparison, instead of delete actions
#     r['rule']['actions']['allow'] = action1_allow
#     dump2 = json.dumps(r, sort_keys=True)    
#     if dump1 == dump2:
#       return True
#   return False


class faucet_management:
  faucet_yaml = {}

  def __init__(self):
    self.remote_faucet_host = "192.168.100.3"
    self.remote_faucet_file = "/etc/faucet/faucet.yaml"
    self.local_faucet_file = "./faucet.yaml"
    self.local_default_faucet_file = "./faucet.yaml.def"
    self.get_faucet_yaml(remote=True)

  # get faucet yaml file using ssh client 
  def get_faucet_yaml(self, remote = False):
      if remote:
        ssh = createSSHClient(self.remote_faucet_host, 22, "root", "changeme")
        scp = SCPClient(ssh.get_transport())
        scp.get(self.remote_faucet_file,self.local_faucet_file)

      with open(self.local_default_faucet_file, 'r') as file_stream:
        try:
          self.faucet_yaml =  load(file_stream)
        except YAMLError as exc:
          print(exc)

  # write faucet yaml file and restart fuacet using ssh
  def set_faucet_yaml(self, remote=False):
      # dump to local file
      noalias_dumper = dumper.Dumper
      noalias_dumper.ignore_aliases = lambda self, data: True
      with open(self.local_faucet_file, "w") as fd:
          dump(self.faucet_yaml, fd, default_flow_style=False, Dumper=noalias_dumper)
      # it works as long as you set ssh key between the two hosts
      # scp faucet.yaml to remote faucet
      if remote:
        ssh = createSSHClient("192.168.100.3", 22, "root", "changeme")
        scp = SCPClient(ssh.get_transport())
        scp.put(self.local_faucet_file,self.remote_faucet_file)
        stdin, stdout, stderr = ssh.exec_command("pkill -HUP ryu-manager")        
        print (stdout.read())
        # os.system("scp "+ self.local_faucet_file +" "+ self.remote_faucet_host+":"+self.remote_faucet_file)
        # #reload faucet.yaml docker 
        # os.system("ssh "+ self.remote_faucet_host + " docker kill --signal=HUP faucet_faucet_1" )


  def create_rule(self, con ):
    proto_type = 6
    allow = False
    if con['resp_p'][1] =='/udp':
      proto_type = 16
    if response.rule['ty'] == 'WHITELIST':
      allow = True
    new_rule = {'rule':{'dl_type': 0x800 \
                        ,'ipv4_src':con['orig_h'] \
                        ,'ipv4_dst':con['resp_h'] \
                        ,'nw_proto': proto_type \
                        ,'tcp_dst': int(con['resp_p'][0]) \
                        ,'actions': {'allow': allow}}}
    return new_rule

  def add_rule(self, new_rule):    


    #update_rule_allow(new_rule, self.faucet_yaml["acls"]["def_acl"])
    
    if not is_rule_exist(new_rule, self.faucet_yaml["acls"]["def_acl"]):
      self.faucet_yaml["acls"]["def_acl"] = [new_rule] + self.faucet_yaml["acls"]["def_acl"]    
      self.set_faucet_yaml(remote=True)
      print("Rule added sucessfully!")
    else: 
      print("rule already exists!")


faucet_mng = faucet_management()

logging.basicConfig(level=logging.DEBUG)
ep = netcontrol.Endpoint("bro/event/netcontrol-faucet", "127.0.0.1", 9977)

while 1==1:
    response = ep.getNextCommand()
    print("### Response.type is : ",response.type)

 
    #pp.pprint(response.rule)
    if response.type == netcontrol.ResponseType.AddRule:
        new_rule  = faucet_mng.create_rule(response.rule["entity"]["conn"])
        faucet_mng.add_rule(new_rule)
        ep.sendRuleAdded(response, "OK")

    elif response.type == netcontrol.ResponseType.RemoveRule:
        new_rule  = faucet_mng.create_rule(response.rule["entity"]["conn"])
        faucet_mng.add_rule(new_rule)
        ep.sendRuleRemoved(response, "OK")
       
    else:
        print("responsee.type isn't add or remove rule: ", response.type)
        continue

    print("Rule type: ", response.rule['ty'])
    print("entity: ", response.rule["entity"])
    
