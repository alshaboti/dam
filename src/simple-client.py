#!/usr/bin/env python3

import subprocess, os

from yaml import load, dump, YAMLError, safe_dump, dumper
import json
import logging
import netcontrol
import pprint
#import paramiko 
#from scp import SCPClient

pp = pprint.PrettyPrinter(indent=5)

# def createSSHClient(server, port, user, password):
#     client = paramiko.SSHClient()
#     client.load_system_host_keys()
#     client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     client.connect(server, port, user, password)
#     return client


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
    self.local_faucet_file = "../etc/faucet/faucet.zeek.yaml"    
    self.get_faucet_yaml(remote=True)

  # get faucet yaml file using ssh client 
  def get_faucet_yaml(self, remote = False):
      
      if remote:
        subprocess.call("./gnmi_get_scr.sh", shell=True)
        #os.system("/bin/bash ./gnmi_get_src.sh")

      #   ssh = createSSHClient(self.remote_faucet_host, 22, "root", "changeme")
      #   scp = SCPClient(ssh.get_transport())
      #   scp.get(self.remote_faucet_file,self.local_faucet_file)

      with open(self.local_faucet_file, 'r') as file_stream:
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
        proc = subprocess.Popen(["./gnmi_set_scr.sh"], stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        print ("gnmi_set_src output:", out)
      #   ssh = createSSHClient("192.168.100.3", 22, "root", "changeme")
      #   scp = SCPClient(ssh.get_transport())
      #   scp.put(self.local_faucet_file,self.remote_faucet_file)
      #   stdin, stdout, stderr = ssh.exec_command("pkill -HUP ryu-manager")        
      #   print (stdout.read())
        # os.system("scp "+ self.local_faucet_file +" "+ self.remote_faucet_host+":"+self.remote_faucet_file)
        # #reload faucet.yaml docker 
        # os.system("ssh "+ self.remote_faucet_host + " docker kill --signal=HUP faucet_faucet_1" )

  def get_match(self,nc_entity):
    if nc_entity['ty'] == 'FLOW':
      nc_flow =  nc_entity['flow']
      match = {
              'dl_type': 0x800 \
              ,'ipv4_src':nc_flow['src_h'].split('/')[0] \
              ,'ipv4_dst':nc_flow['dst_h'].split('/')[0] \
      }

      if nc_flow['src_p'][1] == '/udp':
        match['udp_dst']= int(nc_flow['dst_p'][0])
        match['udp_src']= int(nc_flow['src_p'][0]) 
        match['nw_proto']= 16
      elif nc_flow['src_p'][1] == '/tcp':
        match['tcp_dst']= int(nc_flow['dst_p'][0])
        match['tcp_src']= int(nc_flow['src_p'][0]) 
        match['nw_proto']= 6
      if nc_flow['dst_m'] is not None:
        match['eth_src'] = nc_flow['src_m']
        match['eth_dst'] = nc_flow['dst_m']
      return match
    return {}
      


  def create_redirect_rule(self, nc_rule):
    faucet_match = self.get_match(nc_rule['entity'])
    faucet_rule = {'rule':faucet_match}
    # build action
    faucet_rule['rule']['actions']={
      'output': {
        'port': int(nc_rule['out_port']) 
        }
        }
    return faucet_rule

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
    if not (response.type == netcontrol.ResponseType.AddRule or \
       response.type == netcontrol.ResponseType.RemoveRule) :        
       # ConnectionEstablished = 1, Error = 2, AddRule = 3, RemoveRule = 4, SelfEvent = 5
       # response.type >>  https://github.com/zeek/zeek-netcontrol/blob/master/netcontrol/api.py#L91
        continue


    if response.rule['ty'] == 'WHITELIST':
      print (" Rule type: WHITELIST")
    elif response.rule['ty'] == 'REDIRECT':
      print ("Rule type: REDIRECT")
      if response.rule['target'] == 'FORWARD':
        new_rule  = faucet_mng.create_redirect_rule(response.rule)
        pp.pprint(new_rule)
        faucet_mng.add_rule(new_rule)
        ep.sendRuleAdded(response, "OK")


    elif response.rule['ty'] == 'DROP':
      print ("Rule type: REDIRECT")
    elif response.rule['ty'] == 'MODIFY':
      print ("Rule type: MODIFY")
  
    pp.pprint(response.rule)

    # if response.type == netcontrol.ResponseType.AddRule:
    #     new_rule  = faucet_mng.create_rule(response.rule["entity"]["conn"])
    #     faucet_mng.add_rule(new_rule)
    #     ep.sendRuleAdded(response, "OK")

    # elif response.type == netcontrol.ResponseType.RemoveRule:
    #     new_rule  = faucet_mng.create_rule(response.rule["entity"]["conn"])
    #     faucet_mng.add_rule(new_rule)
    #     ep.sendRuleRemoved(response, "OK")

# 	NetControl::redirect_flow([$src_h=192.168.17.1, $src_p=32/tcp, 
#                              $dst_h=192.168.17.2, $dst_p=32/tcp], 5, 30sec);
# keys are entity, target, and type
# https://docs.zeek.org/en/stable/frameworks/netcontrol.html#rule-api  
# {   'cid': 5L,
#     'entity': {   'conn': None,
#                   'flow': {   'dst_h': '192.168.17.2/32',
#                               'dst_m': None,
#                               'dst_p': ('32', '/tcp'),
#                               'src_h': '192.168.17.1/32',
#                               'src_m': None,
#                               'src_p': ('32', '/tcp')},
#                   'ip': None,
#                   'mac': None,
#                   'ty': u'FLOW'},
#     'expire': datetime.timedelta(0, 30),
#     'id': u'5',
#     'location': u'',
#     'mod': None,
#     'out_port': 5L,
#     'priority': 0L,
#     'target': u'FORWARD',
#     'ty': u'REDIRECT'}
