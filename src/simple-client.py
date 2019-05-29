#!/usr/bin/env python3

import subprocess, os

from yaml import load, dump, YAMLError, safe_dump, dumper
import json
import logging
import netcontrol
import pprint

pp = pprint.PrettyPrinter(indent=5)


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
      if remote:
        proc = subprocess.Popen(["./gnmi_set_scr.sh"], stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        print ("gnmi_set_src output:", out)


  def get_match(self,nc_entity):
    match = {}
    nw_proto = None
    if nc_entity['ty'] == 'FLOW':
      nc_flow =  nc_entity['flow']
      if nc_flow['src_h'] is not None or nc_flow['dst_h'] is not None:
        match = {
                'dl_type': 0x800 
        }

      if nc_flow['src_h'] is not None:
        match['ipv4_src'] = nc_flow['src_h'].split('/')[0] 
      if nc_flow['dst_h'] is not None:
        match ['ipv4_dst'] = nc_flow['dst_h'].split('/')[0]         
  
      if nc_flow['src_p'] is not None and nc_flow['src_p'][1] == '/udp':
        match['udp_src']= int(nc_flow['src_p'][0]) 
        match['nw_proto']= 16
        nw_proto = 'udp'
        
      if nc_flow['dst_p'] is not None and nc_flow['dst_p'][1] == '/udp':
        match['udp_dst']= int(nc_flow['dst_p'][0])
        match['nw_proto']= 16
        nw_proto = 'udp'

      if nc_flow['src_p'] is not None and nc_flow['src_p'][1] == '/tcp':
        match['tcp_src']= int(nc_flow['src_p'][0]) 
        match['nw_proto']= 6
        nw_proto = 'tcp'
      if nc_flow['dst_p'] is not None and nc_flow['dst_p'][1] == '/tcp':
        match['tcp_dst']= int(nc_flow['dst_p'][0])
        match['nw_proto']= 6
        nw_proto = 'tcp'
      # mac
      if nc_flow['src_m'] is not None:
        match['eth_src'] = str(nc_flow['src_m'])
      if nc_flow['dst_m'] is not None:
        match['eth_dst'] = str(nc_flow['dst_m'])

    elif nc_entity['ty'] == 'CONNECTION':
      nc_conn = nc_entity['conn']
      if nc_conn['orig_h'] is not None:
        match = {
                'dl_type': 0x800 \
                ,'ipv4_src':nc_conn['orig_h'].split('/')[0] \
        }
      if nc_conn['resp_h'] is not None:
        match = {
                'dl_type': 0x800 \
                ,'ipv4_dst':nc_conn['resp_h'].split('/')[0] \
        }
      if  nc_conn['orig_p'] is not None and nc_conn['orig_p'][1] == '/udp':
        match['udp_dst']= int(nc_conn['resp_p'][0])
        #match['udp_src']= int(nc_conn['orig_p'][0]) 
        match['nw_proto']= 16
        nw_proto = 'udp'

      elif nc_conn['orig_p'] is not None and nc_conn['orig_p'][1] == '/tcp':
        match['tcp_dst']= int(nc_conn['resp_p'][0])
        #match['tcp_src']= int(nc_conn['origi_p'][0]) 
        match['nw_proto']= 6
        nw_proto = 'tcp'

    elif nc_entity['ty'] == 'ADDRESS':
      match = {
        'ipv4_src': nc_entity['ip'].split('/')[0]         
      }

    elif nc_entity['ty'] == 'MAC':
      match = {
        'eth_src': str(nc_entity['mac'])
      }

    return match, nw_proto


  def get_actions(self, nc_rule, nw_proto):
    actions ={}
    if nc_rule['target']=='FORWARD':
      # REDIRECT
      if  nc_rule['ty'] =='REDIRECT':
        actions = {
        'output': {
                  'port': int(nc_rule['out_port']) 
                  }
        }    
      # allow
      elif  nc_rule['ty'] =='WHITELIST':  
        actions = {'allow': True }
      # block
      elif  nc_rule['ty'] =='DROP':  
        actions = {'allow': False }

      # mod  
      elif nc_rule['ty'] == 'MODIFY':
        set_fields = []
        if nc_rule['mod']['dst_h'] is not None:
          set_fields.append({'ipv4_dst': nc_rule['mod']['dst_h'] })
        if nc_rule['mod']['src_h'] is not None:
          set_fields.append({'ipv4_src': nc_rule['mod']['src_h'] })

        if nc_rule['mod']['dst_p'] is not None:
          if nw_proto =='tcp':
            set_fields.append({'tcp_src': nc_rule['mod']['dst_p'] })
          elif nw_proto =='udp':
            set_fields.append({'udp_src': nc_rule['mod']['dst_p'] })
        if nc_rule['mod']['src_p'] is not None:
          if nw_proto == 'tcp':
            set_fields.append({'tcp_src': nc_rule['mod']['src_p'] })
          elif nw_proto == 'tcp':
            set_fields.append({'udp_src': nc_rule['mod']['src_p'] })

        actions = {
                'output': {
                  'set_fields': set_fields                  
                  }
        }    

        if nc_rule['mod']['redirect_port'] is not None:
          actions['output'] ['port']  = nc_rule['mod']['redirect_port']

          # 'mod': {    'dst_h': None,
          #        'dst_m': None,
          #        'dst_p': None,
          #        'redirect_port': None,
          #        'src_h': '8.8.8.8',
          #        'src_m': None,
          #        'src_p': None},


    elif nc_rule['target']=='MONITOR':
      #SHUNT
      if  nc_rule['ty'] =='DROP':  
        # we may do something other than drop
        actions = {'allow': False }


    return actions

  def create_rule(self, nc_rule):
    faucet_match, nw_proto = self.get_match(nc_rule['entity'])
    faucet_rule = {'rule':faucet_match}
    # build action
    faucet_rule['rule']['actions']= self.get_actions(nc_rule, nw_proto)
    return faucet_rule


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
    pp.pprint(response.rule)

    if response.rule['target'] == 'FORWARD' and \
      response.rule['ty'] in ['WHITELIST','REDIRECT','DROP','MODIFY']:
      
      new_rule  = faucet_mng.create_rule(response.rule)
      if new_rule is not None:
        pp.pprint(new_rule)
        #faucet_mng.add_rule(new_rule)
        ep.sendRuleAdded(response, "OK")
    #SHUNT
    elif response.rule['target'] == 'MONITOR' and \
      response.rule['ty'] =='DROP':      
      new_rule  = faucet_mng.create_rule(response.rule)
      if new_rule is not None:
        pp.pprint(new_rule)
        #faucet_mng.add_rule(new_rule)
        ep.sendRuleAdded(response, "OK")



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
