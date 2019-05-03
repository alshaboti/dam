# #!/usr/bin/env python

import docker
client = docker.from_env()
# run alpine container 
# print client.containers.run("alpine", ["echo", "hello", "world"])
# send -HUP singal to proccessName inside containerNme/ID
container = client.containers.get('faucet')
container.exec_run("pkill -HUP ryu-manager")


# import os
# from yaml import load, dump, YAMLError, safe_dump, dumper
# import json
# import logging
# # pip install paramiko scp
# import paramiko 
# from scp import SCPClient
# import os
# from yaml import load, dump, YAMLError, safe_dump, dumper
# import json
# import logging
# import pprint
# import paramiko 
# from scp import SCPClient

# def createSSHClient(server, port, user, password):
#     client = paramiko.SSHClient()
#     client.load_system_host_keys()
#     client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     client.connect(server, port, user, password)
#     return client

# # ssh = createSSHClient("192.168.100.3", 22, "root", "changeme")
# # scp = SCPClient(ssh.get_transport())
# #scp.put("./faucet.yaml","/etc/faucet/faucety.yaml")
# # scp.get("/etc/faucet/faucet.yaml","./faucet/faucetyskjs.yaml")

# #stdin, stdout, stderr = ssh.exec_command("kill --signal=HUP faucet")
# #print (stdout.read())

# #!/usr/bin/env python


# def create_rule( ):
#     proto_type = 6
#     allow = False
#     new_rule = {'rule':{'dl_type': 2048 \
#                         ,'ipv4_src':"192.168.0.2" \
#                         ,'ipv4_dst':"192.168.0.1" \
#                         ,'nw_proto': 6 \
#                         ,'tcp_dst': 8000 \
#                         ,'actions': {'allow': allow}}}
#     return new_rule

# def is_rule_exist(rule, acl_list):

#   dump1 = json.dumps(rule, sort_keys=True)
#   for r in acl_list:    
#     dump2 = json.dumps(r, sort_keys=True) 
#     if dump1 == dump2:
#       return True
#   return False
  
# def is_opposed_rule_exist(rule, acl_list):
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

# faucet_yaml={}
# with open("faucet/faucet.yaml", 'r') as file_stream:
#     try:
#         faucet_yaml =  load(file_stream)
#     except YAMLError as exc:
#         print(exc)
# r = create_rule()

# if is_rule_exist(r,faucet_yaml["acls"]["def_acl"]):
#     print("rule exist")
# if is_opposed_rule_exist(r,faucet_yaml["acls"]["def_acl"]):
#     print("rule opposed is exist")
    