import os
import re
import paramiko

from yaml import load, dump, YAMLError
import json
#not used anymore, I used ssh key between the devices, such that 
# I don't need to provide username password

class faucet_management:
  faucet_yaml = {}

  def __init__(self):
    self.remote_faucet_host = "root@192.168.3.100"
    self.remote_faucet_file = "/etc/faucet/faucet.yaml"
    self.local_faucet_file = "./faucet.yaml"

  # get faucet yaml file using ssh client 
  def get_faucet_yaml(self):
     cmd = "scp " + self.remote_faucet_host + ":" + self.remote_faucet_file \
                 + " " + self.local_faucet_file
     os.system(cmd)

     with open('faucet.yaml', 'r') as file_stream:
       try:
         faucet_conf =  load(file_stream)
       except YAMLError as exc:
          print(exc)

     self.faucet_yaml = faucet_conf
     return self.faucet_yaml

  # write faucet yaml file and restart fuacet using ssh
  def set_faucet_yaml(self)
      # dump to local file
      with open("faucet.yaml", "w") as fd:
          dump(self.faucet_yaml, fd, default_flow_style=False)
      # it works as long as you set ssh key between the two hosts
      # scp faucet.yaml to remote faucet
      os.system("scp "+ self.local_faucet_file +" "+ self.remote_faucet_host+":"+self.remote_faucet_file)
      # reload faucet.yaml docker 
      os.system("ssh "+ self.remote_faucet_host + " docker kill --signal=HUP faucet_faucet_1" )


