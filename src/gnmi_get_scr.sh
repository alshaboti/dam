#!/bin/bash

string_val() { grep string_val: | awk -F 'string_val: "' '{printf $2;}'  |
               sed -e 's/"$//' | xargs -0 printf; }

# Fetch information about configuration schema
#gnmi_capabilities $AUTH

# Fetch current configuration
gnmi_get $AUTH -xpath=/ | string_val > ../etc/faucet/faucet.zeek.yaml