#!/bin/bash
gnmi_set $AUTH -replace=/:"$(<../etc/faucet/faucet.zeek.yaml)"
