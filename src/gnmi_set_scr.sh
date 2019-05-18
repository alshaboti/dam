#!/bin/bash
gnmi_set $AUTH -replace=/:"$(<../etc/faucet/faucet.yaml)"
