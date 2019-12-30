#!/bin/bash

echo "this setup is for WSL2 on Win10"\
     "it setups the dummy0 interface with a custom ip address, brings it up and gets the eth0 ip"\
     "the two ip addresses can be used as Source and Destination for Craftberry"

ip addr add 192.168.1.42/24 dev dummy0
ip link set dummy0 up
ip addr show | grep -o "inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*"