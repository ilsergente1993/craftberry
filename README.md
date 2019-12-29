### Compilation, Execution and Testing

#### How to use
```
craftberry -A interface_src -B interface_dst { -a ATTACKNAME | -d DEFENSENAME }
```

#### Details:
```
    -A interface src  : Use the specified source interface. Can be interface name (e.g eth0) or interface IPv4 address
    -B interface dst  : Use the specified destination interface. Can be interface name (e.g eth0) or interface IPv4 address
    -a                : Use the specified action
    -d                : Use the specified defence
    -t                : Use the specified timeout in seconds, if not defined it runs until some external signal stops the execution (e.g. ctrl+c)
    -l                : Print the list of interfaces and exists
    -h                : Displays this help message and exits

ATTACKNAME:
    BEQUITE        : just replying all the traffic from source to destination
    DNS            : catch the DNS queries and replace its value
    HTTP           : description
    HTTPIMAGE      : description
    TCPMULTIPY     : multiply N times every tcp packet to dst
    UDPMULTIPY     : multiply N times every udp packet to dst

DEFENSENAME:
    CHACHA20       : description
```

#### How to compile
```bash
make;
```


#### How to send fake traffic for testing
```bash
sudo tcpreplay -i <interface> --loop=10 --loopdelay-ms=1000 <pcap_file>
```


#### Roadmap
- [X] **PoC actions** (work in progress)
- [ ] PoC prevention systems
- [ ] Reputation systems integration