# Craftberry

## Compilation, Execution and Testing

### How to use

```bash
craftberry -A interface_src -B interface_dst { -a ATTACKNAME | -d DEFENSENAME }
```

### Details

```bash
 -A interface_src -B interface_dst -a [ ATTACK | DEFENSE ]

Options:
    -A            : Use the specified source interface. Can be interface name (e.g eth0) or interface IPv4 address
    -B            : Use the specified destination interface. Can be interface name (e.g eth0) or interface IPv4 address
    -a            : Use the specified action
    -t            : Use the specified timeout in seconds, if not defined it runs until some external signal stops the execution (e.g. ctrl+c)
    -l            : Write the output stream sent to the destination interface into a pcapng file having name passed by parameter or, if the parameter's equal to 'default', the name is 'out_<epoch_ms>'
    -i            : Print the list of interfaces and exists
    -h            : Displays this help message and exits

Actions:
   - default:
       BEQUITE    : just replying all the traffic from src to dst
   - ATTACK:
       DNS        : catch the DNS queries and replace its value
       HTTP       : description
       HTTPIMAGE  : description
       TCPMULTIPY : multiply N times every tcp packet to dst
       UDPMULTIPY : multiply N times every udp packet to dst
       ICMPMULTIPY: multiply N times every icmp packet to dst
   - DEFENSE:
       CHACHA20   : encrypt all the outgoing traffic and decrypt all the ingoing traffic
```

### How to compile

The application requires the pcapplusplus libs installed on the target system.
You can find the installation procedure [here](https://pcapplusplus.github.io/docs/install).

Use ```make``` to compile and produce the exec file.

### How to send fake traffic for testing

#### setup

Create two interfaces (if they don't exist) and get the two ip addresses.  
Run ```setup.sh``` as sudo.


##### send traffic in linux

```bash
sudo tcpreplay -i <interface> --loop=10 --loopdelay-ms=1000 <pcap_file>
```

### Roadmap

- [X] **PoC actions** (work in progress)
- [ ] PoC prevention systems
- [ ] Reputation systems integration
