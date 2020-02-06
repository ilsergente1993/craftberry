# Craftberry

## Compilation, Execution and Testing

### How to use

```bash
craftberry -I tun0_interface -a [ ATTACK | DEFENSE ]

Options:
    -I            : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address
    -a            : Use the specified action
    -t            : Use the specified timeout in seconds, if not defined it runs until some external signals stop the execution (e.g. ctrl+c)
    -l            : Write all the crafted and generated traffic into a pcapng file having name passed by parameter or, if the parameter\'s equal to \'default\', the name is `out_<epoch_ms>.pcapng`
    -d            : Direction filtering by and perform the crafting {IN, OUT}, default = IN
    -v            : Shows verbose debug application logs
    -h            : Displays this help message and exits

Actions:
Each action provide an in-going-traffic (IN) and an out-going-traffic (OUT) craft methods based on the attack direction
   - default:
       BEQUITE    : just sniffing all the traffic
   - ATTACK:
       DNS        : catch the DNS queries and replace the (IN) query\'s value or the (OUT) answer value
       HTTP       : description
       HTTPIMAGE  : description
       TCPMULTIPY : multiply N times every tcp packet to dst (IN, OUT)
       UDPMULTIPY : multiply N times every udp packet to dst (IN, OUT)
       ICMPMULTIPY: multiply N times every icmp packet to dst (IN, OUT)
   - DEFENSE:
       CHACHA20   : encrypt all the outgoing traffic (OUT) or decrypt all the ingoing traffic (IN)
```

### How to compile

The application requires the pcapplusplus libs and libnetfilter-queue-dev installed on the target system.
You can find the installation procedure [here](https://pcapplusplus.github.io/docs/install) and [here](https://www.howtoinstall.co/it/ubuntu/trusty/libnetfilter-queue-dev)

Use ```make``` to compile and produce the executable file.

### How to send fake traffic for testing

##### send traffic in linux

```bash
sudo tcpreplay -i <interface> --loop=10 --loopdelay-ms=1000 <pcap_file>
```

### Roadmap

- [X] **PoC actions** (work in progress)
- [ ] PoC prevention systems
    - [ ] Reputation systems integration
