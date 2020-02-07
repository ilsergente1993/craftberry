#pragma once

#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PlatformSpecificUtils.h"
#include "pcapplusplus/TcpLayer.h"
#include <ctime>
#include <getopt.h>
#include <iostream>
#include <stdlib.h>

#include "Cypher.cpp"
#include "Dns.cpp"
#include "Http.cpp"
#include "Icmp.cpp"
#include "Ipv4.cpp"
#include "Tcp.cpp"
#include "Udp.cpp"

#define DEBUG(x)                \
    do {                        \
        std::cerr << "\t" << x; \
    } while (0);

#define ASSERT(x, m, f)        \
    do {                       \
        if ((x)) {             \
            cerr << m << endl; \
            f;                 \
        }                      \
    } while (false);

#define CHECK(x, m) \
    ASSERT(x, m, nullptr)

using namespace std;
using namespace pcpp;

//DOC: global vars
struct Configuration *conf = nullptr;
struct nfq_q_handle *queue = nullptr;
struct nfq_handle *handler = nullptr;
bool verbose = false;

enum PacketDirection { InGoing = 0,
                       OutGoing = 1 };

struct Traffic {
    double bytes = 0;
    double packets = 0;
};

struct Configuration {
public:
    struct Traffic received;
    struct Traffic crafted;
    struct Traffic created;
    struct Traffic dropped;

    string method;
    string tun0Address;
    PcapLiveDevice *devTun0;
    PcapNgFileWriterDevice *devLogFile;
    PacketDirection direction;
    void *data;

    Configuration(string _method, string _tun0Address, string _devLogFilename, PacketDirection _direction) : data(0) {
        method = _method;
        received = {0, 0};
        crafted = {0, 0};
        created = {0, 0};
        dropped = {0, 0};

        devTun0 = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp((tun0Address = _tun0Address).c_str());
        devLogFile = new PcapNgFileWriterDevice(_devLogFilename.c_str());
        direction = _direction;
        //DOC: getting the device
        if (devTun0 == NULL) {
            cout << "Cannot find interface with IPv4 address of '" << tun0Address << "'\n";
            exit(1);
        }
        //DOC: opening the device
        if (!devTun0->open()) {
            cout << "Cannot open the devices" << endl;
            exit(1);
        }
        //DOC: opening the out file stream
        if (!devLogFile->open()) {
            printf("Cannot open the out file stream for writing\n");
            exit(1);
        }
    };
    ~Configuration() {
        if (!devTun0->open()) {
            cout << "Cannot close what is not opened" << endl;
        }
        devTun0->stopCapture();
        devLogFile->close();
        //devInt->close();
        // devExt->close();
        //free(devInt);
        // free(devExt);
        // free(data);
        //delete devInt;
        // delete devExt;
        // delete data;
        //delete devExtFile;
        cout << "All is clean" << endl;
    }

    void toString() {
        cout << "0---------------------------------------------------------0" << endl;
        cout << "\tMethod:                " << method << endl;
        cout << "\tLogfile:               " << devLogFile->getFileName() << endl;
        cout << "\tDirection:             " << (direction == InGoing ? "IN" : "OUT") << endl;
        //cout << "\tAddress Data:          " << data << endl;
        if (!devTun0->open()) {
            cout << "devTun0 is not opened" << endl;
            return;
        }
        cout << "Interface tun0 info:" << endl;
        cout << "\tIP:                    " << devTun0->getIPv4Address().toString() << endl;
        cout << "\tInterface name:        " << devTun0->getName() << endl;
        cout << "\tInterface description: " << devTun0->getDesc() << endl;
        cout << "\tMAC address:           " << devTun0->getMacAddress().toString() << endl;
        cout << "\tDefault gateway:       " << devTun0->getDefaultGateway().toString() << endl;
        cout << "\tInterface MTU:         " << devTun0->getMtu() << endl;
        if (devTun0->getDnsServers().size() > 0)
            cout << "\tDNS server:            " << devTun0->getDnsServers().at(0).toString() << endl;
        else
            cout << "\tDNS Servers:           0" << endl;
    }

    void summary() {
        cerr << endl
             << "   Packets received:      " << received.packets << " (" << received.bytes << " bytes)" << endl
             << "   Packets crafted:       " << crafted.packets << " (" << crafted.bytes << " bytes)" << endl
             << "   Packets created:       " << created.packets << " (" << created.bytes << " bytes)" << endl
             << "   Packets dropped:       " << dropped.packets << " (" << dropped.bytes << " bytes)" << endl;
        /*pcap_stat stats;
        devLogFile->getStatistics(stats);
        cerr << "in file: received:" << stats.ps_recv << ", "
             << "dropped:" << stats.ps_drop << endl;*/
    };
};

void help() {
    cout << "\nUsage: Craftberry options:\n"
            "-------------------------\n"
            "craftberry -I tun0_interface -a [ ATTACK | DEFENSE ]\n"
            "Options:\n"
            "    -I            : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
            "    -a            : Use the specified action\n"
            "    -t            : Use the specified timeout in seconds, if not defined it runs until some external signal stops the execution (e.g. ctrl+c)\n"
            "    -l            : Write all the crafted and generated traffic into a pcapng file having name passed by parameter or, if the parameter\'s equal to \'default\', the name is `out_<epoch_ms>.pcapng`\n"
            "    -d            : Direction filtering by and perform the crafting {IN, OUT}, default = IN\n"
            "    -v            : Shows verbose debug application logs\n"
            "    -h            : Displays this help message and exits\n"
            "Actions:\n"
            "   - default:\n"
            "       BEQUITE    : just sniffing all the traffic\n"
            "   - ATTACK:\n"
            "       DNS        : catch the DNS packets and replace (IN) the query\'s value or (OUT) the answer value\n"
            "       HTTP       : TODO\n"
            "       TCPMULTIPY : multiply N times every tcp packet to dst (IN, OUT)\n"
            "       UDPMULTIPY : multiply N times every udp packet to dst (IN, OUT)\n"
            "       ICMPMULTIPY: multiply N times every icmp packet to dst (IN, OUT)\n"
            "   - DEFENSE:\n"
            "       CHACHA20   : encrypt all the outgoing traffic (OUT) or decrypt all the ingoing traffic (IN)\n";
    exit(0);
}

bool sendPkt(const uint8_t *packetData, int packetDataLength) {
    if (packetDataLength > conf->devTun0->getMtu()) {
        conf->dropped.packets++;
        conf->dropped.bytes += packetDataLength;
        return false;
    }
    if (conf->devTun0->sendPacket(packetData, packetDataLength)) {
        conf->created.packets++;
        conf->created.bytes += packetDataLength;
        //conf->devLogFile->writePacket(*p); //TODO:
        return true;
    }
    cout << "something strange did just happen" << endl;
    return false;
};

bool sendPkt(RawPacket *p) {
    if (p->getRawDataLen() > conf->devTun0->getMtu()) {
        conf->dropped.packets++;
        conf->dropped.bytes += p->getRawDataLen();
        return false;
    }
    if (conf->devTun0->sendPacket(*p)) {
        conf->created.packets++;
        conf->created.bytes += p->getRawDataLen();
        conf->devLogFile->writePacket(*p);
        return true;
    }
    cout << "something strange did just happen" << endl;
    return false;
};

void sendPkt(vector<RawPacket *> *pToSend) {
    int cont = 0;
    double size = 0;
    for (auto p : *pToSend) {
        if (!sendPkt(p)) {
            cout << "1 packet skipped" << endl;
        } else {
            cont++;
            size += p->getRawDataLen();
        }
    }
    DEBUG(" └> " << cont << " packets (" << size << " B) to " << conf->devTun0->getIPv4Address().toString() << endl);
};

void printAllLayers(pcpp::Packet *p) {
    pcpp::Layer *L = p->getFirstLayer();
    while (L != nullptr) {
        cout << "\t\t| LEV: " << L->getOsiModelLayer() << " => " << L->toString() << endl;
        L = L->getNextLayer();
    }
}

int verdict_drop(struct nfq_q_handle *qh, u_int32_t id, Packet *p) {
    conf->dropped.packets++;
    conf->dropped.bytes += p->getRawPacket()->getRawDataLen();
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}
int verdict_accept(struct nfq_q_handle *qh, u_int32_t id, Packet *p) {
    conf->crafted.packets++;
    conf->crafted.bytes += p->getRawPacket()->getRawDataLen();
    p->computeCalculateFields();
    return nfq_set_verdict(qh, id, NF_ACCEPT, p->getRawPacket()->getRawDataLen(), p->getRawPacket()->getRawData());
}

void makeIptableCmd(bool isDeleting) {
    string protocol = "";
    if (conf->method.compare("BEQUITE") == 0) {
        protocol = "all";
    } else if (conf->method.compare("DNSROBBER") == 0) {
        protocol = "udp port 53";
    } else if (conf->method.compare("ICMP") == 0 || conf->method.compare("ICMPMULTIPLY") == 0 || conf->method.compare("IPV4") == 0) {
        protocol = "icmp";
    } else if (conf->method.compare("UDPMULTIPLY") == 0) {
        protocol = "udp";
    } else if (conf->method.compare("TCPMULTIPLY") == 0 || conf->method.compare("IPV4") == 0) {
        protocol = "tcp";
    } else if (conf->method.compare("HTTP") == 0 || conf->method.compare("HTTPBLOCK") == 0) {
        protocol = "tcp -m multiport --dports 80,443";
    }
    string dir = std::to_string(static_cast<std::underlying_type<Direction>::type>(conf->direction));
    string cmd = ("sudo iptables -t filter "s +
                  (!isDeleting ? "-I "s : "-D "s) +
                  (conf->direction == 0 ? "INPUT "s : "OUTPUT "s) +
                  "-p "s + protocol + " -j NFQUEUE "s +
                  " --queue-num "s + dir);
    cout << "IPTABLE RULE: " << endl
         << "\t$: " << cmd << endl;
    system(("\n#/bin/bash\n\n"s + cmd).c_str());
};