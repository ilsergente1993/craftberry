#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
//#include <libmnl/libmnl.h>
#include <functional>
#include <getopt.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/types.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <thread>

#include "pcapplusplus/DnsLayer.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/IcmpLayer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PlatformSpecificUtils.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"

extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/pktbuff.h>
}

#include "Configuration.cpp"

#define ASSERT(x, m, f)        \
    do {                       \
        if ((x)) {             \
            cerr << m << endl; \
            f;                 \
        }                      \
    } while (false);

#define CHECK(x, m) \
    ASSERT(x, m, nullptr)

#define IPTABLES(proto, isdel)         \
    system(("\n#/bin/bash\n\n"s +      \
            "sudo iptables "s +        \
            (!isdel ? "-A"s : "-D"s) + \
            " INPUT -p "s +            \
            #proto +                   \
            " -j NFQUEUE"s)            \
               .c_str());

using namespace std;
using namespace pcpp;

//DOC: struct storaging the usage options for the CLI
const char *const CraftberryOptionsShort = "I:a:t:l:d:h";
static struct option CraftberryOptions[] =
    {{"tun0_interface", required_argument, 0, 'I'},
     {"action", required_argument, 0, 'a'},
     {"timeout", required_argument, 0, 't'},
     {"log", required_argument, 0, 'l'},
     {"direction", required_argument, 0, 'd'},
     {"help", no_argument, 0, 'h'},
     {0, 0, 0, 0}};

void ctrl_c(int);
void help();
void listInterfaces();
void printAllLayers(pcpp::Packet *p);
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
bool sendPkt(RawPacket *p, PcapLiveDevice *destination);
void sendPkt(vector<RawPacket *> *pToSend, PcapLiveDevice *destination);
void quitCraftberry();

//DOC: global vars
struct Configuration *conf = nullptr;
struct nfq_q_handle *queue = nullptr;
struct nfq_handle *handler = nullptr;

//DOC: handler function to manage external signals
void ctrl_c(int s) {
    if (conf == nullptr)
        exit(1);
    cerr << "\nOoooops got ctrl+c signal (" << s << ")\nHere a summary of what happened:";
    quitCraftberry();
    exit(1);
}
//DOC: all the ops to close the app
void quitCraftberry() {
    conf->summary();
    delete conf;
    //DOC: deleting the queue and freeing resources
    cout << "exiting from craftberry" << endl;
    nfq_destroy_queue(queue);
    nfq_close(handler);
    cout << "bye bye\n";
}
//DOC: just the main
int main(int argc, char *argv[]) {
    //DOC: setup for ctrl+c signal
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = ctrl_c;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    //DOC: reading cli parameters
    string interfaceTun0 = "";
    string action = "BEQUITE";
    string logName = "captures/out_" + to_string(time(0)) + ".pcapng";
    PacketDirection direction = Both;
    int optionIndex = 0, timeout = 0;
    char opt = 0;
    //':' => significa che si aspetta degli argomenti
    while ((opt = getopt_long(argc, argv, CraftberryOptionsShort, CraftberryOptions, &optionIndex)) != -1) {
        switch (opt) {
        case 0:
            break;
        case 'I':
            interfaceTun0 = optarg;
            break;
        case 'a':
            action = optarg;
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        case 'l':
            if (strcmp(optarg, "default") != 0)
                (logName = optarg) += ".pcapng";
            break;
        case 'd':
            if (strcmp(&optarg[0], "in") == 0)
                direction = InGoing;
            else if (strcmp(&optarg[0], "out") == 0)
                direction = OutGoing;
            else
                direction = Both;
            break;
        case 'h':
        default:
            help();
            exit(-1);
        }
    }

    if (action.length() <= 0) {
        cout << "Dude, let's do some action!" << endl;
        exit(1);
    }

    //DOC: setup of the configuration obj
    conf = new Configuration{action, "10.135.63.160" /*interfaceTun0*/, logName, direction};
    conf->toString();

    //DOC: setup the queue handling
    cout << "adding iptables rule" << endl;
    // IPTABLES("udp", false);

    int num_queue = 0;
    handler = nfq_open();
    ASSERT(handler == nullptr, "Can\'t open hfqueue handler.", exit(1));

    //cout << "unbinding existing nf_queue handler for AF_INET (if any)\n";
    ASSERT(nfq_unbind_pf(handler, AF_INET) < 0, "error during nfq_unbind_pf()\n", exit(1));
    //cout << "binding nfnetlink_queue as nf_queue handler for AF_INET\n";
    ASSERT(nfq_bind_pf(handler, AF_INET) < 0, "error during nfq_bind_pf()\n", exit(1));

    queue = nfq_create_queue(handler, num_queue, &callback, nullptr);
    ASSERT(queue == nullptr, "Can\'t create queue handler.", exit(1));
    ASSERT(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.", exit(1));
    int fd = nfq_fd(handler);
    std::array<char, 0x10000> buffer;

    //DOC: this is the main cycle where the read and the callback happen
    if (timeout > 0) {
        std::thread t([&timeout]() {
            std::this_thread::sleep_for(std::chrono::seconds(timeout));
            quitCraftberry();
            exit(0);
        });
        t.detach();
        cout << "Working in timeout mode: " << timeout << " seconds left." << endl;
    } else {
        cout << "Working in infinite mode, press ctrl+c to exit..." << endl;
    }
    while (true) {
        //DOC: I quit only when ctrl+c is pressed
        int len = read(fd, buffer.data(), buffer.size());
        CHECK(len < 0, "Issue while read");
        nfq_handle_packet(handler, buffer.data(), len);
    };
    // cout << "removing iptables rule" << endl;
    // IPTABLES("icmp", true);

    quitCraftberry();
    return 0;
};

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    //cout << "entering callback" << endl;

    //DOC: ottengo il payload del pacchetto
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    CHECK(ph == nullptr, "Issue while packet header");
    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(nfa, &rawData);
    CHECK(len < 0, "Can\'t get payload data");

    struct timeval timestamp;
    nfq_get_timestamp(nfa, &timestamp);

    //DOC: creo il pacchetto pcapPlusPlus dal payload restituito da nf_queue
    pcpp::RawPacket *inPacketRaw = new pcpp::RawPacket(static_cast<uint8_t *>(rawData), len, timestamp, false, pcpp::LINKTYPE_RAW);
    pcpp::Packet *inPacket = new pcpp::Packet(inPacketRaw);
    // pcpp::EthLayer *newEthernetLayer = new pcpp::EthLayer(pcpp::MacAddress("f0:4b:3a:4f:80:30"), pcpp::MacAddress("a2:ee:e9:dd:4c:14"));
    // inPacket->insertLayer(nullptr, newEthernetLayer, true);
    inPacket->computeCalculateFields();
    pcpp::IPv4Address ip("165.22.66.6");

    conf->received.bytes += inPacketRaw->getRawDataLen();
    conf->received.packets++;

    //DOC: scrorro i pacchetti per inspezione
    DEBUG("[#" << conf->received.packets << "] -> " << inPacket->getLastLayer()->toString() << endl);
    //printAllLayers(inPacket);

    /*//DOC: accetto tutto il traffico che non è diretto al mio IP
    if (!inPacket->getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress().equals(&ip)) {
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
    }*/

    vector<RawPacket *> *pToSend;
    if (conf->method.compare("BEQUITE") == 0) {
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
    }

    if (conf->method.compare("DNSROBBER") == 0 && DnsRobber::isDns(inPacket)) {
        DnsRobber action;
        //Packet *p;
        action.craftInGoing(inPacket);
        //ASSERT(, "DNSROBBER failed for some reason", exit(1));
        //return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
        //printAllLayers(p);

        pcpp::RawPacket *outPacketRaw = new pcpp::RawPacket();
        outPacketRaw->setRawData(inPacket->getRawPacket()->getRawData(), inPacket->getRawPacket()->getRawDataLen(), timestamp);
        pcpp::Packet *outPacket = new pcpp::Packet(outPacketRaw);

        CHECK(!sendPkt(outPacket->getRawPacket(), conf->devTun0), "packet not sent");
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_DROP, 0, NULL);
        //return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, len, (unsigned char *)rawData);
    }

    //TODO: per copia ed invio del pacchetto
    if (false) {
        //DOC: creo e riempio il secondo pacchetto
        pcpp::RawPacket *outPacketRaw = new pcpp::RawPacket();
        outPacketRaw->setRawData(inPacket->getRawPacket()->getRawData(), inPacket->getRawPacket()->getRawDataLen(), timestamp);
        pcpp::Packet *outPacket = new pcpp::Packet(outPacketRaw);

        cout << "OUT: " << outPacket->getLastLayer()->toString() << endl;
        printAllLayers(outPacket);

        //cout << " -- pacchetto copiato" << endl;
        CHECK(!sendPkt(outPacket->getRawPacket(), conf->devTun0), "packet not sent");
        CHECK(!sendPkt(outPacket->getRawPacket(), conf->devTun0), "packet not sent");
        CHECK(!sendPkt(outPacket->getRawPacket(), conf->devTun0), "packet not sent");

        DEBUG(" -- pacchetto inviato a (" << conf->devTun0->getName() << ") " << conf->devTun0->getIPv4Address().toString() << endl);
    }

    //DOC: invio il verdetto
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}

bool sendPkt(RawPacket *p, PcapLiveDevice *destination) {
    if (p->getRawDataLen() > destination->getMtu()) {
        conf->dropped.packets++;
        conf->dropped.bytes += p->getRawDataLen();
        return false;
    }
    if (destination->sendPacket(*p)) {
        conf->created.packets++;
        conf->created.bytes += p->getRawDataLen();
        conf->devLogFile->writePacket(*p);
        return true;
    }
    cout << "something strange did just happen" << endl;
    return false;
};

void sendPkt(vector<RawPacket *> *pToSend, PcapLiveDevice *destination) {
    int cont = 0;
    double size = 0;
    for (auto p : *pToSend) {
        if (!sendPkt(p, destination)) {
            cout << "1 packet skipped" << endl;
        } else {
            cont++;
            size += p->getRawDataLen();
        }
    }
    DEBUG(" └> " << cont << " packets (" << size << " B) to " << destination->getIPv4Address().toString() << endl);
};

void help() {
    cout << "\nUsage: Craftberry options:\n"
            "-------------------------\n"
            " -A interface_src -B interface_dst\n"
            "Options:\n"
            "    -A            : Use the specified source interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
            "    -B            : Use the specified destination interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
            "    -a            : Use the specified action\n"
            "    -t            : Use the specified timeout in seconds, if not defined it runs until some external signal stops the execution (e.g. ctrl+c)\n"
            "    -l            : Write the output stream sent to the destination interface into a pcapng file having name passed by parameter or, if the parameter's equal to 'default', the name is 'out_<epoch_ms>'\n"
            "    -i            : Print the list of interfaces and exists\n"
            "    -d            : Set the flow direction where to perform the action. Both direction is the default value.\n"
            "    -h            : Displays this help message and exits\n"
            "Actions:\n"
            "   - default:\n"
            "       BEQUITE    : just replying all the traffic from src to dst\n"
            "   - ATTACK:\n"
            "       DNS        : catch the DNS queries and replace its value\n"
            "       HTTP       : description\n"
            "       HTTPIMAGE  : description\n"
            "       TCPMULTIPY : multiply N times every tcp packet to dst\n"
            "       UDPMULTIPY : multiply N times every udp packet to dst\n"
            "       ICMPMULTIPY: multiply N times every icmp packet to dst\n"
            "   - DEFENSE:\n"
            "       CHACHA20   : encrypt all the outgoing traffic and decrypt all the ingoing traffic\n";
    exit(0);
}

void printAllLayers(pcpp::Packet *p) {
    pcpp::Layer *L = p->getFirstLayer();
    while (L != nullptr) {
        cout << "\t\tLEV: " << L->getOsiModelLayer() << " => " << L->toString() << endl;
        L = L->getNextLayer();
    }
}