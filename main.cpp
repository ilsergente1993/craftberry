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

using namespace std;
using namespace pcpp;

//DOC: struct storaging the usage options for the CLI
const char *const CraftberryOptionsShort = "I:a:t:l:d:hv";
static struct option CraftberryOptions[] =
    {{"tun0_interface", required_argument, 0, 'I'},
     {"action", required_argument, 0, 'a'},
     {"timeout", required_argument, 0, 't'},
     {"log", required_argument, 0, 'l'},
     {"direction", required_argument, 0, 'd'},
     {"verbose", no_argument, 0, 'v'},
     {"help", no_argument, 0, 'h'},
     {0, 0, 0, 0}};

void ctrl_c(int);
void help();
void listInterfaces();
void printAllLayers(pcpp::Packet *p);
bool sendPkt(const uint8_t *packetData, int packetDataLength);
bool sendPkt(RawPacket *p);
void sendPkt(vector<RawPacket *> *pToSend);
void quitCraftberry();
void makeIptableCmd(bool);
int verdict_drop(struct nfq_q_handle *qh, u_int32_t id, Packet *p);
int verdict_accept(struct nfq_q_handle *qh, u_int32_t id, Packet *p);
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

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
    //DOC: deleting the queue and freeing resources
    nfq_destroy_queue(queue);
    nfq_close(handler);
    conf->summary();
    delete conf;
    makeIptableCmd(true);
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
    PacketDirection direction = InGoing;
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
        case 'v':
            verbose = true;
            break;
        case 'd':
            if (strcmp(&optarg[0], "IN") == 0)
                direction = InGoing;
            else if (strcmp(&optarg[0], "OUT") == 0)
                direction = OutGoing;
            else
                cout << "direction value not valid" << endl;
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
    makeIptableCmd(false);

    handler = nfq_open();
    ASSERT(handler == nullptr, "Can\'t open hfqueue handler.", exit(1));

    //cout << "unbinding existing nf_queue handler for AF_INET (if any)\n";
    ASSERT(nfq_unbind_pf(handler, AF_INET) < 0, "error during nfq_unbind_pf()\n", exit(1));
    //cout << "binding nfnetlink_queue as nf_queue handler for AF_INET\n";
    ASSERT(nfq_bind_pf(handler, AF_INET) < 0, "error during nfq_bind_pf()\n", exit(1));

    queue = nfq_create_queue(handler, static_cast<std::underlying_type<Direction>::type>(direction), &callback, nullptr);
    ASSERT(queue == nullptr, "Can\'t create queue handler.", exit(1));
    ASSERT(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.", exit(1));
    int fd = nfq_fd(handler);
    std::array<char, 0x10000> buffer;

    //DOC: this is the main cycle where the read and the callback happen
    if (timeout > 0) {
        //DOC: timeout thread
        std::thread t([&timeout]() {
            std::this_thread::sleep_for(std::chrono::seconds(timeout));
            quitCraftberry();
            exit(0);
        });
        t.detach();
        cout << "Working in timeout mode: " << timeout << " seconds left." << endl;
    } else {
        cout << "Working in infinity mode, press ctrl+c to exit..." << endl;
    }
    while (true) {
        //DOC: I quit only when ctrl+c is pressed
        int len = read(fd, buffer.data(), buffer.size());
        CHECK(len < 0, "Issue while read");
        nfq_handle_packet(handler, buffer.data(), len);
    };
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
    CHECK(len < 0, "Can't get payload data");

    struct timeval timestamp;
    nfq_get_timestamp(nfa, &timestamp);

    //DOC: creo il pacchetto pcapPlusPlus dal payload restituito da nf_queue
    pcpp::RawPacket *inPacketRaw = new pcpp::RawPacket(static_cast<uint8_t *>(rawData), len, timestamp, false, pcpp::LINKTYPE_RAW);
    pcpp::Packet *inPacket = new pcpp::Packet(inPacketRaw);
    // pcpp::EthLayer *newEthernetLayer = new pcpp::EthLayer(pcpp::MacAddress("f0:4b:3a:4f:80:30"), pcpp::MacAddress("a2:ee:e9:dd:4c:14"));
    // inPacket->insertLayer(nullptr, newEthernetLayer, true);
    inPacket->computeCalculateFields();

    conf->received.bytes += inPacketRaw->getRawDataLen();
    conf->received.packets++;

    //DOC: scrollo i pacchetti per inspezione
    DEBUG("[#" << conf->received.packets << "] -> " << inPacket->getLastLayer()->toString() << endl);
    if (verbose)
        printAllLayers(inPacket);

    if (conf->method.compare("BEQUITE") == 0) {
        return verdict_accept(qh, ntohl(ph->packet_id), inPacket);
    }

    if (conf->method.compare("ICMP") == 0 && Action::Icmp::isProto(inPacket)) {
        return verdict_accept(qh, ntohl(ph->packet_id), inPacket);
    }
    if (conf->method.compare("IPV4") == 0 && Action::Icmp::isProto(inPacket)) {
        if (!verbose)
            printAllLayers(inPacket);
        Action::IPv4 *ip = new Action::IPv4(1);
        ip->changeDst(inPacket);
        if (!verbose)
            printAllLayers(inPacket);
        return verdict_accept(qh, ntohl(ph->packet_id), inPacket);
    }

    if (conf->method.compare("HTTP") == 0 && Action::HTTP::isProto(inPacket)) {
        if (!verbose)
            printAllLayers(inPacket);
        Action::HTTP *c = new Action::HTTP();
        c->changeUrl(inPacket);
        return verdict_accept(qh, ntohl(ph->packet_id), inPacket);
    }
    if (conf->method.compare("HTTPBLOCK") == 0 && Action::HTTP::isProto(inPacket)) {
        cout << "packet blocked" << endl;
        if (!verbose)
            printAllLayers(inPacket);
        return verdict_drop(qh, ntohl(ph->packet_id), inPacket);
    }

    if (conf->method.compare("ICMPMULTIPLY") == 0 && Action::Icmp::isProto(inPacket)) {
        // pcpp::Packet *outPacket = new pcpp::Packet(*inPacket);
        // cout << "\tOUT: " << outPacket->getLastLayer()->toString() << endl;
        Action::Icmp *action = new Action::Icmp(2, 2);
        action->changeRequestData(inPacket);

        cout << "---" << endl;
        printAllLayers(inPacket);

        //cout << " -- pacchetto copiato" << endl;
        //CHECK(!sendPkt(outPacket->getRawPacket()), "packet not sent");
        //CHECK(!sendPkt(outPacket->getRawPacket()), "packet not sent");
        //CHECK(!sendPkt(outPacket->getRawPacket()), "packet not sent");

        return verdict_accept(qh, ntohl(ph->packet_id), inPacket);
    }

    if (conf->method.compare("DNSROBBER") == 0 && Action::Dns::isProto(inPacket)) {
        Action::Dns action;
        //Packet *p;
        action.changeRequest(inPacket);
        //ASSERT(, "DNSROBBER failed for some reason", exit(1));
        //return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
        //printAllLayers(p);

        pcpp::RawPacket *outPacketRaw = new pcpp::RawPacket();
        outPacketRaw->setRawData(inPacket->getRawPacket()->getRawData(), inPacket->getRawPacket()->getRawDataLen(), timestamp);
        pcpp::Packet *outPacket = new pcpp::Packet(outPacketRaw);

        CHECK(!sendPkt(outPacket->getRawPacket()), "packet not sent");
        //return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_DROP, 0, NULL);
        return verdict_accept(qh, ntohl(ph->packet_id), outPacket);
    }
    //CHECK(!sendPkt(outPacket->getRawPacket()), "packet not sent");

    //DOC: invio il verdetto
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}
