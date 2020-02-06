#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
//#include <libmnl/libmnl.h>
#include <functional>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/types.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

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

void printAllLayers(pcpp::Packet *p) {
    pcpp::Layer *L = p->getFirstLayer();
    while (L != nullptr) {
        cout << "\tLEV: " << L->getOsiModelLayer() << " => " << L->toString() << endl;
        L = L->getNextLayer();
    }
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    cout << "entering callback" << endl;

    //DOC: ottengo il payload del pacchetto
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    CHECK(ph == nullptr, "Issue while packet header");
    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(nfa, &rawData);
    CHECK(len < 0, "Can\'t get payload data");
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
    struct timeval timestamp;
    nfq_get_timestamp(nfa, &timestamp);

    //DOC: creo il pacchetto pcapPlusPlus
    pcpp::RawPacket *inPacketRaw = new pcpp::RawPacket(static_cast<uint8_t *>(rawData), len, timestamp, false, pcpp::LINKTYPE_RAW);

    pcpp::Packet *inPacket = new pcpp::Packet(inPacketRaw);
    pcpp::EthLayer *newEthernetLayer = new pcpp::EthLayer(pcpp::MacAddress("f0:4b:3a:4f:80:30"), pcpp::MacAddress("a2:ee:e9:dd:4c:14"));
    inPacket->insertLayer(nullptr, newEthernetLayer, true);
    inPacket->computeCalculateFields();
    pcpp::IPv4Address ip("165.22.66.6");
    //DOC: accetto tutto il traffico che non è diretto al mio IP
    if (!inPacket->getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress().equals(&ip)) {
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
    }

    //DOC: scrorro i pacchetti per inspezione
    cout << "IN:  " << inPacket->getLastLayer()->toString() << endl;
    //printAllLayers(inPacket);

    //DOC: creo e riempio il secondo pacchetto
    pcpp::RawPacket *outPacketRaw = new pcpp::RawPacket();
    outPacketRaw->setRawData(inPacket->getRawPacket()->getRawData(), inPacket->getRawPacket()->getRawDataLen(), timestamp);
    pcpp::Packet *outPacket = new pcpp::Packet(outPacketRaw);

    cout << "OUT: " << outPacket->getLastLayer()->toString() << endl;
    //printAllLayers(outPacket);

    cout << " -- pacchetto copiato" << endl;

    //DOC: apro il dispositivo di destinazione
    //TODO: deve essere della tun0 e non dell'interfaccia pubblica. per test metto eth1
    string dstAddr = "10.135.63.160";
    pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(dstAddr.c_str());
    ASSERT(dev == nullptr, "Cannot find interface with IPv4 address of "s + dstAddr, exit(1));
    ASSERT(!dev->open(), "Cannot open device", exit(1));

    CHECK(!dev->pcpp::PcapLiveDevice::sendPacket(*outPacket->getRawPacket()), "packet not sent");
    CHECK(!dev->pcpp::PcapLiveDevice::sendPacket(*outPacket->getRawPacket()), "packet not sent");
    CHECK(!dev->pcpp::PcapLiveDevice::sendPacket(*outPacket->getRawPacket()), "packet not sent");
    dev->close();
    cout << " -- pacchetto inviato a (" << dev->getName() << ") " << dev->getIPv4Address().toString() << endl;

    //DOC: invio il verdetto
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}

int main(/*int argc, char **argv*/) {
    // cout << "adding iptables rule" << endl;
    // IPTABLES("udp", false);
    int num_queue = 0;
    struct nfq_handle *handler = nfq_open();
    ASSERT(handler == nullptr, "Can\'t open hfqueue handler.", exit(1));

    // cout << "unbinding existing nf_queue handler for AF_INET (if any)\n";
    // ASSERT(nfq_unbind_pf(handler, AF_INET) < 0, "error during nfq_unbind_pf()\n", exit(1));
    // cout << "binding nfnetlink_queue as nf_queue handler for AF_INET\n";
    // ASSERT(nfq_bind_pf(handler, AF_INET) < 0, "error during nfq_bind_pf()\n", exit(1));

    struct nfq_q_handle *queue = nfq_create_queue(handler, num_queue, &callback, nullptr);
    ASSERT(queue == nullptr, "Can\'t create queue handler.", exit(1));
    ASSERT(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.", exit(1));
    int fd = nfq_fd(handler);
    std::array<char, 0x10000> buffer;
    cout << "gonna be into run" << endl;

    while (true) {
        int len = read(fd, buffer.data(), buffer.size());
        CHECK(len < 0, "Issue while read");
        nfq_handle_packet(handler, buffer.data(), len);
    }

    cout << "exiting from craftberry" << endl;
    nfq_destroy_queue(queue);
    nfq_close(handler);

    // cout << "removing iptables rule" << endl;
    // IPTABLES("icmp", true);
    return 0;
}
