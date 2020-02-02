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

#define IPTABLES(proto, isdel)            \
    system((                              \
               "\n#/bin/bash\n\n"s +      \
               "sudo iptables "s +        \
               (!isdel ? "-A"s : "-D"s) + \
               " INPUT -p "s +            \
               #proto +                   \
               " -j NFQUEUE"s)            \
               .c_str());

using namespace std;

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    cout << "entering callback" << endl;

    //DOC: ottengo il payload del pacchetto
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    CHECK(ph == nullptr, "Issue while packet header");
    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(nfa, &rawData);
    CHECK(len < 0, "Can\'t get payload data");

    struct timeval timestamp;
    nfq_get_timestamp(nfa, &timestamp);

    //DOC: creo il pacchetto pcapPlusPlus
    pcpp::RawPacket inPacketRaw(static_cast<uint8_t *>(rawData), len, timestamp, false, pcpp::LINKTYPE_RAW);

    pcpp::Packet inPacket(&inPacketRaw);
    pcpp::EthLayer newEthernetLayer(pcpp::MacAddress("f0:4b:3a:4f:80:30"), pcpp::MacAddress("a2:ee:e9:dd:4c:14"));
    inPacket.insertLayer(NULL, &newEthernetLayer, true);
    inPacket.computeCalculateFields();

    //DOC: scrorro i pacchetti per inspezione
    pcpp::Layer *L = inPacket.getFirstLayer();
    cout << "Pacchetto In" << endl;
    while (L != nullptr) {
        cout << "\t" << L->getOsiModelLayer() << " => " << L->toString() << endl;
        L = L->getNextLayer();
    }

    cout << "Invio il pacchetto" << endl;

    //DOC: apro il dispositivo di destinazione
    string dstAddr = inPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress().toString();
    pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(dstAddr.c_str());
    ASSERT(dev == NULL, "Cannot find interface with IPv4 address of "s + dstAddr, exit(1));
    ASSERT(!dev->open(), "Cannot open device", exit(1));

    //DOC: creo ed invio una secondo pacchetto identico
    pcpp::RawPacket outPacketRaw(*inPacket.getRawPacketReadOnly());
    pcpp::Packet outPacket(&outPacketRaw);

    pcpp::Layer *LL = outPacket.getFirstLayer();
    cout << "Pacchetto Out" << endl;
    while (LL != nullptr) {
        cout << "\t" << LL->getOsiModelLayer() << " => " << LL->toString() << endl;
        LL = LL->getNextLayer();
    }

    CHECK(!dev->pcpp::PcapLiveDevice::sendPacket(outPacketRaw), "packet not sent");
    dev->close();

    //DOC: invio il verdetto
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}

int main(/*int argc, char **argv*/) {
    // cout << "adding iptables rule" << endl;
    // IPTABLES("udp", false);

    struct nfq_handle *handler = nfq_open();
    ASSERT(handler == nullptr, "Can\'t open hfqueue handler.", exit(1));

    // cout << "unbinding existing nf_queue handler for AF_INET (if any)\n";
    // ASSERT(nfq_unbind_pf(handler, AF_INET) < 0, "error during nfq_unbind_pf()\n", exit(1));
    // cout << "binding nfnetlink_queue as nf_queue handler for AF_INET\n";
    // ASSERT(nfq_bind_pf(handler, AF_INET) < 0, "error during nfq_bind_pf()\n", exit(1));

    struct nfq_q_handle *queue = nfq_create_queue(handler, 0, &callback, nullptr);
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
