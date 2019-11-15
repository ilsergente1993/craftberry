#include "fstream"
#include "iostream"
#include "pcapplusplus/DnsLayer.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"
#include "pcapplusplus/VlanLayer.h"
#include "stdlib.h"
#include "string.h"

using namespace std;
using namespace pcpp;

class Crafter {
  public:
    Crafter(){};
    void help() {
        cout << "";
    };

    //LEV 2
    void VLANDoubleTagging(){};
    //LEV 4
    static Packet multiplyTCP(Packet packet) {
        Packet p(packet);
        return p;
        // Packet p(100);
        // p.setRawPacket(packet->getRawPacket(), false);
        // return p;
        /*// Packet Creation
        // create a new Ethernet layer
        EthLayer newEthernetLayer(MacAddress("00:50:43:11:22:33"), MacAddress("aa:bb:cc:dd:ee"));
        // create a new IPv4 layer
        IPv4Layer newIPLayer(IPv4Address(std::string("192.168.1.1")), IPv4Address(std::string("10.0.0.1")));
        newIPLayer.getIPv4Header()->ipId = htons(2000);
        newIPLayer.getIPv4Header()->timeToLive = 64;
        // create a new UDP layer
        UdpLayer newUdpLayer(12345, 53);
        // create a new DNS layer
        DnsLayer newDnsLayer;
        newDnsLayer.addQuery("www.ebay.com", DNS_TYPE_A, DNS_CLASS_IN);
        // create a packet with initial capacity of 100 bytes (will grow automatically if needed)
        Packet newPacket(100);
        // add all the layers we created
        newPacket.addLayer(&newEthernetLayer);
        newPacket.addLayer(&newIPLayer);
        newPacket.addLayer(&newUdpLayer);
        newPacket.addLayer(&newDnsLayer);
        // compute all calculated fields
        newPacket.computeCalculateFields();
        // write the new packet to a pcap file
        return newPacket;*/
    };
    void multiplyUDP(int n){};
    //LEV 5
    static void HTTPImageSubstitution(Packet *packet) {
        //NOTE: non riesco a prendere l'immagine perchè è suddivisa su più frame e devo prima ricostruire i pacchetti tcp
        //vedi: https://github.com/seladb/PcapPlusPlus/blob/master/Examples/TcpReassembly/main.cpp
        HttpResponseLayer *response = packet->getLayerOfType<HttpResponseLayer>();
        if (response == NULL)
            return;

        if (response->getFirstLine()->getStatusCodeAsInt() == 200) {
            ofstream image;
            image.open("passport.jpg", ios::binary);

            cout << "got 200 HTTP packet: " << response->getFirstLine()->getStatusCodeString() << endl;
            cout << response->getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD)->getFieldValue() << " bytes" << endl;
            uint8_t *p = response->getData();
            cout << "LEN: " << response->getDataLen() << " bytes" << endl;
            cout << "LEN: " << response->getHeaderLen() << " bytes" << endl;
            cout << response->getDataPtr(0) << endl;
            cout << "size: " << response->getLayerPayloadSize() << " bytes" << endl;
            image << response->getLayerPayload(); //è il puntatore al primo byte della stringa
            cout << response->getLayerPayload() << endl;
            image.close();
        }
    };

    void HTTPContentCatcher(){};
    void DNSRobber(){};
};