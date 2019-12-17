#include "fstream"
#include "iostream"
#include "pcapplusplus/DnsLayer.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"
#include "pcapplusplus/VlanLayer.h"
#include "stdlib.h"
#include "string.h"

#define DEBUG(x)        \
    do {                \
        std::cerr << x; \
    } while (0)

using namespace std;
using namespace pcpp;

class Crafter {
private:
    string interfaceSrc;
    string interfaceDst;
    PcapLiveDevice *devSrc;
    PcapLiveDevice *devDst;

public:
    Crafter(string _interfaceSrc, string _interfaceDst) {
        this->interfaceSrc = _interfaceSrc;
        this->interfaceDst = _interfaceDst;
        this->devSrc = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(this->interfaceSrc.c_str());
        this->devDst = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(this->interfaceDst.c_str());

        //DOC: ottengo il device
        if (this->devSrc == NULL || this->devDst == NULL) {
            cout << "Cannot find interface with IPv4 address of '" << this->interfaceSrc.c_str() << "' or '"
                 << this->interfaceDst.c_str() << "'\n";
            exit(1);
        }
        //DOC: stampo informazioni dei device
        this->deviceInfo();
        //DOC: apro il device
        if (!this->devSrc->open() || !this->devDst->open()) {
            cout << "Cannot open the devices\n";
            exit(1);
        }
    };
    void sendPacket(RawPacket *p) {
        if (!this->devSrc->sendPacket(*p)) {
            cout << "Couldn't send packet\n";
            exit(1);
        }
        cout << "wrote " << p->getRawDataLen() << " B" << endl;
    }
    void stopCapture() {
        this->devSrc->stopCapture();
    }

    //LEV 2
    void VLANDoubleTagging();
    //LEV 4
    void TCPmultiply(int n) {
        devSrc->startCapture(
            [](RawPacket *inPacket, PcapLiveDevice *dev, void *myself) {
                // if (n < 0) {
                //     cout << "Cool, but I cannot do that dude!" << endl;
                //     return;
                // }
                Packet parsedPacket(inPacket);
                if (!parsedPacket.isPacketOfType(ProtocolType::TCP))
                    return;
                for (int i = 0; i < 3 /*n*/; i++) {
                    cout << "scrivo pacchetto tcp" << endl;
                    static_cast<Crafter *>(myself)->sendPacket(inPacket);
                }
            },
            nullptr);
    };
    void UDPmultiply(int n) {
        devSrc->startCapture(
            [](RawPacket *inPacket, PcapLiveDevice *dev, void *myself) {
                // if (n < 0) {
                //     cout << "Cool, but I cannot do that dude!" << endl;
                //     return;
                // }
                Packet parsedPacket(inPacket);
                cout << "got a packet of " << inPacket->getRawDataLen() << " B from dev " << dev->getIPv4Address().toString() << endl;
                if (parsedPacket.isPacketOfType(ProtocolType::UDP)) {
                    for (int i = 0; i < 3 /*n*/; i++) {
                        cout << "scrivo pacchetto tcp" << endl;
                        static_cast<Crafter *>(myself)->sendPacket(inPacket);
                    }
                }
            },
            nullptr);
    };
    //LEV 5
    static void HTTPImageSubstitution(Packet packet) {
        //NOTE: non riesco a prendere l'immagine perchè è suddivisa su più frame e devo prima ricostruire i pacchetti tcp
        //vedi: https://github.com/seladb/PcapPlusPlus/blob/master/Examples/TcpReassembly/main.cpp
        HttpResponseLayer *response = packet.getLayerOfType<HttpResponseLayer>();
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

    //map di sostituzioni <from,to>
    // void DNSRobber(map<string, string> substitutions) {
    //     //TODO: adesso la sostituzione è in query ed in answer e ritorna malformed packet. Separare??
    //     RawPacket inPacket;
    //     while (this->input->getNextPacket(inPacket)) {
    //         Packet parsedPacket(&inPacket);
    //         DnsLayer *response = parsedPacket.getLayerOfType<DnsLayer>();
    //         if (response == NULL)
    //             continue;
    //         DnsQuery *q;
    //         if ((q = response->getFirstQuery()) == NULL)
    //             continue;
    //         do {
    //             DEBUG(q->getName());
    //             for (auto &dnsname : substitutions) {
    //                 if (q->getName().compare(dnsname.first) == 0 && q->setName(dnsname.second))
    //                     DEBUG(" --> " << dnsname.second << endl);
    //             }
    //         } while ((q = response->getNextQuery(q)) != NULL);

    //         parsedPacket.computeCalculateFields();
    //         //this->output->writePacket(*parsedPacket.getRawPacket());
    //     }
    // };

    //void getOutputStats() {
    // create the stats object
    //pcap_stat stats;
    //this->output->getStatistics(stats);
    //cout << "Written " << stats.ps_recv << " packets successfully to pcap-ng writer and " << stats.ps_drop << " packets could not be written\n";
    //}

    void deviceInfo() {
        cout << "Interface Src info:\n";
        cout << "   Interface name:        " << this->devSrc->getName() << endl;
        cout << "   Interface description: " << this->devSrc->getDesc() << endl;
        cout << "   MAC address:           " << this->devSrc->getMacAddress().toString().c_str() << endl;
        cout << "   Default gateway:       " << this->devSrc->getDefaultGateway().toString().c_str() << endl;
        cout << "   Interface MTU:        " << this->devSrc->getMtu() << endl;
        if (this->devSrc->getDnsServers().size() > 0)
            cout << "   DNS server:            " << this->devSrc->getDnsServers().at(0).toString().c_str() << endl;

        cout << "Interface Src info:\n";
        cout << "   Interface name:        " << this->devDst->getName() << endl;
        cout << "   Interface description: " << this->devDst->getDesc() << endl;
        cout << "   MAC address:           " << this->devDst->getMacAddress().toString().c_str() << endl;
        cout << "   Default gateway:       " << this->devDst->getDefaultGateway().toString().c_str() << endl;
        cout << "   Interface MTU:         " << this->devDst->getMtu() << endl;
        if (this->devDst->getDnsServers().size() > 0)
            cout << "   DNS server:            " << this->devDst->getDnsServers().at(0).toString().c_str() << endl;
    }
};