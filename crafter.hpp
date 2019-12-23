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

struct Cuki;
class Crafter;

struct Cuki {
    Crafter *myself;
    void *data;
    Cuki(Crafter *c, void *d) {
        this->myself = c;
        this->data = d;
    };
};

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
    };

    //LEV 2
    void VLANDoubleTagging();
    //LEV 4
    void TCPmultiply(int n) {
        if (n < 0) {
            cout << "Cool, but I cannot do that dude! 'n' must be greater than 0." << endl;
            return;
        }
        Cuki c = {this, &n};
        devSrc->startCapture(
            [](RawPacket *inPacket, PcapLiveDevice *dev, void *cookie) {
                Packet parsedPacket(inPacket);
                if (!parsedPacket.isPacketOfType(ProtocolType::TCP))
                    return;

                Cuki *c = static_cast<Cuki *>(cookie);
                cout << " ---> " << (intptr_t)c->data << endl;
                for (int i = 0; i < (intptr_t)c->data; i++) {
                    cout << "scrivo pacchetto tcp" << endl;
                    //c->myself->sendPacket(inPacket);
                }
            },
            &c);
    };
    void UDPmultiply(int n) {
        if (n < 0) {
            cout << "Cool, but I cannot do that dude! 'n' must be greater than 0." << endl;
            return;
        }
        Cuki *c = new Cuki(this, &n);
        cout << " -> YEAH: " << *(int *)(c->data) << " => " << (c->data) << endl;

        devSrc->startCapture(
            [](RawPacket *inPacket, PcapLiveDevice *dev, void *cookie) {
                Packet parsedPacket(inPacket);
                DEBUG("got a packet of " << inPacket->getRawDataLen() << " B from dev " << dev->getIPv4Address().toString() << endl);

                Cuki *c = (Cuki *)(cookie);
                cout << " -> YEAH: " << *(int *)static_cast<void *>(c->data) << " => " << (c->data) << endl;

                if (parsedPacket.isPacketOfType(ProtocolType::UDP)) {
                    for (int i = 0; i < 3; i++) {
                        //cout << "scrivo pacchetto udp " << inPacket->getRawDataLen() << "B" << endl;
                        //c->myself->sendPacket(inPacket);
                    }
                }
                exit(1);
            },
            c);
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
    void DNSRobber(map<string, string> substitutions) {
        //TODO: adesso la sostituzione è in query ed in answer e ritorna malformed packet. Separare??
        if (substitutions.size() <= 0) {
            cout << "Cool, but I cannot do that dude! the substitution map size must be greater than 0." << endl;
            return;
        }
        Cuki c = {this, &substitutions};
        devSrc->startCapture(
            [](RawPacket *inPacket, PcapLiveDevice *dev, void *cookie) {
                Packet parsedPacket(inPacket);
                DnsLayer *response = parsedPacket.getLayerOfType<DnsLayer>();
                if (response == NULL)
                    return;
                DnsQuery *q;
                if ((q = response->getFirstQuery()) == NULL)
                    return;
                DEBUG("got a packet of " << inPacket->getRawDataLen() << " B from dev " << dev->getIPv4Address().toString() << endl);
                Cuki c = *(Cuki *)(cookie);
                do {
                    DEBUG(q->getName());
                    map<string, string> substitutions = *(map<string, string> *)(c.data);
                    for (auto &dnsname : substitutions) {
                        if (q->getName().compare(dnsname.first) == 0 && q->setName(dnsname.second))
                            DEBUG(" --> " << dnsname.second << endl);
                    }
                } while ((q = response->getNextQuery(q)) != NULL);
                cout << "scrivo pacchetto udp" << endl;
                //c.myself->sendPacket(parsedPacket.getRawPacket());
            },
            &c);
    };

    void stopCapture() {
        this->devSrc->stopCapture();
    }
};
