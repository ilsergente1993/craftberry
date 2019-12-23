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
    //LEV 2
    void VLANDoubleTagging();
    //LEV 4

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
};
