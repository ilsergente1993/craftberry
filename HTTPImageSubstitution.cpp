#include "Attack.cpp"
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

using namespace std;
using namespace pcpp;

class HTTPImageSubstitution : public Attack {

public:
    static const int level = 5;
    int n;

    HTTPImageSubstitution() : n(0){};
    ~HTTPImageSubstitution(){};
    vector<RawPacket *> *craft(RawPacket *inPacket) {
        Packet parsedPacket(inPacket);
        vector<RawPacket *> *pp = new vector<RawPacket *>();

        //NOTE: non riesco a prendere l'immagine perchè è suddivisa su più frame e devo prima ricostruire i pacchetti tcp
        //vedi: https://github.com/seladb/PcapPlusPlus/blob/master/Examples/TcpReassembly/main.cpp
        HttpResponseLayer *response = parsedPacket.getLayerOfType<HttpResponseLayer>();
        if (response == NULL)
            return nullptr;
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
        // pp->push_back(inPacket);
        // this->shots++;
        return pp;
    }
};