#include "Action.cpp"
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

class HTTPContentCatcher : public Action {

public:
    static const int level = 5;
    int n;

    HTTPContentCatcher() : n(0){};
    ~HTTPContentCatcher(){};
    vector<RawPacket *> *craft(RawPacket *inPacket) {
        Packet parsedPacket(inPacket);
        vector<RawPacket *> *pp = new vector<RawPacket *>();
        // if (parsedPacket.isPacketOfType(ProtocolType::UDP)) {
        //     for (int i = 0; i < this->n; i++) {
        //         pp->push_back(inPacket);
        //     }
        //     this->shots++;
        // }
        return pp;
    }
};