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

#include "Attack.cpp"

class TcpMultiply : public Attack {

public:
    int n{2};

    TcpMultiply(){};
    ~TcpMultiply(){};
    vector<RawPacket *> *craft(RawPacket *inPacket) {
        Packet parsedPacket(inPacket);
        vector<RawPacket *> *pp = new vector<RawPacket *>();
        if (parsedPacket.isPacketOfType(ProtocolType::TCP)) {
            for (int i = 0; i < this->n; i++) {
                pp->push_back(inPacket);
            }
        }
        return pp;
    }
};