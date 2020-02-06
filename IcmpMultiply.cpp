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

class IcmpMultiply : public Action {

public:
    static const int level = 4; //TODO: ??
    int nIn, nOut;

    IcmpMultiply(int _nIn, int _nOut) : nIn(_nIn), nOut(_nOut){};
    ~IcmpMultiply(){};
    // vector<RawPacket *> *craftInGoing(RawPacket *inPacket) {
    //     Packet parsedPacket(inPacket);
    //     vector<RawPacket *> *pp = new vector<RawPacket *>();
    //     if (parsedPacket.isPacketOfType(ProtocolType::ICMP)) {
    //         for (int i = 0; i < this->nIn; i++) {
    //             pp->push_back(inPacket);
    //         }
    //         this->shots++;
    //     }
    //     return pp;
    // }

    void craftInGoing(Packet *inPacket) {
    }
    void craftOutGoing(Packet *inPacket) {
    }
    static bool isIcmp(Packet *p) {
        return p->getLayerOfType<IcmpLayer>() != nullptr;
    }
};