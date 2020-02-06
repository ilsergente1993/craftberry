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

namespace Action {
class Udp {

public:
    static const int level = 4;
    int n;

    Udp(int _n) : n(_n){};
    ~Udp(){};
    // vector<RawPacket *> *craftInGoing(RawPacket *inPacket) {
    //     Packet parsedPacket(inPacket);
    //     vector<RawPacket *> *pp = new vector<RawPacket *>();
    //     if (parsedPacket.isPacketOfType(ProtocolType::UDP)) {
    //         for (int i = 0; i < this->n; i++) {
    //             pp->push_back(inPacket);
    //         }
    //         this->shots++;
    //     }
    //     return pp;
    // }
};
} // namespace Action