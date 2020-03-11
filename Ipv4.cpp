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
class IPv4 {

public:
    static const int level = 4;
    int n;

    IPv4(int _n) : n(_n){};
    ~IPv4(){};

    void changeDst(Packet *inPacket) {
        cout << "cambio ip di destinazione: da "
             << inPacket->getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress().toString();
        inPacket->getLayerOfType<pcpp::IPv4Layer>()->setDstIpAddress(IPv4Address("10.135.63.160"));
        cout << " a " << inPacket->getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress().toString() << endl;
    }

    static bool isProtocol(Packet *p) {
        return p->getLastLayer()->getProtocol() == pcpp::IPv4;
    }
};
} // namespace Action