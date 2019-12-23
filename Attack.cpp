//DOC: abstract class parent of every single attack implementation

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

class Attack {
protected:
    int shots;

public:
    static const int level;
    Attack() : shots(0){};
    ~Attack(){};
    virtual vector<RawPacket *> *craft(RawPacket *) = 0;

    int getShots() { return this->shots; };
};