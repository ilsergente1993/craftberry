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
    

    void HTTPContentCatcher(){};
};
