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

    void craftInGoing(Packet *inPacket) {
    }
    void craftOutGoing(Packet *inPacket) {
    }
    void changeUrl(Packet *inPacket) {
        cout << "url:     " << inPacket->getLayerOfType<HttpRequestLayer>()->getUrl() << endl;
        HttpRequestLayer *http = inPacket->getLayerOfType<HttpRequestLayer>();
        //http->getFirstLine()->setMethod(pcpp::HttpRequestLayer::HttpGET);
        http->getFieldByName(PCPP_HTTP_HOST_FIELD)->setFieldValue("www.jafed.xyz");
        http->getFirstLine()->setUri("/test.txt");
        http->computeCalculateFields();
        inPacket->computeCalculateFields();
        cout << "new url: " << inPacket->getLayerOfType<HttpRequestLayer>()->getUrl() << endl;
    }

    static bool isHTTPRequest(Packet *p) {
        return p->getLastLayer()->getProtocol() == HTTPRequest;
    }
};