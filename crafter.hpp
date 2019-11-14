#include "iostream"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/Packet.h"

using namespace std;
using namespace pcpp;

class Crafter {
public:
    Crafter(){};
    void help() {
        cout << "";
    };

    //LEV 2
    void VLANDoubleTagging(){};
    //LEV 4
    void multiplyTCP(int n){};
    void multiplyUDP(int n){};
    //LEV 5
    static void HTTPImageSubstitution(Packet *packet) {
        HttpResponseLayer *response = packet->getLayerOfType<HttpResponseLayer>();
        if (response == NULL)
            return;

        if (response->getFirstLine()->getStatusCodeAsInt() == 200) {

            cout << "got 200 HTTP packet: " << response->getFirstLine()->getStatusCodeString() << endl;
        }
        // add x-forwarded-for field
        //HeaderField *xForwardedForField = httpRequestLayer->insertField(httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD), "X-Forwarded-For", "1.1.1.1");
        // add cache-control field
        //httpRequestLayer->insertField(xForwardedForField, "Cache-Control", "max-age=0");
    };

    void HTTPContentCatcher(){};
    void DNSRobber(){};
};