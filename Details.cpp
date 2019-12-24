#pragma once

#include "Attack.cpp"
#include "arpa/inet.h"
#include "getopt.h"
#include "iostream"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PlatformSpecificUtils.h"
#include "pcapplusplus/TcpLayer.h"
#include "stdlib.h"

using namespace std;
using namespace pcpp;

struct Details {
public:
    double totalByteReceived{0};
    double totalPacketsReceived{0};
    double totalByteSent{0};
    double totalPacketsSent{0};

    string method;
    string intSrc;
    string intDst;
    pcpp::PcapLiveDevice *devSrc;
    pcpp::PcapLiveDevice *devDst;
    void *data;

    Details(string _method, string _interfaceSrc, string _interfaceDst) : data(0) {
        method = _method;
        devSrc = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp((intSrc = _interfaceSrc).c_str());
        devDst = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp((intDst = _interfaceDst).c_str());
        //DOC: ottengo il device
        if (devSrc == NULL || devDst == NULL) {
            cout << "Cannot find interface with IPv4 address of '" << intSrc << "' or '" << intDst << "'\n";
            exit(1);
        }
        //DOC: apro il device
        if (!devSrc->open() || !devDst->open()) {
            cout << "Cannot open the devices" << endl;
            exit(1);
        }
    };
    ~Details() {
        if (!devSrc->open() || !devDst->open()) {
            cout << "Cannot close what is not opened" << endl;
        }
        //d->devSrc->stopCapture(); ???
        //devSrc->close();
        // devDst->close();
        //free(devSrc);
        // free(devDst);
        // free(data);
        //delete devSrc;
        // delete devDst;
        // delete data;
        cout << "All is clean" << endl;
    }

    void toString() {
        cout << "0---------------------------------------------------------0" << endl;
        cout << "\tMethod:                " << method << endl;
        cout << "\tAddress Data:          " << data << endl;
        if (!devSrc->open() || !devDst->open()) {
            cout << "DevSrc or DevDst not opened" << endl;
            return;
        }
        cout << "Interface Src info:\n";
        cout << "\tIP:                    " << devSrc->getIPv4Address().toString() << endl;
        cout << "\tInterface name:        " << devSrc->getName() << endl;
        cout << "\tInterface description: " << devSrc->getDesc() << endl;
        cout << "\tMAC address:           " << devSrc->getMacAddress().toString() << endl;
        cout << "\tDefault gateway:       " << devSrc->getDefaultGateway().toString() << endl;
        cout << "\tInterface MTU:         " << devSrc->getMtu() << endl;
        if (devSrc->getDnsServers().size() > 0)
            cout << "\tDNS server:            " << devSrc->getDnsServers().at(0).toString() << endl;
        else
            cout << "\tDNS Servers:           0" << endl;

        cout << "Interface Dst info:\n";
        cout << "\tIP:                    " << devDst->getIPv4Address().toString() << endl;
        cout << "\tInterface name:        " << devDst->getName() << endl;
        cout << "\tInterface description: " << devDst->getDesc() << endl;
        cout << "\tMAC address:           " << devDst->getMacAddress().toString() << endl;
        cout << "\tDefault gateway:       " << devDst->getDefaultGateway().toString() << endl;
        cout << "\tInterface MTU:         " << devDst->getMtu() << endl;
        if (devDst->getDnsServers().size() > 0)
            cout << "\tDNS server:            " << devDst->getDnsServers().at(0).toString() << endl;
        else
            cout << "\tDNS Servers:           0" << endl;
    }
    void stats() {
        cout << endl;
        cout << "   Packets received:      " << totalPacketsReceived << " (" << totalByteReceived << " bytes)" << endl;
        cout << "   Packets sent:          " << totalPacketsSent << " (" << totalByteSent << " bytes)" << endl;
    };

    static void sendPacket(vector<RawPacket *> *pToSend, Details *d) {
        int cont = 0;
        double size = 0;
        for (auto p : *pToSend) {
            if (!d->devDst->sendPacket(*p)) {
                cout << "1 packet skipped" << endl;
                //exit(1);
            } else {
                cont++;
                size += p->getRawDataLen();
            }
            d->totalByteSent += size;
            d->totalPacketsSent += cont;
        }
        DEBUG("-> " << cont << " packets (" << size << " B) to " << d->devDst->getIPv4Address().toString() << endl);
    }
};