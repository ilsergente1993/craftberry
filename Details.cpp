#pragma once

#include "Action.cpp"
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

#include "ChaCha20Worker.cpp"
#include "DnsRobber.cpp"
#include "IcmpMultiply.cpp"
#include "TcpMultiply.cpp"
#include "UdpMultiply.cpp"

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
        devSrc->stopCapture();
        devDst->stopCapture();
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
        cout << "Interface Src info:" << endl;
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

        cout << "Interface Dst info:" << endl;
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
    void summary() {
        cerr << endl
             << "   Packets received:      " << totalPacketsReceived << " (" << totalByteReceived << " bytes)" << endl
             << "   Packets sent:          " << totalPacketsSent << " (" << totalByteSent << " bytes)" << endl;
    };

    void sendPackets(vector<RawPacket *> *pToSend) {
        int cont = 0;
        double size = 0;
        for (auto p : *pToSend) {
            if (!devDst->sendPacket(*p)) {
                cout << "1 packet skipped" << endl;
                //exit(1);
            } else {
                cont++;
                size += p->getRawDataLen();
            }
            totalByteSent += size;
            totalPacketsSent += cont;
        }
        DEBUG("-> " << cont << " packets (" << size << " B) to " << devDst->getIPv4Address().toString() << endl);
    }

    static void callback(RawPacket *inPacket, PcapLiveDevice *devSrc, void *details) {
        //DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << devSrc->getIPv4Address().toString() << endl);
        vector<RawPacket *> *pToSend;
        Details *d = (Details *)details;
        d->totalByteReceived += inPacket->getRawDataLen();
        d->totalPacketsReceived++;

        if (d->method.compare("BEQUITE") == 0) {
            DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << devSrc->getIPv4Address().toString() << endl);
            pToSend = new vector<RawPacket *>();
            pToSend->push_back(inPacket);
            d->sendPackets(pToSend);
            return;
        }

        if (d->method.compare("TCPMULTIPLY") == 0) {
            TcpMultiply action(3);
            pToSend = action.craft(inPacket);
            if (pToSend->size() > 0) {
                DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << devSrc->getIPv4Address().toString() << endl);
                d->sendPackets(pToSend);
                return;
            }
        }

        if (d->method.compare("UDPMULTIPLY") == 0) {
            UdpMultiply action(3);
            pToSend = action.craft(inPacket);
            if (pToSend->size() > 0) {
                DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << devSrc->getIPv4Address().toString() << endl);
                cout << pToSend->size() << endl;
                d->sendPackets(pToSend);
                return;
            }
        }

        if (d->method.compare("ICMPMULTIPLY") == 0) {
            IcmpMultiply action(2);
            pToSend = action.craft(inPacket);
            if (pToSend->size() > 0) {
                DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << devSrc->getIPv4Address().toString() << endl);
                //cout << pToSend->size() << endl;
                d->sendPackets(pToSend);
                return;
            }
        }

        if (d->method.compare("CHACHA20") == 0) {
            DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << devSrc->getIPv4Address().toString() << endl);

            ChaCha20Worker action;
            pToSend = action.craft(inPacket);
            if (pToSend->size() > 0) {
                d->sendPackets(pToSend);
                return;
            }
        }
    }
};