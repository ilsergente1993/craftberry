#pragma once

#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PlatformSpecificUtils.h"
#include "pcapplusplus/TcpLayer.h"
#include <arpa/inet.h>
#include <ctime>
#include <getopt.h>
#include <iostream>
#include <stdlib.h>

#include "Action.cpp"
#include "ChaCha20Worker.cpp"
#include "DnsRobber.cpp"
#include "IcmpMultiply.cpp"
#include "TcpMultiply.cpp"
#include "UdpMultiply.cpp"

using namespace std;
using namespace pcpp;

enum PacketDirection { Both,
                       LeftToRight,
                       RightToLeft };

struct Details {
public:
    double totalBytesReceived{0};
    double totalPacketsReceived{0};
    double totalBytesSent{0};
    double totalPacketsSent{0};
    double totalBytesDropped{0};
    double totalPacketsDropped{0};

    string method;
    string intSrc;
    string intDst;
    PcapLiveDevice *devSrc;
    PcapLiveDevice *devDst;
    PcapNgFileWriterDevice *devDstFile;
    PacketDirection direction;
    void *data;

    Details(string _method, string _interfaceSrc, string _interfaceDst, string _devDstFilename, PacketDirection _direction) : data(0) {
        method = _method;
        devSrc = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp((intSrc = _interfaceSrc).c_str());
        devDst = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp((intDst = _interfaceDst).c_str());
        devDstFile = new PcapNgFileWriterDevice(_devDstFilename.c_str());
        direction = _direction;
        //DOC: getting the device
        if (devSrc == NULL || devDst == NULL) {
            cout << "Cannot find interface with IPv4 address of '" << intSrc << "' or '" << intDst << "'\n";
            exit(1);
        }
        //DOC: opening the device
        if (!devSrc->open() || !devDst->open()) {
            cout << "Cannot open the devices" << endl;
            exit(1);
        }
        //DOC: opening the out file stream
        if (!devDstFile->open()) {
            printf("Cannot open the out file stream for writing\n");
            exit(1);
        }
    };
    ~Details() {
        if (!devSrc->open() || !devDst->open()) {
            cout << "Cannot close what is not opened" << endl;
        }
        devSrc->stopCapture();
        devDst->stopCapture();
        devDstFile->close();
        //devSrc->close();
        // devDst->close();
        //free(devSrc);
        // free(devDst);
        // free(data);
        //delete devSrc;
        // delete devDst;
        // delete data;
        //delete devDstFile;
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
             << "   Packets received:      " << totalPacketsReceived << " (" << totalBytesReceived << " bytes)" << endl
             << "   Packets sent:          " << totalPacketsSent << " (" << totalBytesSent << " bytes)" << endl
             << "   Packets dropped:       " << totalPacketsDropped << " (" << totalBytesDropped << " bytes)" << endl;
    };

    bool sendPacket(RawPacket *p) {
        if (p->getRawDataLen() > devDst->getMtu()) {
            totalPacketsDropped++;
            totalBytesDropped += p->getRawDataLen();
            return false;
        }
        if (devDst->sendPacket(*p)) {
            devDstFile->writePacket(*p);
            return true;
        }
        return false;
    };
    void sendPackets(vector<RawPacket *> *pToSend) {
        sendPackets(pToSend, false);
    };
    void sendPackets(vector<RawPacket *> *pToSend, bool hidden) {
        int cont = 0;
        double size = 0;
        for (auto p : *pToSend) {
            if (!sendPacket(p)) {
                if (!hidden)
                    cout << "1 packet skipped" << endl;
                //exit(1);
            } else {
                cont++;
                size += p->getRawDataLen();
                sendPacket(p);
            }
            totalBytesSent += p->getRawDataLen();
            totalPacketsSent += cont;
        }
        if (!hidden)
            DEBUG(" └> " << cont << " packets (" << size << " B) to " << devDst->getIPv4Address().toString() << endl);
    };

    static void callback(RawPacket *inPacket, PcapLiveDevice *localDevSrc, void *details) {
        //DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << devSrc->getIPv4Address().toString() << endl);
        vector<RawPacket *> *pToSend;
        Details *d = (Details *)details;
        d->totalBytesReceived += inPacket->getRawDataLen();
        d->totalPacketsReceived++;

        if (d->method.compare("BEQUITE") == 0) {
            //DOC: just forwarding everything
            //DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevSrc->getIPv4Address().toString() << endl);
            d->sendPacket(inPacket);
            return;
        }

        if (d->method.compare("TCPMULTIPLY") == 0) {
            if (!d->hasCorrectDirection(localDevSrc))
                return;
            TcpMultiply action(3);
            pToSend = action.craft(inPacket);
            if (pToSend->size() > 0) {
                DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevSrc->getIPv4Address().toString() << endl);
                d->sendPackets(pToSend);
            }
            return;
        }

        if (d->method.compare("UDPMULTIPLY") == 0) {
            UdpMultiply action(3);
            pToSend = action.craft(inPacket);
            if (pToSend->size() > 0) {
                DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevSrc->getIPv4Address().toString() << endl);
                cout << pToSend->size() << endl;
                d->sendPackets(pToSend);
            }
            return;
        }

        if (d->method.compare("ICMPMULTIPLY") == 0) {
            if (d->hasCorrectDirection(localDevSrc)) {
                IcmpMultiply action(2);
                pToSend = action.craft(inPacket);
                if (pToSend->size() > 0) {
                    DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevSrc->getIPv4Address().toString() << endl);
                    //cout << pToSend->size() << endl;
                    d->sendPackets(pToSend);
                }
            } else {
                d->sendPacket(inPacket);
            }
            return;
        }

        if (d->method.compare("CHACHA20") == 0) {
            DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevSrc->getIPv4Address().toString() << endl);

            ChaCha20Worker action;
            pToSend = action.craft(inPacket);
            if (pToSend->size() > 0) {
                d->sendPackets(pToSend);
            }
            return;
        }

        //se non è nessuno dei precedenti cmq rimbalzo tutto
        //DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevSrc->getIPv4Address().toString() << endl);
        //modalità solo protocollo interessato?!?!?!?!?!?!?
        //senza di questo potrei non riuscire a tenere la comunicazione perchè tolgo pacchetti di servizio
        d->sendPacket(inPacket);
    }

private:
    bool hasCorrectDirection(PcapLiveDevice *devFromPacketComes) {
        return direction == Both ||
               (direction == LeftToRight && devFromPacketComes == devSrc) ||
               (direction == RightToLeft && devFromPacketComes == devDst);
    }
    void direc(PcapLiveDevice *devFromPacketComes) {
        cout << "==========> " << devFromPacketComes->getIPv4Address().toString()
             << " =?= " << devSrc->getIPv4Address().toString()
             << " or "
             << " =?= " << devDst->getIPv4Address().toString() << " -> "
             << direction << " = "
             << (direction == LeftToRight && devFromPacketComes == devSrc) << " or "
             << (direction == RightToLeft && devFromPacketComes == devDst)
             << endl;
    }
};