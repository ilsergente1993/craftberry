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
                       InGoing,
                       OutGoing };

struct Details {
public:
    double totalBytesReceived{0};
    double totalPacketsReceived{0};
    double totalBytesSent{0};
    double totalPacketsSent{0};
    double totalBytesDropped{0};
    double totalPacketsDropped{0};

    string method;
    string interfaceInt;
    string interfaceExt;
    PcapLiveDevice *devInt;
    PcapLiveDevice *devExt;
    PcapNgFileWriterDevice *devExtFile;
    PacketDirection direction;
    void *data;

    Details(string _method, string _interfaceInt, string _interfaceExt, string _devExtFilename, PacketDirection _direction) : data(0) {
        method = _method;
        devInt = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp((interfaceInt = _interfaceInt).c_str());
        devExt = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp((interfaceExt = _interfaceExt).c_str());
        devExtFile = new PcapNgFileWriterDevice(_devExtFilename.c_str());
        direction = _direction;
        //DOC: getting the device
        if (devInt == NULL || devExt == NULL) {
            cout << "Cannot find interface with IPv4 address of '" << interfaceInt << "' or '" << interfaceExt << "'\n";
            exit(1);
        }
        //DOC: opening the device
        if (!devInt->open() || !devExt->open()) {
            cout << "Cannot open the devices" << endl;
            exit(1);
        }
        //DOC: opening the out file stream
        if (!devExtFile->open()) {
            printf("Cannot open the out file stream for writing\n");
            exit(1);
        }
    };
    ~Details() {
        if (!devInt->open() || !devExt->open()) {
            cout << "Cannot close what is not opened" << endl;
        }
        devInt->stopCapture();
        devExt->stopCapture();
        devExtFile->close();
        //devInt->close();
        // devExt->close();
        //free(devInt);
        // free(devExt);
        // free(data);
        //delete devInt;
        // delete devExt;
        // delete data;
        //delete devExtFile;
        cout << "All is clean" << endl;
    }

    void toString() {
        cout << "0---------------------------------------------------------0" << endl;
        cout << "\tMethod:                " << method << endl;
        cout << "\tLogfile:               " << devExtFile->getFileName() << endl;
        cout << "\tDirection:             " << (direction == Both ? "in&out" : (direction == InGoing ? "in" : "out")) << endl;
        //cout << "\tAddress Data:          " << data << endl;
        if (!devInt->open() || !devExt->open()) {
            cout << "DevInt or DevExt not opened" << endl;
            return;
        }
        cout << "Interface Int info:" << endl;
        cout << "\tIP:                    " << devInt->getIPv4Address().toString() << endl;
        cout << "\tInterface name:        " << devInt->getName() << endl;
        cout << "\tInterface description: " << devInt->getDesc() << endl;
        cout << "\tMAC address:           " << devInt->getMacAddress().toString() << endl;
        cout << "\tDefault gateway:       " << devInt->getDefaultGateway().toString() << endl;
        cout << "\tInterface MTU:         " << devInt->getMtu() << endl;
        if (devInt->getDnsServers().size() > 0)
            cout << "\tDNS server:            " << devInt->getDnsServers().at(0).toString() << endl;
        else
            cout << "\tDNS Servers:           0" << endl;

        cout << "Interface Ext info:" << endl;
        cout << "\tIP:                    " << devExt->getIPv4Address().toString() << endl;
        cout << "\tInterface name:        " << devExt->getName() << endl;
        cout << "\tInterface description: " << devExt->getDesc() << endl;
        cout << "\tMAC address:           " << devExt->getMacAddress().toString() << endl;
        cout << "\tDefault gateway:       " << devExt->getDefaultGateway().toString() << endl;
        cout << "\tInterface MTU:         " << devExt->getMtu() << endl;
        if (devExt->getDnsServers().size() > 0)
            cout << "\tDNS server:            " << devExt->getDnsServers().at(0).toString() << endl;
        else
            cout << "\tDNS Servers:           0" << endl;
    }

    void summary() {
        cerr << endl
             << "   Packets received:      " << totalPacketsReceived << " (" << totalBytesReceived << " bytes)" << endl
             << "   Packets sent:          " << totalPacketsSent << " (" << totalBytesSent << " bytes)" << endl
             << "   Packets dropped:       " << totalPacketsDropped << " (" << totalBytesDropped << " bytes)" << endl;
        pcap_stat stats;
        devExtFile->getStatistics(stats);
        cerr << "in file: received:" << stats.ps_recv << ", "
             << "dropped:" << stats.ps_drop << endl;
    };

    bool sendPacket(RawPacket *p, PcapLiveDevice *destination) {
        nat(p);
        if (p->getRawDataLen() > destination->getMtu()) {
            totalPacketsDropped++;
            totalBytesDropped += p->getRawDataLen();
            return false;
        }
        if (destination->sendPacket(*p)) {
            totalBytesSent += p->getRawDataLen();
            totalPacketsSent++;
            devExtFile->writePacket(*p);
            return true;
        }
        cout << "something strange has just happened" << endl;
        return false;
    };
    void sendPackets(vector<RawPacket *> *pToSend, PcapLiveDevice *destination, bool hidden = false) {
        int cont = 0;
        double size = 0;
        for (auto p : *pToSend) {
            if (!sendPacket(p, destination)) {
                //if (!hidden)
                cout << "1 packet skipped" << endl;
            } else {
                cont++;
                size += p->getRawDataLen();
            }
        }
        //if (!hidden)
        DEBUG(" └> " << cont << " packets (" << size << " B) to " << destination->getIPv4Address().toString() << endl);
    };

    static void callback(RawPacket *inPacket, PcapLiveDevice *localDevInt, void *details) {
        //DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
        vector<RawPacket *> *pToSend;
        Details *d = (Details *)details;
        d->totalBytesReceived += inPacket->getRawDataLen();
        d->totalPacketsReceived++;

        if (d->method.compare("BEQUITE") == 0) {
            //DOC: just forwarding everything
            DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
            vector<RawPacket *> *pp = new vector<RawPacket *>();
            pp->push_back(inPacket);
            //d->sendPackets(pp);
            return;
        }

        if (d->method.compare("TCPMULTIPLY") == 0) {
            if (!d->isCraftingOutGoing(localDevInt))
                return;
            TcpMultiply action(3);
            pToSend = action.craftOutGoing(inPacket);
            if (pToSend->size() > 0) {
                DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
                //d->sendPackets(pToSend);
            }
            return;
        }

        if (d->method.compare("UDPMULTIPLY") == 0) {
            UdpMultiply action(3);
            pToSend = action.craftOutGoing(inPacket);
            if (pToSend->size() > 0) {
                DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
                cout << pToSend->size() << endl;
                //d->sendPackets(pToSend);
            }
            return;
        }

        if (d->method.compare("CHACHA20") == 0) {
            DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);

            ChaCha20Worker action;
            pToSend = action.craftOutGoing(inPacket);
            if (pToSend->size() > 0) {
                //d->sendPackets(pToSend);
            }
            return;
        }

        if (d->method.compare("ICMPMULTIPLY") == 0) {
            IcmpMultiply action(2, 3);
            if (d->isCraftingInGoing(localDevInt)) {
                pToSend = action.craftInGoing(inPacket);
                if (pToSend->size() > 0) {
                    DEBUG("-> 1 in packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
                    //cout << pToSend->size() << endl;
                    d->sendPackets(pToSend, d->devInt);
                }
            }
            if (d->isCraftingOutGoing(localDevInt)) {
                pToSend = action.craftOutGoing(inPacket);
                if (pToSend->size() > 0) {
                    DEBUG("-> 1 out packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
                    //cout << pToSend->size() << endl;
                    d->sendPackets(pToSend, d->devExt);
                }
            }
            return;
        }

        //se non è nessuno dei precedenti cmq rimbalzo tutto
        //DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
        //modalità solo protocollo interessato?!?!?!?!?!?!?
        //senza di questo potrei non riuscire a tenere la comunicazione perchè tolgo pacchetti di servizio
        //d->sendPacket(inPacket);
    }

private:
    bool isCraftingInGoing(PcapLiveDevice *devFromPacketComes) {
        //cout << devFromPacketComes->getIPv4Address().toInt() << " =?= " << devExt->getIPv4Address().toInt() << endl;
        return devFromPacketComes->getIPv4Address().toInt() == devExt->getIPv4Address().toInt();
    }
    bool isCraftingOutGoing(PcapLiveDevice *devFromPacketComes) {
        //cout << devFromPacketComes->getIPv4Address().toInt() << " =?= " << devInt->getIPv4Address().toInt() << endl;
        return devFromPacketComes->getIPv4Address().toInt() == devInt->getIPv4Address().toInt();
    }

    void nat(RawPacket *p) {
        Packet parsedPacket(p);
        IPv4Layer *ipv4 = parsedPacket.getLayerOfType<IPv4Layer>();
        if (ipv4->getIPv4Header()->ipDst == devExt->getIPv4Address().toInt())
            ipv4->setDstIpAddress(devInt->getIPv4Address());
        if (ipv4->getIPv4Header()->ipDst == devInt->getIPv4Address().toInt())
            ipv4->setDstIpAddress(devExt->getIPv4Address());
    }
};