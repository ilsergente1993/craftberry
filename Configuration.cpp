#pragma once

#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PlatformSpecificUtils.h"
#include "pcapplusplus/TcpLayer.h"
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

struct Traffic {
    double bytes = 0;
    double packets = 0;
};

struct Configuration {
public:
    struct Traffic received;
    struct Traffic crafted;
    struct Traffic created;
    struct Traffic dropped;

    string method;
    string tun0Address;
    PcapLiveDevice *devTun0;
    PcapNgFileWriterDevice *devLogFile;
    PacketDirection direction;
    void *data;

    Configuration(string _method, string _tun0Address, string _devLogFilename, PacketDirection _direction) : data(0) {
        method = _method;
        received = {0, 0};
        crafted = {0, 0};
        created = {0, 0};
        dropped = {0, 0};

        devTun0 = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp((tun0Address = _tun0Address).c_str());
        devLogFile = new PcapNgFileWriterDevice(_devLogFilename.c_str());
        direction = _direction;
        //DOC: getting the device
        if (devTun0 == NULL) {
            cout << "Cannot find interface with IPv4 address of '" << tun0Address << "'\n";
            exit(1);
        }
        //DOC: opening the device
        if (!devTun0->open()) {
            cout << "Cannot open the devices" << endl;
            exit(1);
        }
        //DOC: opening the out file stream
        if (!devLogFile->open()) {
            printf("Cannot open the out file stream for writing\n");
            exit(1);
        }
    };
    ~Configuration() {
        if (!devTun0->open()) {
            cout << "Cannot close what is not opened" << endl;
        }
        devTun0->stopCapture();
        devLogFile->close();
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
        cout << "\tLogfile:               " << devLogFile->getFileName() << endl;
        cout << "\tDirection:             " << (direction == Both ? "in&out" : (direction == InGoing ? "in" : "out")) << endl;
        //cout << "\tAddress Data:          " << data << endl;
        if (!devTun0->open()) {
            cout << "devTun0 is not opened" << endl;
            return;
        }
        cout << "Interface tun0 info:" << endl;
        cout << "\tIP:                    " << devTun0->getIPv4Address().toString() << endl;
        cout << "\tInterface name:        " << devTun0->getName() << endl;
        cout << "\tInterface description: " << devTun0->getDesc() << endl;
        cout << "\tMAC address:           " << devTun0->getMacAddress().toString() << endl;
        cout << "\tDefault gateway:       " << devTun0->getDefaultGateway().toString() << endl;
        cout << "\tInterface MTU:         " << devTun0->getMtu() << endl;
        if (devTun0->getDnsServers().size() > 0)
            cout << "\tDNS server:            " << devTun0->getDnsServers().at(0).toString() << endl;
        else
            cout << "\tDNS Servers:           0" << endl;
    }

    void summary() {
        cerr << endl
             << "   Packets received:      " << received.packets << " (" << received.bytes << " bytes)" << endl
             << "   Packets crafted:       " << crafted.packets << " (" << crafted.bytes << " bytes)" << endl
             << "   Packets created:       " << created.packets << " (" << created.bytes << " bytes)" << endl
             << "   Packets dropped:       " << dropped.packets << " (" << dropped.bytes << " bytes)" << endl;
        /*pcap_stat stats;
        devLogFile->getStatistics(stats);
        cerr << "in file: received:" << stats.ps_recv << ", "
             << "dropped:" << stats.ps_drop << endl;*/
    };

    static void callback(RawPacket *inPacket, PcapLiveDevice *localDevInt, void *_conf) {
        //DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
        vector<RawPacket *> *pToSend;
        Configuration *conf = (Configuration *)_conf;
        conf->received.bytes += inPacket->getRawDataLen();
        conf->received.packets++;
        if (conf->method.compare("BEQUITE") == 0) {
            //DOC: just forwarding everything
            DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
            vector<RawPacket *> *pp = new vector<RawPacket *>();
            pp->push_back(inPacket);
            //d->sendPackets(pp);
            return;
        }
        /*
        if (conf->method.compare("TCPMULTIPLY") == 0) {
            if (!conf->isCraftingOutGoing(localDevInt))
                return;
            TcpMultiply action(3);
            pToSend = action.craftOutGoing(inPacket);
            if (pToSend->size() > 0) {
                DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
                //d->sendPackets(pToSend);
            }
            return;
        }

        if (conf->method.compare("UDPMULTIPLY") == 0) {
            UdpMultiply action(3);
            pToSend = action.craftOutGoing(inPacket);
            if (pToSend->size() > 0) {
                DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
                cout << pToSend->size() << endl;
                //d->sendPackets(pToSend);
            }
            return;
        }

        if (conf->method.compare("CHACHA20") == 0) {
            DEBUG("-> 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);

            ChaCha20Worker action;
            pToSend = action.craftOutGoing(inPacket);
            if (pToSend->size() > 0) {
                //d->sendPackets(pToSend);
            }
            return;
        }

        if (conf->method.compare("ICMPMULTIPLY") == 0) {
            IcmpMultiply action(2, 3);
            if (conf->isCraftingInGoing(localDevInt)) {
                pToSend = action.craftInGoing(inPacket);
                if (pToSend->size() > 0) {
                    DEBUG("-> 1 in packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
                    //cout << pToSend->size() << endl;
                    //d->sendPackets(pToSend, d->devInt);
                }
            }
            if (conf->isCraftingOutGoing(localDevInt)) {
                pToSend = action.craftOutGoing(inPacket);
                if (pToSend->size() > 0) {
                    DEBUG("-> 1 out packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
                    //cout << pToSend->size() << endl;
                    //d->sendPackets(pToSend, d->devExt);
                }
            }
            return;
        }
*/
        //se non è nessuno dei precedenti cmq rimbalzo tutto
        //DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
        //modalità solo protocollo interessato?!?!?!?!?!?!?
        //senza di questo potrei non riuscire a tenere la comunicazione perchè tolgo pacchetti di servizio
        //d->sendPacket(inPacket);
    }

private:
    bool isCraftingInGoing(PcapLiveDevice *devFromPacketComes) {
        //cout << devFromPacketComes->getIPv4Address().toInt() << " =?= " << devExt->getIPv4Address().toInt() << endl;
        return devFromPacketComes->getIPv4Address().toInt(); // == devExt->getIPv4Address().toInt();
    }
    bool isCraftingOutGoing(PcapLiveDevice *devFromPacketComes) {
        //cout << devFromPacketComes->getIPv4Address().toInt() << " =?= " << devInt->getIPv4Address().toInt() << endl;
        return devFromPacketComes->getIPv4Address().toInt(); // == devInt->getIPv4Address().toInt();
    }
};