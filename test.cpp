#include "arpa/inet.h"
#include "getopt.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PlatformSpecificUtils.h"
#include "pcapplusplus/TablePrinter.h"
#include "pcapplusplus/TcpLayer.h"
#include "stdlib.h"
#include <iostream>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DEBUG(x)                \
    do {                        \
        std::cerr << "\t" << x; \
    } while (0);

using namespace std;
using namespace pcpp;

bool gotit = false;

bool sendPacket(RawPacket *p, PcapLiveDevice *destination) {
    DEBUG("-> 1 packet" << p->getRawDataLen() << endl);
    return destination->sendPacket(*p);
};

static void callback(RawPacket *inPacket, PcapLiveDevice *localDevInt, void *data) {
    Packet parsedPacket(inPacket);
    if (!parsedPacket.isPacketOfType(ProtocolType::ICMP))
        return;
    DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << localDevInt->getIPv4Address().toString() << endl);
    if (!gotit) {
        //sendPacket(inPacket, localDevInt);
        gotit = true;
    }
}

int main(int argc, char *argv[]) {
    PcapLiveDevice *dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp("172.24.24.3");
    if (dev == NULL) {
        cout << "Cannot find interface with that IPv4 address\n";
        exit(1);
    }
    if (!dev->open()) {
        cout << "Cannot open the devices" << endl;
        exit(1);
    }
    dev->startCapture(callback, nullptr);
    PCAP_SLEEP(10);
    return 0;
}
