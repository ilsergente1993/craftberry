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

#include "UdpMultiply.cpp"
#include "crafter.hpp"
#include "packetsContainer.hpp"

using namespace std;
using namespace pcpp;

static struct option CraftberryOptions[] =
    {{"interfaceSrc", required_argument, 0, 'A'},
     {"interfaceDst", required_argument, 0, 'B'},
     {"attack", required_argument, 0, 'a'},
     {"defense", required_argument, 0, 'd'},
     {"list-interfaces", no_argument, 0, 'l'},
     {"help", no_argument, 0, 'h'},
     {0, 0, 0, 0}};

struct Details {
    string attackName;
    string interfaceSrc;
    string interfaceDst;
    PcapLiveDevice *devSrc;
    PcapLiveDevice *devDst;
    void *data;
    Details(string _attackName, string _interfaceSrc, string _interfaceDst, PcapLiveDevice *_devSrc, PcapLiveDevice *_devDst) : data(0) {
        attackName = _attackName;
        interfaceSrc = _interfaceSrc;
        interfaceDst = _interfaceDst;
        devSrc = _devSrc;
        devDst = _devDst;
    };
};
void help();
void init(Details *);
void deviceInfo(Details *);
void callback(RawPacket *, PcapLiveDevice *, void *);
void listInterfaces();
void sendPacket(vector<RawPacket *> *, Details *);

int main(int argc, char *argv[]) {
    string interfaceSrc = "", interfaceDst = "";
    string attackName = "", defenseName = "";
    int optionIndex = 0;
    char opt = 0;
    while ((opt = getopt_long(argc, argv, "ABa:d:lh", CraftberryOptions, &optionIndex)) != -1) {
        switch (opt) {
        case 0:
            break;
        case 'A':
            interfaceSrc = optarg;
            break;
        case 'B':
            interfaceDst = optarg;
            break;
        case 'a':
            attackName = optarg;
            break;
        case 'd':
            defenseName = optarg;
            break;
        case 'l':
            listInterfaces();
            break;
        case 'h':
            help();
        default:
            help();
            exit(-1);
        }
    }

    PcapLiveDevice *devSrc;
    PcapLiveDevice *devDst;

    struct Details *d = new Details{attackName, "172.22.35.109", "127.0.0.1", devSrc, devDst};

    //DOC: inizializzazione
    init(d);
    //DOC: stampo informazioni dei device
    deviceInfo(d);
    //DOC: avvio la ricezione dei pacchetti
    devSrc->startCapture(callback, &d);
    cout << "working" << endl;

    //PCAP_SLEEP(10);
    while (1)
        ;
    //C.stopCapture();
}

void callback(RawPacket *inPacket, PcapLiveDevice *devSrc, void *details) {
    DEBUG("got a packet of " << inPacket->getRawDataLen() << " B from dev " << devSrc->getIPv4Address().toString() << endl);

    Attack *a;
    vector<RawPacket *> *pToSend;
    Details *d = (Details *)details;

    if (d->attackName.compare("DNS") == 0) {
        //C.DNSRobber({{"jafed.xyz", "pippo.pippo"}, {"www.jafed.xyz", "www.pippo.pippo"}});
    } else if (d->attackName.compare("TCPMULTIPLY") == 0) {
        //C.TCPmultiply(3);
    } else if (d->attackName.compare("UDPMULTIPLY") == 0) {
        a = new UdpMultiply();
    } else {
        help();
        exit(1);
    }

    sendPacket(a->craft(inPacket), (Details *)details);
}

//packetsContainer pakStat;

//Crafter::HTTPImageSubstitution(&parsedPacket);
/*
            Packet p = Crafter::multiplyTCP(parsedPacket);
            cout << "len 1" << parsedPacket.getFirstLayer()->getDataLen() << " bytes" << endl;
            cout << "len 2" << p.getFirstLayer()->getDataLen() << " bytes" << endl;
            */

//scorro tutti i layer
//int i = 0;
//for (Layer *curLayer = parsedPacket.getFirstLayer(); curLayer != NULL && i < 8; curLayer = curLayer->getNextLayer(), i++) {
//pakStat.add(curLayer);
// }
//cout << inPacket.getFrameLength() << endl;

//pakStat.printStats();

void help() {
    cout << "\nUsage: Craftberry options:\n"
            "-------------------------\n"
            " -A interface src -B interface dst { -a ATTACKNAME | -d DEFENSENAME }\n"
            "\nOptions:\n"
            "    -A interface src  : Use the specified source interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
            "    -B interface dst  : Use the specified destination interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
            "    -a                : Use the specified attack\n"
            "    -d                : Use the specified defence\n"
            "    -l                : Print the list of interfaces and exists\n"
            "    -h                : Displays this help message and exits\n"
            "\nATTACKNAME:\n"
            "    DNS            : description\n"
            "    HTTP           : description\n"
            "    HTTPIMAGE      : description\n"
            "    TCPMULTIPY     : description\n"
            "    UDPMULTIPY     : description\n"
            "\nDEFENSENAME:\n"
        //"    CHACHA20       : description\n"
        ;
    exit(0);
}

void listInterfaces() {
    // create the table
    cout << endl
         << "Network interfaces" << endl;
    TablePrinter printer({"Name", "IP address"}, {20, 20});

    const vector<PcapLiveDevice *> &devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    for (vector<PcapLiveDevice *>::const_iterator iter = devList.begin(); iter != devList.end(); iter++) {
        printer.printRow({(*iter)->getName(), (*iter)->getIPv4Address().toString()});
        //cout << (*iter)->getName() << "      " << (*iter)->getIPv4Address().toString() << endl;
        //printf("    -> Name: '%s'   IP address: %s\n", (*iter)->getName(), (*iter)->getIPv4Address().toString().c_str());
    }
    printer.printSeparator();

    exit(0);
}

void init(Details *d) {
    d->devSrc = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(d->interfaceSrc.c_str());
    d->devDst = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(d->interfaceDst.c_str());

    //DOC: ottengo il device
    if (d->devSrc == NULL || d->devDst == NULL) {
        cout << "Cannot find interface with IPv4 address of '" << d->interfaceSrc << "' or '" << d->interfaceDst << "'\n";
        exit(1);
    }
    //DOC: apro il device
    if (!d->devSrc->open() || !d->devDst->open()) {
        cout << "Cannot open the devices\n";
        exit(1);
    }
}

void sendPacket(vector<RawPacket *> *pToSend, Details *d) {
    int cont = 0;
    double size = 0;
    for (auto p : *pToSend) {
        if (!d->devSrc->sendPacket(*p)) {
            cout << "Couldn't send packet\n";
            exit(1);
        }
        cont++;
        size += p->getRawDataLen();
    }
    DEBUG("wrote " << cont << " packets for a total of " << size << " B" << endl);
}

void deviceInfo(Details *d) {
    cout << "Interface Src info:\n";
    cout << "   IP:                    " << d->devSrc->getIPv4Address().toString() << endl;
    cout << "   Interface name:        " << d->devSrc->getName() << endl;
    cout << "   Interface description: " << d->devSrc->getDesc() << endl;
    cout << "   MAC address:           " << d->devSrc->getMacAddress().toString() << endl;
    cout << "   Default gateway:       " << d->devSrc->getDefaultGateway().toString() << endl;
    cout << "   Interface MTU:         " << d->devSrc->getMtu() << endl;
    if (d->devSrc->getDnsServers().size() > 0)
        cout << "   DNS server:            " << d->devSrc->getDnsServers().at(0).toString() << endl;

    cout << "Interface Dst info:\n";
    cout << "   IP:                    " << d->devDst->getIPv4Address().toString() << endl;
    cout << "   Interface name:        " << d->devDst->getName() << endl;
    cout << "   Interface description: " << d->devDst->getDesc() << endl;
    cout << "   MAC address:           " << d->devDst->getMacAddress().toString() << endl;
    cout << "   Default gateway:       " << d->devDst->getDefaultGateway().toString() << endl;
    cout << "   Interface MTU:         " << d->devDst->getMtu() << endl;
    if (d->devDst->getDnsServers().size() > 0)
        cout << "   DNS server:            " << d->devDst->getDnsServers().at(0).toString() << endl;
}