#include "arpa/inet.h"
#include "getopt.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/TablePrinter.h"
#include "pcapplusplus/TcpLayer.h"
#include "stdlib.h"

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

void help();
void listInterfaces();

int main(int argc, char *argv[]) {
    string interfaceSrc = "", interfaceDst = "";
    string attackName = "", defenseName = "";
    int optionIndex = 0;
    char opt = 0;
    //cout << argc << " = " << argv[0] << argv[1] << endl;
    while ((opt = getopt_long(argc, argv, "ABa:d:lh", CraftberryOptions, &optionIndex)) != -1) {
        //cout << " -- > " << opt << endl;
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

    //DOC: apertura del file
    string filename = "tcpmult_01"; //"dns_01";
    IFileReaderDevice *input = IFileReaderDevice::getReader(("captures/" + filename + ".pcap").c_str());
    PcapNgFileWriterDevice *output = new PcapNgFileWriterDevice(("captures/" + filename + "_out.pcapng").c_str());

    if (input == NULL || !input->open()) {
        cout << "Cannot open the input file for reading or cannot determine input for file type\n";
        exit(1);
    }
    if (!output->open()) {
        cout << "Cannot open the output file\n";
        exit(1);
    }
    Crafter C(input, output);

    if (attackName.compare("DNS") == 0) {
        C.DNSRobber({{"jafed.xyz", "pippo.pippo"}, {"www.jafed.xyz", "www.pippo.pippo"}});
    } else if (attackName.compare("TCPMULTIPLY") == 0) {
        C.multiplyTCP(3);
    } else {
        help();
        exit(1);
    }

    C.getOutputStats();
    //chiusura dei file
    output->close();
    input->close();
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
