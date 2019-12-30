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

#include "Details.cpp"
//#include "packetsContainer.hpp"

using namespace std;
using namespace pcpp;

//DOC: struct to storage the usage options for the CLI
static struct option CraftberryOptions[] =
    {{"interfac_src", required_argument, 0, 'A'},
     {"interface_dst", required_argument, 0, 'B'},
     {"action", required_argument, 0, 'a'},
     {"timeout", required_argument, 0, 't'},
     {"list-interfaces", no_argument, 0, 'l'},
     {"help", no_argument, 0, 'h'},
     {0, 0, 0, 0}};

void ctrlc(int);
void help();
void listInterfaces();
struct Details *gd;

//DOC: handler function to manage external signals
void ctrlc(int s) {
    cerr << "\nOoooops got ctrl+c signal (" << s << ")\nHere a summary of what happened:";
    gd->summary();
    delete gd;
    cout << "bye bye\n";
    exit(1);
}

int main(int argc, char *argv[]) {
    //DOC: setup for ctrl+c signal
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = ctrlc;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    string interfaceSrc = "", interfaceDst = "";
    string action = "BEQUITE";
    int optionIndex = 0, timeout = 0;
    char opt = 0;
    //':' => significa che si aspetta degli argomenti
    while ((opt = getopt_long(argc, argv, "A:B:a:t:lh", CraftberryOptions, &optionIndex)) != -1) {
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
            action = optarg;
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        case 'l':
            listInterfaces();
            exit(-1);
        case 'h':
        default:
            help();
            exit(-1);
        }
    }

    if (action.length() <= 0) {
        cout << "Dude, let's do some action!" << endl;
        exit(1);
    }
    gd = new Details{action, interfaceSrc, interfaceDst}; //"172.28.46.141", "192.168.50.5"
    gd->toString();

    //DOC: start packet capturing
    gd->devSrc->startCapture(Details::callback, gd);
    if (timeout == 0) {
        cout << "Working in infinite mode, press ctrl+c to exit..." << endl;
        while (1) {
            //DOC: I quit when someone press ctrl+c
        };
    } else {
        while (--timeout >= 0) {
            PCAP_SLEEP(1);
            if (timeout > 0)
                cout << timeout << " seconds left" << endl;
        };
        cout << "Finished" << endl;
        gd->summary();
    }

    delete gd;
    return 0;
}

void help() {
    cout << "\nUsage: Craftberry options:\n"
            "-------------------------\n"
            " -A interface_src -B interface_dst -a [ ATTACK | DEFENSE ]\n"
            "\nOptions:\n"
            "    -A            : Use the specified source interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
            "    -B            : Use the specified destination interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
            "    -a            : Use the specified action\n"
            "    -t            : Use the specified timeout in seconds, if not defined it runs until some external signal stops the execution (e.g. ctrl+c)\n"
            "    -l            : Print the list of interfaces and exists\n"
            "    -h            : Displays this help message and exits\n"
            "\nActions:\n"
            "   - default:\n"
            "       BEQUITE    : just replying all the traffic from src to dst\n"
            "   - ATTACK:\n"
            "       DNS        : catch the DNS queries and replace its value\n"
            "       HTTP       : description\n"
            "       HTTPIMAGE  : description\n"
            "       TCPMULTIPY : multiply N times every tcp packet to dst\n"
            "       UDPMULTIPY : multiply N times every udp packet to dst\n"
            "   - DEFENSE:\n"
            "       CHACHA20   : encrypt all the outgoing traffic and decrypt all the ingoing traffic\n";
    exit(0);
}

void listInterfaces() {
    cout << "Network interfaces" << endl;
    pcpp::TablePrinter printer({"Name", "IP address"}, {20, 20});
    const vector<PcapLiveDevice *> &devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    for (vector<PcapLiveDevice *>::const_iterator iter = devList.begin(); iter != devList.end(); iter++) {
        printer.printRow({(*iter)->getName(), (*iter)->getIPv4Address().toString()});
        //TODO: stampa solo il primo indirizzo, il codice seguente deve essere corretto
        // const vector<pcap_addr_t> &addresses = (*iter)->getAddresses();
        // for (vector<pcap_addr_t>::const_iterator addr = addresses.begin(); addr != addresses.end(); addr++) {
        //     printer.printRow({(*iter)->getName(), string(addr->addr->sa_data)});
        // }
    }
}