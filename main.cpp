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

static struct option CraftberryOptions[] =
    {{"interfac_src", required_argument, 0, 'A'},
     {"interface_dst", required_argument, 0, 'B'},
     {"attack", required_argument, 0, 'a'},
     {"defense", required_argument, 0, 'd'},
     {"timeout", required_argument, 0, 't'},
     {"list-interfaces", no_argument, 0, 'l'},
     {"help", no_argument, 0, 'h'},
     {0, 0, 0, 0}};

void help();
//static void callback(RawPacket *, PcapLiveDevice *, void *);
void listInterfaces();
struct Details *gd;

void ctrlc(int s) {
    printf("\nOoooops got ctrl+c signal (%d)\nHere a summary of what happened:", s);
    gd->statistics();
    delete gd;
    cout << "bye bye" << endl;
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
    string attackName = "", defenseName = "";
    int optionIndex = 0, timeout = 0;
    char opt = 0;
    //':' significa che si aspetta degli argomenti
    while ((opt = getopt_long(argc, argv, "A:B:a:d:t:lh", CraftberryOptions, &optionIndex)) != -1) {
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

    if (attackName.length() > 0 && defenseName.length() > 0) {
        cout << "Dude, attack or defence. Just decide!" << endl;
        exit(1);
    }
    gd = new Details{attackName.length() > 0 ? attackName : defenseName, interfaceSrc, interfaceDst}; //"172.28.46.141", "192.168.50.5"
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
        gd->statistics();
    }

    delete gd;
    return 0;
}

void help() {
    cout << "\nUsage: Craftberry options:\n"
            "-------------------------\n"
            " -A interface_src -B interface_dst { -a ATTACKNAME | -d DEFENSENAME }\n"
            "\nOptions:\n"
            "    -A interface src  : Use the specified source interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
            "    -B interface dst  : Use the specified destination interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
            "    -a                : Use the specified attack\n"
            "    -d                : Use the specified defence\n"
            "    -t                : Use the specified timeout in seconds, if not defined it runs until some external signal stops the execution (e.g. ctrl+c)\n"
            "    -l                : Print the list of interfaces and exists\n"
            "    -h                : Displays this help message and exits\n"
            "\nATTACKNAME:\n"
            "    BEQUITE        : just replying all the traffic from src to dst\n"
            "    DNS            : catch the DNS queries and replace its value\n"
            "    HTTP           : description\n"
            "    HTTPIMAGE      : description\n"
            "    TCPMULTIPY     : multiply N times every tcp packet to dst\n"
            "    UDPMULTIPY     : multiply N times every udp packet to dst\n"
            "\nDEFENSENAME:\n"
            "    CHACHA20       : description\n";
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