#include "arpa/inet.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/TcpLayer.h"
#include "stdlib.h"

#include "crafter.hpp"
#include "packetsContainer.hpp"

using namespace std;
using namespace pcpp;

int main(/*int argc, char *argv[]*/) {
    //apertura del file
    string filename = "2_mix";
    IFileReaderDevice *input = IFileReaderDevice::getReader(("captures/" + filename + ".pcap").c_str());
    if (input == NULL) {
        printf("Cannot determine input for file type\n");
        exit(1);
    }
    if (!input->open()) {
        printf("Cannot open the input file for reading\n");
        exit(1);
    }

    //lettura del pacchetto
    RawPacket rawPacket;
    packetsContainer pakStat;
    PcapNgFileWriterDevice output(("captures/" + filename + "_out.pcapng").c_str());
    output.open();

    //scorro tutti i pacchetti
    while (input->getNextPacket(rawPacket)) {
        // output.writePacket(rawPacket);
        // continue;

        Packet parsedPacket(&rawPacket);
        //cout << parsedPacket.toString() << endl;

        if (parsedPacket.isPacketOfType(ProtocolType::TCP)) {
            output.writePacket(rawPacket);
            output.writePacket(rawPacket);
        }

        //Crafter::HTTPImageSubstitution(&parsedPacket);
        /*
        Packet p = Crafter::multiplyTCP(parsedPacket);
        cout << "len 1" << parsedPacket.getFirstLayer()->getDataLen() << " bytes" << endl;
        cout << "len 2" << p.getFirstLayer()->getDataLen() << " bytes" << endl;
        */

        //scorro tutti i layer
        int i = 0;
        for (Layer *curLayer = parsedPacket.getFirstLayer(); curLayer != NULL && i < 8; curLayer = curLayer->getNextLayer(), i++) {
            pakStat.add(curLayer);
        }
    }

    //pakStat.printStats();
    //chiusura del file
    output.close();
    input->close();
}