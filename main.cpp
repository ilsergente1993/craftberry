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
    IFileReaderDevice *reader = IFileReaderDevice::getReader("captures/big.pcapng");
    if (reader == NULL) {
        printf("Cannot determine reader for file type\n");
        exit(1);
    }
    if (!reader->open()) {
        printf("Cannot open input.pcap for reading\n");
        exit(1);
    }

    //lettura del pacchetto
    RawPacket rawPacket;
    packetsContainer pakStat;
    //scorro tutti i pacchetti
    while (reader->getNextPacket(rawPacket)) {
        Packet parsedPacket(&rawPacket);

        Crafter::HTTPImageSubstitution(&parsedPacket);

        //scorro tutti i layer
        /*int i = 0;
        for (Layer *curLayer = parsedPacket.getFirstLayer(); curLayer != NULL && i < 8; curLayer = curLayer->getNextLayer(), i++) {
            pakStat.add(curLayer);
        }*/
    }

    pakStat.printStats();
    //chiusura del file
    reader->close();
}