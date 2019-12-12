#include "fstream"
#include "iostream"
#include "pcapplusplus/DnsLayer.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"
#include "pcapplusplus/VlanLayer.h"
#include "stdlib.h"
#include "string.h"

using namespace std;
using namespace pcpp;

class Crafter {
private:
    IFileReaderDevice *input;
    PcapNgFileWriterDevice *output;

public:
    Crafter(IFileReaderDevice *input, PcapNgFileWriterDevice *output) {
        this->input = input;
        this->output = output;
    };
    //LEV 2
    void VLANDoubleTagging();
    //LEV 4
    void multiplyTCP(int n) {
        if (n < 0)
            return;
        RawPacket inPacket;
        while (this->input->getNextPacket(inPacket)) {
            Packet parsedPacket(&inPacket);
            if (!parsedPacket.isPacketOfType(ProtocolType::TCP))
                continue;
            for (int i = 0; i < n; i++)
                this->output->writePacket(inPacket);
        }
    };
    void multiplyUDP(int n){};
    //LEV 5
    static void HTTPImageSubstitution(Packet packet) {
        //NOTE: non riesco a prendere l'immagine perchè è suddivisa su più frame e devo prima ricostruire i pacchetti tcp
        //vedi: https://github.com/seladb/PcapPlusPlus/blob/master/Examples/TcpReassembly/main.cpp
        HttpResponseLayer *response = packet.getLayerOfType<HttpResponseLayer>();
        if (response == NULL)
            return;

        if (response->getFirstLine()->getStatusCodeAsInt() == 200) {
            ofstream image;
            image.open("passport.jpg", ios::binary);

            cout << "got 200 HTTP packet: " << response->getFirstLine()->getStatusCodeString() << endl;
            cout << response->getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD)->getFieldValue() << " bytes" << endl;
            uint8_t *p = response->getData();
            cout << "LEN: " << response->getDataLen() << " bytes" << endl;
            cout << "LEN: " << response->getHeaderLen() << " bytes" << endl;
            cout << response->getDataPtr(0) << endl;
            cout << "size: " << response->getLayerPayloadSize() << " bytes" << endl;
            image << response->getLayerPayload(); //è il puntatore al primo byte della stringa
            cout << response->getLayerPayload() << endl;
            image.close();
        }
    };

    void HTTPContentCatcher(){};

    //map di sostituzioni <from,to>
    void DNSRobber(map<string, string> substitutions) {
        RawPacket inPacket;
        while (this->input->getNextPacket(inPacket)) {
            Packet parsedPacket(&inPacket);
            DnsLayer *response = parsedPacket.getLayerOfType<DnsLayer>();
            if (response == NULL)
                continue;
            DnsQuery *q;
            if ((q = response->getFirstQuery()) == NULL)
                continue;
            do {
                cout << q->getName();

                for (auto &x : substitutions) {
                    //cout << x.first << ", " << x.second << endl;
                    if (q->getName().compare(x.first) == 0 && q->setName(x.second))
                        cout << " --> " << x.second;
                }

                //if (q->getName().compare(from) == 0 && q->setName(to)) {
                //    cout << " --> " << to;
                //}
            } while ((q = response->getNextQuery(q)) != NULL);
            cout << endl;

            parsedPacket.computeCalculateFields();
            this->output->writePacket(*parsedPacket.getRawPacket());
        }
    };

    void getOutputStats() {
        // create the stats object
        pcap_stat stats;
        this->output->getStatistics(stats);
        cout << "Written " << stats.ps_recv << " packets successfully to pcap-ng writer and " << stats.ps_drop << " packets could not be written\n";
    }
};