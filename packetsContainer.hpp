
#include "iostream"
#include "pcapplusplus/Packet.h"

using namespace std;
using namespace pcpp;

class packetsContainer {
public:
    int osiPackets[8];
    int ARPpackets;
    int ICMPpackets;
    int DNSpackets;
    int HTTPpackets;
    int SSLpackets;
    packetsContainer() {
        for (int i = 0; i < 8; i++)
            osiPackets[i] = 0;
        ARPpackets = 0;
        ICMPpackets = 0;
        DNSpackets = 0;
        HTTPpackets = 0;
        SSLpackets = 0;
    }

public:
    void add(Layer *p) {
        switch (p->getProtocol()) {
        case ARP:
            this->ARPpackets++;
            break;
        case ICMP:
            this->ICMPpackets++;
            break;
        case DNS:
            this->DNSpackets++;
            break;
        case HTTPRequest:
            this->HTTPpackets++;
            break;
        case SSL:
            this->SSLpackets++;
            break;
        default:
            break;
        }
        this->osiPackets[p->getOsiModelLayer() - 1]++;
    }
    void printStats() {
        cout << "ARP: " << this->ARPpackets << endl;
        cout << "ICMP: " << this->ICMPpackets << endl;
        cout << "DNS: " << this->DNSpackets << endl;
        cout << "HTTP: " << this->HTTPpackets << endl;
        cout << "SSL: " << this->SSLpackets << endl;
        for (int i = 0; i < 8; i++)
            cout << "Layer " << i + 1 << ": " << this->osiPackets[i] << endl;
    }
};