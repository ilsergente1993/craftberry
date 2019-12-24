#pragma once

#include "Attack.cpp"
#include "arpa/inet.h"
#include "getopt.h"
#include "iostream"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PlatformSpecificUtils.h"
#include "pcapplusplus/TcpLayer.h"
#include "stdlib.h"

#include "DnsRobber.cpp"
#include "TcpMultiply.cpp"
#include "UdpMultiply.cpp"
#include "chacha20.hpp"

using namespace std;
using namespace pcpp;

struct Details {
public:
    double totalByteReceived{0};
    double totalPacketsReceived{0};
    double totalByteSent{0};
    double totalPacketsSent{0};

    string method;
    string intSrc;
    string intDst;
    pcpp::PcapLiveDevice *devSrc;
    pcpp::PcapLiveDevice *devDst;
    void *data;

    Details(string _method, string _interfaceSrc, string _interfaceDst) : data(0) {
        method = _method;
        devSrc = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp((intSrc = _interfaceSrc).c_str());
        devDst = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp((intDst = _interfaceDst).c_str());
        //DOC: ottengo il device
        if (devSrc == NULL || devDst == NULL) {
            cout << "Cannot find interface with IPv4 address of '" << intSrc << "' or '" << intDst << "'\n";
            exit(1);
        }
        //DOC: apro il device
        if (!devSrc->open() || !devDst->open()) {
            cout << "Cannot open the devices" << endl;
            exit(1);
        }
    };
    ~Details() {
        if (!devSrc->open() || !devDst->open()) {
            cout << "Cannot close what is not opened" << endl;
        }
        //d->devSrc->stopCapture(); ???
        //devSrc->close();
        // devDst->close();
        //free(devSrc);
        // free(devDst);
        // free(data);
        //delete devSrc;
        // delete devDst;
        // delete data;
        cout << "All is clean" << endl;
    }

    void toString() {
        cout << "0---------------------------------------------------------0" << endl;
        cout << "\tMethod:                " << method << endl;
        cout << "\tAddress Data:          " << data << endl;
        if (!devSrc->open() || !devDst->open()) {
            cout << "DevSrc or DevDst not opened" << endl;
            return;
        }
        cout << "Interface Src info:\n";
        cout << "\tIP:                    " << devSrc->getIPv4Address().toString() << endl;
        cout << "\tInterface name:        " << devSrc->getName() << endl;
        cout << "\tInterface description: " << devSrc->getDesc() << endl;
        cout << "\tMAC address:           " << devSrc->getMacAddress().toString() << endl;
        cout << "\tDefault gateway:       " << devSrc->getDefaultGateway().toString() << endl;
        cout << "\tInterface MTU:         " << devSrc->getMtu() << endl;
        if (devSrc->getDnsServers().size() > 0)
            cout << "\tDNS server:            " << devSrc->getDnsServers().at(0).toString() << endl;
        else
            cout << "\tDNS Servers:           0" << endl;

        cout << "Interface Dst info:\n";
        cout << "\tIP:                    " << devDst->getIPv4Address().toString() << endl;
        cout << "\tInterface name:        " << devDst->getName() << endl;
        cout << "\tInterface description: " << devDst->getDesc() << endl;
        cout << "\tMAC address:           " << devDst->getMacAddress().toString() << endl;
        cout << "\tDefault gateway:       " << devDst->getDefaultGateway().toString() << endl;
        cout << "\tInterface MTU:         " << devDst->getMtu() << endl;
        if (devDst->getDnsServers().size() > 0)
            cout << "\tDNS server:            " << devDst->getDnsServers().at(0).toString() << endl;
        else
            cout << "\tDNS Servers:           0" << endl;
    }
    void statistics() {
        cout << endl;
        cout << "   Packets received:      " << totalPacketsReceived << " (" << totalByteReceived << " bytes)" << endl;
        cout << "   Packets sent:          " << totalPacketsSent << " (" << totalByteSent << " bytes)" << endl;
    };

    static void sendPacket(vector<RawPacket *> *pToSend, Details *d) {
        int cont = 0;
        double size = 0;
        for (auto p : *pToSend) {
            if (!d->devDst->sendPacket(*p)) {
                cout << "1 packet skipped" << endl;
                //exit(1);
            } else {
                cont++;
                size += p->getRawDataLen();
            }
            d->totalByteSent += size;
            d->totalPacketsSent += cont;
        }
        DEBUG("-> " << cont << " packets (" << size << " B) to " << d->devDst->getIPv4Address().toString() << endl);
    }

    static void callback(RawPacket *inPacket, PcapLiveDevice *devSrc, void *details) {
        DEBUG("<- 1 packet (" << inPacket->getRawDataLen() << " B) from dev " << devSrc->getIPv4Address().toString() << endl);
        vector<RawPacket *> *pToSend;
        Details *d = (Details *)details;
        d->totalByteReceived += inPacket->getRawDataLen();
        d->totalPacketsReceived++;

        if (d->method.compare("BEQUITE") == 0) {
            pToSend = new vector<RawPacket *>();
            pToSend->push_back(inPacket);
            Details::sendPacket(pToSend, d);
            return;
        }

        if (d->method.compare("UDPMULTIPLY") == 0) {
            UdpMultiply attack;
            pToSend = attack.craft(inPacket);
            if (pToSend->size() > 0) {
                Details::sendPacket(pToSend, d);
                return;
            }
        }

        if (d->method.compare("TCPMULTIPLY") == 0) {
            TcpMultiply attack;
            pToSend = attack.craft(inPacket);
            if (pToSend->size() > 0) {
                Details::sendPacket(pToSend, d);
                return;
            }
        }

        if (d->method.compare("CHACHA20") == 0) {
            // Initialize lookup table
            for (int i = 0; i < 10; i++)
                ChaChaMi::char_to_uint[i + '0'] = i;
            for (int i = 0; i < 26; i++)
                ChaChaMi::char_to_uint[i + 'a'] = i + 10;
            for (int i = 0; i < 26; i++)
                ChaChaMi::char_to_uint[i + 'A'] = i + 10;

            // From rfc7539.txt
            ChaChaMi::test_crypt("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586", 0);
            ChaChaMi::test_crypt("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000002", "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f", "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221", 1);
            ChaChaMi::test_crypt("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", "0000000000000002", "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e", "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1", 42);
            ChaChaMi::test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
            ChaChaMi::test_keystream("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000", "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963");
            ChaChaMi::test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000001", "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3");
            ChaChaMi::test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0100000000000000", "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b");
            ChaChaMi::test_keystream("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "0001020304050607", "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9");

            ChaChaMi::test_encrypt_decrypt(3934073876);

            puts("Success! Tests passed.");

            TcpMultiply attack;
            pToSend = attack.craft(inPacket);
            if (pToSend->size() > 0) {
                Details::sendPacket(pToSend, d);
                return;
            }
        }
    }
};