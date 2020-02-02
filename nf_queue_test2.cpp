#include <array>
#include <functional>
#include <linux/netfilter.h>
#include <memory>
//#include <netinet/in.h>
//#include <netinet/ip.h>
//#include <netinet/tcp.h>
#include <unistd.h>

extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/pktbuff.h>
}

#define THROW_IF_TRUE(x, m)              \
    do {                                 \
        if ((x)) {                       \
            throw std::runtime_error(m); \
        }                                \
    } while (false)

#define CONCAT_0(pre, post) pre##post
#define CONCAT_1(pre, post) CONCAT_0(pre, post)
#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)

using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;
#define SCOPED_GUARD_NAMED(name, code)                                            \
    ScopedGuard name(reinterpret_cast<void *>(-1), [&](void *) -> void { code }); \
    (void)name
#define SCOPED_GUARD(code) SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code)

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    ASSERT(ph == nullptr, "Issue while packet header");

    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(nfad, &rawData);
    ASSERT(len < 0, "Can\'t get payload data");

    struct pkt_buff *pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
    ASSERT(pkBuff == nullptr, "Issue while pktb allocate");
    SCOPED_GUARD(pktb_free(pkBuff);); // Don't forget to clean up

    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
    ASSERT(ip == nullptr, "Issue while ipv4 header parse.");

    ASSERT(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can\'t set transport header.");

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
        ASSERT(tcp == nullptr, "Issue while tcp header.");

        void *payload = nfq_tcp_get_payload(tcp, pkBuff);
        unsigned int payloadLen = nfq_tcp_get_payload_len(tcp, pkBuff);
        payloadLen -= 4 * tcp->th_off;
        ASSERT(payload == nullptr, "Issue while payload.");

        for (unsigned int i = 0; i < payloadLen / 2; ++i) {
            char tmp = (static_cast<char *>(payload))[i];
            (static_cast<char *>(payload))[i] = (static_cast<char *>(payload))[payloadLen - 1 - i];
            (static_cast<char *>(payload))[payloadLen - 1 - i] = tmp;
        }

        nfq_tcp_compute_checksum_ipv4(tcp, ip);
        return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
    }
    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
}

int main() {
    struct nfq_handle *handler = nfq_open();
    ASSERT(handler == nullptr, "Can\'t open hfqueue handler.");
    SCOPED_GUARD(nfq_close(handler);); // Don’t forget to clean up

    struct nfq_q_handle *queue = nfq_create_queue(handler, 0, netfilterCallback, nullptr);
    ASSERT(queue == nullptr, "Can\'t create queue handler.");
    SCOPED_GUARD(nfq_destroy_queue(queue);); // Do not forget to clean up

    ASSERT(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.");

    int fd = nfq_fd(handler);
    std::array<char, 0x10000> buffer;
    for (;;) {
        int len = read(fd, buffer.data(), buffer.size());
        ASSERT(len < 0, "Issue while read");
        nfq_handle_packet(handler, buffer.data(), len);
    }
    return 0;
}
