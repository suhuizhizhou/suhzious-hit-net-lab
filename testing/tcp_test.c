#include <stdio.h>
#include <string.h>
#include "tcp.h"
#include "ip.h"

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "TCP test failed at line %d: %s\n", __LINE__, #condition); \
    exit(1); \
} } while (0)

uint8_t net_if_mac[NET_MAC_LEN] = NET_IF_MAC;
uint8_t net_if_ip[NET_IP_LEN] = NET_IF_IP;
buf_t rxbuf, txbuf;

static buf_t output[16];
static uint8_t output_ip[16][NET_IP_LEN];
static size_t output_count;
static size_t callback_count;
static const uint8_t peer_ip[NET_IP_LEN] = {192, 168, 163, 10};

static uint32_t swap32(uint32_t value)
{
    return ((value & 0x000000ffU) << 24) |
           ((value & 0x0000ff00U) << 8) |
           ((value & 0x00ff0000U) >> 8) |
           ((value & 0xff000000U) >> 24);
}

static uint32_t checksum_add(uint32_t sum, const uint8_t *data, size_t len)
{
    while (len > 1)
    {
        sum += ((uint16_t)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }
    if (len)
        sum += (uint16_t)data[0] << 8;
    return sum;
}

static uint16_t segment_checksum(buf_t *buf, const uint8_t *src_ip, const uint8_t *dst_ip)
{
    uint8_t pseudo[12] = {0};
    uint32_t sum = 0;
    memcpy(pseudo, src_ip, NET_IP_LEN);
    memcpy(pseudo + NET_IP_LEN, dst_ip, NET_IP_LEN);
    pseudo[9] = NET_PROTOCOL_TCP;
    pseudo[10] = (uint8_t)(buf->len >> 8);
    pseudo[11] = (uint8_t)buf->len;
    sum = checksum_add(sum, pseudo, sizeof(pseudo));
    sum = checksum_add(sum, buf->data, buf->len);
    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)~sum;
}

static void make_segment(buf_t *buf, uint16_t src_port, uint16_t dst_port,
                         uint32_t seq, uint32_t ack, uint8_t flags,
                         const uint8_t *data, size_t len)
{
    buf_init(buf, len);
    if (len)
        memcpy(buf->data, data, len);
    buf_add_header(buf, sizeof(tcp_hdr_t));
    tcp_hdr_t *hdr = (tcp_hdr_t *)buf->data;
    memset(hdr, 0, sizeof(tcp_hdr_t));
    hdr->src_port16 = swap16(src_port);
    hdr->dst_port16 = swap16(dst_port);
    hdr->seq32 = swap32(seq);
    hdr->ack32 = swap32(ack);
    hdr->data_offset = TCP_DATA_OFFSET(sizeof(tcp_hdr_t));
    hdr->flags = flags;
    hdr->window16 = swap16(TCP_DEFAULT_WINDOW);
    hdr->checksum16 = swap16(segment_checksum(buf, peer_ip, net_if_ip));
}

void net_add_protocol(uint16_t protocol, net_handler_t handler)
{
    (void)protocol;
    (void)handler;
}

void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    CHECK(protocol == NET_PROTOCOL_TCP);
    CHECK(output_count < 16);
    buf_copy(&output[output_count], buf, 0);
    memcpy(output_ip[output_count], ip, NET_IP_LEN);
    output_count++;
}

static void echo_handler(uint8_t *data, size_t len, uint8_t *src_ip, uint16_t src_port)
{
    callback_count++;
    CHECK(len == 5);
    CHECK(memcmp(data, "hello", 5) == 0);
    CHECK(src_port == 50000);
    CHECK(memcmp(src_ip, peer_ip, NET_IP_LEN) == 0);
    CHECK(tcp_send(data, (uint16_t)len, 60001, src_ip, src_port) == 0);
}

int main(void)
{
    buf_t input;
    tcp_init();
    CHECK(tcp_listen(60001, echo_handler) == 0);

    make_segment(&input, 50000, 60001, 100, 0, TCP_FLAG_SYN, NULL, 0);
    tcp_in(&input, (uint8_t *)peer_ip);
    CHECK(output_count == 1);
    tcp_hdr_t *syn_ack = (tcp_hdr_t *)output[0].data;
    CHECK(syn_ack->flags == (TCP_FLAG_SYN | TCP_FLAG_ACK));
    CHECK(swap32(syn_ack->ack32) == 101);
    CHECK(segment_checksum(&output[0], net_if_ip, peer_ip) == 0);
    uint32_t server_isn = swap32(syn_ack->seq32);

    tcp_in(&input, (uint8_t *)peer_ip);
    CHECK(output_count == 2);
    CHECK(swap32(((tcp_hdr_t *)output[1].data)->seq32) == server_isn);

    make_segment(&input, 50000, 60001, 101, server_isn + 1, TCP_FLAG_ACK, NULL, 0);
    tcp_in(&input, (uint8_t *)peer_ip);
    CHECK(output_count == 2);

    make_segment(&input, 50000, 60001, 101, server_isn + 1,
                 TCP_FLAG_ACK | TCP_FLAG_PSH, (const uint8_t *)"hello", 5);
    tcp_in(&input, (uint8_t *)peer_ip);
    CHECK(callback_count == 1);
    CHECK(output_count == 4);
    tcp_hdr_t *echo = (tcp_hdr_t *)output[3].data;
    CHECK(echo->flags == (TCP_FLAG_ACK | TCP_FLAG_PSH));
    CHECK(swap32(echo->seq32) == server_isn + 1);
    CHECK(swap32(echo->ack32) == 106);
    CHECK(segment_checksum(&output[3], net_if_ip, peer_ip) == 0);
    CHECK(memcmp(output[3].data + sizeof(tcp_hdr_t), "hello", 5) == 0);

    make_segment(&input, 50000, 60001, 106, server_isn + 6,
                 TCP_FLAG_ACK | TCP_FLAG_FIN, NULL, 0);
    tcp_in(&input, (uint8_t *)peer_ip);
    CHECK(output_count == 5);
    tcp_hdr_t *fin_ack = (tcp_hdr_t *)output[4].data;
    CHECK(fin_ack->flags == (TCP_FLAG_FIN | TCP_FLAG_ACK));
    CHECK(swap32(fin_ack->ack32) == 107);

    make_segment(&input, 50000, 60001, 107, server_isn + 7, TCP_FLAG_ACK, NULL, 0);
    tcp_in(&input, (uint8_t *)peer_ip);
    CHECK(tcp_send((uint8_t *)"x", 1, 60001, (uint8_t *)peer_ip, 50000) == -1);

    make_segment(&input, 50000, 60002, 200, 0, TCP_FLAG_SYN, NULL, 0);
    tcp_in(&input, (uint8_t *)peer_ip);
    CHECK(output_count == 6);
    CHECK(((tcp_hdr_t *)output[5].data)->flags == (TCP_FLAG_RST | TCP_FLAG_ACK));

    printf("TCP state machine test passed.\n");
    return 0;
}
