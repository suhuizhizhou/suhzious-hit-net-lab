#ifndef TCP_H
#define TCP_H

#include "net.h"

#pragma pack(1)
typedef struct tcp_hdr
{
    uint16_t src_port16;
    uint16_t dst_port16;
    uint32_t seq32;
    uint32_t ack32;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window16;
    uint16_t checksum16;
    uint16_t urgent16;
} tcp_hdr_t;

typedef struct tcp_key
{
    uint16_t local_port;
    uint8_t remote_ip[NET_IP_LEN];
    uint16_t remote_port;
} tcp_key_t;
#pragma pack()

#define TCP_HDR_MIN_LEN 20
#define TCP_DATA_OFFSET(len) ((uint8_t)((len) / 4U << 4))
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_DEFAULT_WINDOW 65535

typedef void (*tcp_handler_t)(uint8_t *data, size_t len, uint8_t *src_ip, uint16_t src_port);

void tcp_init(void);
void tcp_in(buf_t *buf, uint8_t *src_ip);
int tcp_listen(uint16_t port, tcp_handler_t handler);
void tcp_unlisten(uint16_t port);
int tcp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port);
int tcp_close(uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port);

#endif
