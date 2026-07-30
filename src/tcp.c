#include <time.h>
#include "tcp.h"
#include "ip.h"

typedef enum tcp_state
{
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSING,
    TCP_STATE_LAST_ACK
} tcp_state_t;

typedef struct tcp_connection
{
    tcp_state_t state;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    tcp_handler_t handler;
} tcp_connection_t;

static map_t tcp_listeners;
static map_t tcp_connections;
static uint32_t tcp_next_isn;

static uint32_t tcp_swap32(uint32_t value)
{
    return ((value & 0x000000ffU) << 24) |
           ((value & 0x0000ff00U) << 8) |
           ((value & 0x00ff0000U) >> 8) |
           ((value & 0xff000000U) >> 24);
}

static uint32_t tcp_checksum_add(uint32_t sum, const uint8_t *data, size_t len)
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

static uint16_t tcp_checksum(buf_t *buf, const uint8_t *src_ip, const uint8_t *dst_ip)
{
    uint8_t pseudo_hdr[12] = {0};
    uint32_t sum = 0;

    memcpy(pseudo_hdr, src_ip, NET_IP_LEN);
    memcpy(pseudo_hdr + NET_IP_LEN, dst_ip, NET_IP_LEN);
    pseudo_hdr[9] = NET_PROTOCOL_TCP;
    pseudo_hdr[10] = (uint8_t)(buf->len >> 8);
    pseudo_hdr[11] = (uint8_t)buf->len;

    sum = tcp_checksum_add(sum, pseudo_hdr, sizeof(pseudo_hdr));
    sum = tcp_checksum_add(sum, buf->data, buf->len);
    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)~sum;
}

static tcp_key_t tcp_make_key(uint16_t local_port, const uint8_t *remote_ip, uint16_t remote_port)
{
    tcp_key_t key;
    key.local_port = local_port;
    memcpy(key.remote_ip, remote_ip, NET_IP_LEN);
    key.remote_port = remote_port;
    return key;
}

static int tcp_out(const tcp_key_t *key, uint32_t seq, uint32_t ack,
                   uint8_t flags, const uint8_t *data, size_t len)
{
    if (buf_init(&txbuf, len) < 0)
        return -1;
    if (len)
        memcpy(txbuf.data, data, len);
    if (buf_add_header(&txbuf, sizeof(tcp_hdr_t)) < 0)
        return -1;

    tcp_hdr_t *hdr = (tcp_hdr_t *)txbuf.data;
    memset(hdr, 0, sizeof(tcp_hdr_t));
    hdr->src_port16 = swap16(key->local_port);
    hdr->dst_port16 = swap16(key->remote_port);
    hdr->seq32 = tcp_swap32(seq);
    hdr->ack32 = tcp_swap32(ack);
    hdr->data_offset = TCP_DATA_OFFSET(sizeof(tcp_hdr_t));
    hdr->flags = flags;
    hdr->window16 = swap16(TCP_DEFAULT_WINDOW);
    hdr->checksum16 = swap16(tcp_checksum(&txbuf, net_if_ip, key->remote_ip));

    ip_out(&txbuf, (uint8_t *)key->remote_ip, NET_PROTOCOL_TCP);
    return 0;
}

static void tcp_reset(const tcp_key_t *key, uint32_t seq, uint32_t ack,
                      uint8_t incoming_flags, size_t segment_len)
{
    if (incoming_flags & TCP_FLAG_RST)
        return;
    if (incoming_flags & TCP_FLAG_ACK)
        tcp_out(key, ack, 0, TCP_FLAG_RST, NULL, 0);
    else
        tcp_out(key, 0, seq + (uint32_t)segment_len,
                TCP_FLAG_RST | TCP_FLAG_ACK, NULL, 0);
}

void tcp_in(buf_t *buf, uint8_t *src_ip)
{
    if (buf->len < sizeof(tcp_hdr_t))
        return;

    tcp_hdr_t *hdr = (tcp_hdr_t *)buf->data;
    size_t hdr_len = (size_t)(hdr->data_offset >> 4) * 4U;
    if (hdr_len < sizeof(tcp_hdr_t) || hdr_len > buf->len)
        return;
    if (tcp_checksum(buf, src_ip, net_if_ip) != 0)
        return;

    uint16_t src_port = swap16(hdr->src_port16);
    uint16_t dst_port = swap16(hdr->dst_port16);
    uint32_t seq = tcp_swap32(hdr->seq32);
    uint32_t ack = tcp_swap32(hdr->ack32);
    uint8_t flags = hdr->flags;
    size_t data_len = buf->len - hdr_len;
    size_t sequence_len = data_len + !!(flags & TCP_FLAG_SYN) + !!(flags & TCP_FLAG_FIN);
    tcp_key_t key = tcp_make_key(dst_port, src_ip, src_port);
    tcp_connection_t *connection = map_get(&tcp_connections, &key);

    if (!connection)
    {
        tcp_handler_t *listener = map_get(&tcp_listeners, &dst_port);
        if (!(flags & TCP_FLAG_SYN) || (flags & TCP_FLAG_ACK) || !listener)
        {
            tcp_reset(&key, seq, ack, flags, sequence_len);
            return;
        }

        tcp_connection_t new_connection = {
            .state = TCP_STATE_SYN_RECEIVED,
            .snd_nxt = tcp_next_isn + 1,
            .rcv_nxt = seq + 1,
            .handler = *listener
        };
        tcp_next_isn += 64000;
        if (map_set(&tcp_connections, &key, &new_connection) < 0)
            return;
        tcp_out(&key, new_connection.snd_nxt - 1, new_connection.rcv_nxt,
                TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);
        return;
    }

    if (flags & TCP_FLAG_RST)
    {
        map_delete(&tcp_connections, &key);
        return;
    }

    if (connection->state == TCP_STATE_SYN_RECEIVED)
    {
        if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK) && seq + 1 == connection->rcv_nxt)
        {
            tcp_out(&key, connection->snd_nxt - 1, connection->rcv_nxt,
                    TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);
            return;
        }
        if ((flags & TCP_FLAG_ACK) && ack == connection->snd_nxt && seq == connection->rcv_nxt)
            connection->state = TCP_STATE_ESTABLISHED;
        else
            tcp_reset(&key, seq, ack, flags, sequence_len);
        return;
    }

    if ((connection->state == TCP_STATE_FIN_WAIT_1 || connection->state == TCP_STATE_LAST_ACK) &&
        (flags & TCP_FLAG_ACK) && ack == connection->snd_nxt)
    {
        if (connection->state == TCP_STATE_LAST_ACK)
        {
            map_delete(&tcp_connections, &key);
            return;
        }
        connection->state = TCP_STATE_FIN_WAIT_2;
    }
    else if (connection->state == TCP_STATE_CLOSING &&
             (flags & TCP_FLAG_ACK) && ack == connection->snd_nxt)
    {
        map_delete(&tcp_connections, &key);
        return;
    }

    if (!sequence_len)
        return;
    if (seq != connection->rcv_nxt)
    {
        tcp_out(&key, connection->snd_nxt, connection->rcv_nxt, TCP_FLAG_ACK, NULL, 0);
        return;
    }

    connection->rcv_nxt += (uint32_t)sequence_len;

    if (data_len && connection->state == TCP_STATE_ESTABLISHED)
    {
        uint8_t *data = buf->data + hdr_len;
        tcp_out(&key, connection->snd_nxt, connection->rcv_nxt, TCP_FLAG_ACK, NULL, 0);
        connection->handler(data, data_len, src_ip, src_port);
    }

    if (flags & TCP_FLAG_FIN)
    {
        if (connection->state == TCP_STATE_ESTABLISHED)
        {
            tcp_out(&key, connection->snd_nxt, connection->rcv_nxt,
                    TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
            connection->snd_nxt++;
            connection->state = TCP_STATE_LAST_ACK;
        }
        else
        {
            tcp_out(&key, connection->snd_nxt, connection->rcv_nxt, TCP_FLAG_ACK, NULL, 0);
            connection->state = connection->state == TCP_STATE_FIN_WAIT_1
                                    ? TCP_STATE_CLOSING : TCP_STATE_FIN_WAIT_2;
        }
    }
}

int tcp_listen(uint16_t port, tcp_handler_t handler)
{
    if (!handler)
        return -1;
    return map_set(&tcp_listeners, &port, &handler);
}

void tcp_unlisten(uint16_t port)
{
    map_delete(&tcp_listeners, &port);
}

int tcp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    tcp_key_t key = tcp_make_key(src_port, dst_ip, dst_port);
    tcp_connection_t *connection = map_get(&tcp_connections, &key);
    if (!connection || connection->state != TCP_STATE_ESTABLISHED || (!data && len))
        return -1;

    uint8_t flags = TCP_FLAG_ACK | (len ? TCP_FLAG_PSH : 0);
    if (tcp_out(&key, connection->snd_nxt, connection->rcv_nxt, flags, data, len) < 0)
        return -1;
    connection->snd_nxt += len;
    return 0;
}

int tcp_close(uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    tcp_key_t key = tcp_make_key(src_port, dst_ip, dst_port);
    tcp_connection_t *connection = map_get(&tcp_connections, &key);
    if (!connection || connection->state != TCP_STATE_ESTABLISHED)
        return -1;

    if (tcp_out(&key, connection->snd_nxt, connection->rcv_nxt,
                TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0) < 0)
        return -1;
    connection->snd_nxt++;
    connection->state = TCP_STATE_FIN_WAIT_1;
    return 0;
}

void tcp_init(void)
{
    map_init(&tcp_listeners, sizeof(uint16_t), sizeof(tcp_handler_t), 0, 0, NULL);
    map_init(&tcp_connections, sizeof(tcp_key_t), sizeof(tcp_connection_t),
             64, TCP_TIMEOUT_SEC, NULL);
    tcp_next_isn = (uint32_t)time(NULL) * 1000U;
    net_add_protocol(NET_PROTOCOL_TCP, tcp_in);
}
