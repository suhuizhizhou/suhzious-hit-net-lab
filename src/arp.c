#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    buf_init(&txbuf, ETHERNET_MIN_TRANSPORT_UNIT);
    memset(txbuf.data, 0, ETHERNET_MIN_TRANSPORT_UNIT);

    arp_pkt_t *arp = (arp_pkt_t *) txbuf.data;

    uint8_t boardcast_mac[] = {0xff,0xff,0xff,0xff,0xff,0xff};

    memcpy(arp, &arp_init_pkt, sizeof(arp_pkt_t));
    arp->opcode16 = swap16(ARP_REQUEST);
    memcpy(arp->target_ip, target_ip, NET_IP_LEN );

    ethernet_out(&txbuf, boardcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    buf_init(&txbuf, ETHERNET_MIN_TRANSPORT_UNIT);
    memset(txbuf.data, 0, ETHERNET_MIN_TRANSPORT_UNIT);

    arp_pkt_t *arp = (arp_pkt_t *) txbuf.data;

    memcpy(arp, &arp_init_pkt, sizeof(arp_pkt_t));
    arp->opcode16 = swap16(ARP_REPLY);
    memcpy(arp->target_ip, target_ip, NET_IP_LEN );
    memcpy(arp->target_mac, target_mac, NET_MAC_LEN );
    
    ethernet_out(&txbuf, arp->target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{

    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT -18){
        // 怎么发进来无填充的arp
        //printf("\narp_in 已丢弃( 长度 %d\n",buf->len);
        return;
    }

    //报文检查
    arp_pkt_t * arp = (arp_pkt_t*)buf->data;
    if (memcmp(&arp_init_pkt, arp, 6 ) || ( swap16(arp->opcode16) != ARP_REQUEST & swap16(arp->opcode16) != ARP_REPLY )){
        return;
    }

    //更新arp
    map_set(&arp_table, arp->sender_ip, src_mac);

    if (!memcmp(arp->target_ip, net_if_ip, NET_IP_LEN) & swap16(arp->opcode16) == ARP_REQUEST) {
        //如果没有，比对本机ip，是目标且为请求报文则响应
        arp_resp(arp->sender_ip, arp->sender_mac);
    } 

    buf_t * wait_arp_buf = (buf_t *) map_get(&arp_buf, arp->sender_ip);
    if (wait_arp_buf != NULL){
        //如果其源ip是某个缓存包的目标ip,则可以从中找到ip对应的下一个mac,于是可以发出缓存包
        arp_out(wait_arp_buf, arp->sender_ip);
        map_delete(&arp_buf, arp->sender_ip);
    }
    else if (memcmp(arp->target_ip, net_if_ip, NET_IP_LEN)) {
        //本机不是目标，直接转发
        arp_out(buf, arp->target_ip);
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // 查表寻找下一跳mac
    uint8_t * target_mac = (uint8_t *) map_get(&arp_table, ip);
    if (target_mac != NULL){
        
        ethernet_out(buf, target_mac, NET_PROTOCOL_IP );//lack of protocol

    } else if (map_get(&arp_buf, ip) == NULL){
    // 未查找到ip地址且此前未曾已经向该ip发送arp请求，则发送arp请求寻找该ip
        map_set(&arp_buf, ip, buf);
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}