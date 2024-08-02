#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

uint16_t extern_id = 0;

/**
 * @brief ip分片的缓存表，<ip, ip_fragment_t>
 * 理论上至少需要id+ip的key，但目前先不管
 * 
 */
map_t ip_frag_table;

/**
 * @brief 合成两个ip分片
 * 不会判断两个ip分片是否同组
 * 
 * @param former 要合成的分片左
 * @param frag 要合成的分片右
 * 
 * @return 合成成功返回1，失败返回0
 */
int ip_fragment_combine(ip_fragment_t *former, ip_fragment_t *frag){

    if ( former->mf == 1 && frag->mf != 0 && (former->offset << 3) + ((frag->buf).len - sizeof(ip_hdr_t)) == frag->offset ) {
        former->mf = frag->mf;
        former->next = frag->next;
        buf_add_padding(&(former->buf), (frag->buf).len - sizeof(ip_hdr_t));
        memcpy((former->buf).data + (former->buf).len, (frag->buf).data + sizeof(ip_hdr_t), (frag->buf).len);
        free(frag);
        return 1;
    } else return 0;

}

/**
 * @brief 处理一个要进入的ip分片
 * 基本逻辑：使用环链表存放一个分组的ip分片
 * 并将环链表中offset=0的分片作为头存入map中
 * 
 * @param buf 要发送的分片
 * @param ip 源ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_in(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf){

    // 生成fragment
    ip_fragment_t *frag = (ip_fragment_t *)calloc(1, sizeof(ip_fragment_t));
    memcpy(&(frag->buf), buf, sizeof(buf_t));
    frag->mf        = (uint8_t)mf;
    frag->offset    = offset;

    ip_fragment_t *head     = (ip_fragment_t *)map_get(&ip_frag_table, ip);
    ip_fragment_t *former   = NULL;

    if (head == NULL) {
        // 若此前无该组分片，存入map
        head = frag;
        head->next = frag;
        map_set(&ip_frag_table, ip, head);
    } else {
        // 否则按offset存入环链表
        if (offset < head->offset){
            frag->next = head->next;
            head->next = frag;
        } else {
            former = head;
            while (offset > former->next->offset && former->next != head) {
                former = former->next;
            }
            frag->next = former->next;
            former->next = frag;
        }
    }

    // 仅与左右分片合成
    if (former != NULL)
        if (ip_fragment_combine(former, frag))
            frag = former;

    if (frag->next != head)
        ip_fragment_combine(frag, frag->next);

    // 如合成完毕，发出分片
    if (head->mf == 0 && head->offset == 0){
        buf_remove_header((&head->buf), sizeof(ip_hdr_t));

        ip_hdr_t *hdr = (ip_hdr_t *)((head->buf).data);
        
        net_in(buf, hdr->protocol, hdr->src_ip);
    }
}


/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{    
    if(buf->len < sizeof(ip_hdr_t)){
        return;
    }

    // 报头检测
    ip_hdr_t * hdr = (ip_hdr_t *) buf->data;
    if (hdr->version != IP_VERSION_4)
        return;
    if (hdr->hdr_len != sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE)
        return;
    if (swap16(hdr->total_len16) > buf->len)
        return;

    // 校验和
    uint16_t hdr_checksum16 = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;
    if (hdr_checksum16 ^ checksum16((uint16_t *)hdr, hdr->hdr_len) ) hdr->hdr_checksum16 = hdr_checksum16;
    else
        return;

    // 对比本机ip
    if(memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN))
        return;

    // 删除ip填充
    if (swap16(hdr->total_len16) < buf->len) buf_remove_padding(buf, buf->len - swap16(hdr->total_len16));

    // 目前ttl似乎没用？
    //if (hdr->ttl == 0) printf("ttl out\n");
    //else hdr->ttl--;

    switch (hdr->protocol){
    case NET_PROTOCOL_TCP:
    case NET_PROTOCOL_ICMP:
    case NET_PROTOCOL_UDP:
        break;
    default:
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
        return;
    }

    // 分片进入处理
    if (hdr->flags_fragment16 & 0x3fff != 0) {
        ip_fragment_in(buf, hdr->src_ip, hdr->protocol, swap16(hdr->id16), hdr->flags_fragment16 & 0x1fff, (hdr->flags_fragment16 >> 13) & 1);
        return;
    }
    
    // 发往上层协议
    buf_remove_header(buf, sizeof(ip_hdr_t));

    net_in(buf, hdr->protocol, hdr->src_ip);

}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    buf_add_header(buf, sizeof(ip_hdr_t));

    ip_hdr_t * hdr = (ip_hdr_t *)buf->data;

    hdr->version            = IP_VERSION_4;
    hdr->tos                = 0;
    hdr->hdr_len            = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    hdr->total_len16        = swap16(buf->len);
    hdr->id16               = swap16((uint16_t)id);
    hdr->flags_fragment16   = swap16(((mf & 0x1) ? IP_MORE_FRAGMENT : 0) + offset);
    hdr->ttl                = 64;
    hdr->protocol           = protocol;
    hdr->hdr_checksum16     = 0;
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);

    hdr->hdr_checksum16 = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t) / sizeof(uint16_t));

    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // 自设id，并不知道这东西在哪里
    uint16_t id = extern_id;

    uint32_t frag_data_len = ( (ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t)) >> 3 ) << 3;

    if (buf->len <= frag_data_len){
        
        ip_fragment_out(buf, ip, protocol, id, 0, 0);

    } else {
        uint32_t frag_offset = 0;

        while(buf->len > frag_data_len){            
            buf_init(&txbuf, frag_data_len);

            memcpy(txbuf.data, buf->data, frag_data_len);

            buf_remove_header(buf, frag_data_len);

            ip_fragment_out(&txbuf, ip, protocol, id, frag_offset >> 3, 1);

            frag_offset += frag_data_len;
        }

        ip_fragment_out(buf, ip, protocol, id, frag_offset >> 3, 0);
    }

    extern_id++;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    map_init(&ip_frag_table, NET_IP_LEN, sizeof(ip_fragment_t), 0, IP_TIMEOUT_SEC, NULL);
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}