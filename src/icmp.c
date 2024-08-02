#include "net.h"
#include "icmp.h"
#include "ip.h"
#include <time.h>

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    buf_init(&txbuf, 46 - sizeof(ip_hdr_t));

    buf_copy(&txbuf, req_buf, sizeof(buf_t));

    icmp_hdr_t * hdr = (icmp_hdr_t *) txbuf.data;

    hdr->type = ICMP_TYPE_ECHO_REPLY;
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16((uint16_t *)hdr, txbuf.len / sizeof(uint16_t));

    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 发送icmp请求
 * 
 * @param dst_ip 目标ip地址
 */
static void icmp_req(uint8_t *dst_ip)
{
    buf_init(&txbuf, 46 - sizeof(ip_hdr_t) - sizeof(icmp_hdr_t));

    // 8 bytes
    struct timeval time_stamp;
    mingw_gettimeofday(&time_stamp, NULL);
    //printf("time: %d s %d ns %d bytes\n",time_stamp.tv_sec, time_stamp.tv_usec, sizeof(time_stamp));

    memcpy(txbuf.data, &time_stamp, sizeof(time_stamp));

    buf_add_header(&txbuf, sizeof(icmp_hdr_t));

    icmp_hdr_t * hdr = (icmp_hdr_t *) txbuf.data;

    hdr->type = ICMP_TYPE_ECHO_REQUEST;
    hdr->code = 0;
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16((uint16_t *)hdr, txbuf.len / sizeof(uint16_t));

    ip_out(&txbuf, dst_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    if (buf->len < sizeof(icmp_hdr_t)){
        return;
    }

    icmp_hdr_t * hdr = (icmp_hdr_t *) buf->data;

    if (hdr->type == ICMP_TYPE_ECHO_REQUEST){
        icmp_resp(buf, src_ip);
    } else if (hdr->type == ICMP_TYPE_ECHO_REPLY){
        ;
    }
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    if (code == ICMP_CODE_PROTOCOL_UNREACH || code == ICMP_CODE_PORT_UNREACH)
    {
        buf_init(&txbuf, sizeof(ip_hdr_t) + 8);
        memcpy(txbuf.data, recv_buf->data, sizeof(ip_hdr_t) + 8);

        buf_add_header(&txbuf, sizeof(icmp_hdr_t));
        icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
        
        hdr->type = ICMP_TYPE_UNREACH;
        hdr->code = code;
        hdr->id16 = 0;
        hdr->seq16 = 0;

        hdr->checksum16 = 0;
        hdr->checksum16 = checksum16((uint16_t *)hdr, txbuf.len / sizeof(uint16_t));

        ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
    } else {
        printf("icmp_unreachable 404");
    }
}

void ping(uint8_t *dst_ip)
{
    //printf("\n来自 %d.%d.%d.%d 的回复：字节=%d", src_ip[0], src_ip[1], src_ip[2], src_ip[3], buf->len);        
    
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}