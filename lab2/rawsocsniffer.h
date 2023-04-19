#include <iostream>
#include <iomanip>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include "rawsocket.h"
using namespace std;

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;

typedef struct filter
{
    unsigned long sip;
    unsigned long dip;
    unsigned int protocol;    
} filter;

typedef struct ether_header_t{
    BYTE des_hw_addr[6];    //目的MAC地址
    BYTE src_hw_addr[6];    //源MAC地址
    WORD frametype;       //数据长度或类型
} ether_header_t;


typedef struct arp_header_t{
    WORD hw_type;          //16位硬件类型
    WORD prot_type;         //16位协议类型
    BYTE hw_addr_len;       //8位硬件地址长度
    BYTE prot_addr_len;      //8位协议地址长度
    WORD flag;             //16位操作码
    BYTE send_hw_addr[6];   //源Ethernet网地址
    DWORD send_prot_addr;  //源IP地址
    BYTE des_hw_addr[6];    //目的Ethernet网地址
    DWORD des_prot_addr;   //目的IP地址
} arp_header_t;


typedef struct ip_header_t{
    BYTE hlen_ver;         //头部长度和版本信息
    BYTE tos;              //8位服务类型
    WORD total_len;        //16位总长度
    WORD id;             //16位标识符
    WORD flag;           //3位标志+13位片偏移
    BYTE ttl;             //8位生存时间
    BYTE protocol;        //8位上层协议号    
    WORD checksum;      //16位校验和
    DWORD src_ip;       //32位源IP地址
    DWORD des_ip;      //32位目的IP地址
} ip_header_t;




typedef struct tcp_header_t{
    WORD src_port;          //源端口
    WORD des_port;          //目的端口
    DWORD seq;             //seq号
    DWORD ack;             //ack号
    BYTE len_res;            //头长度
    BYTE flag;               //标志字段 
    WORD window;           //窗口大小
    WORD checksum;         //校验和
    WORD urp;              //紧急指针 
} tcp_header_t;

typedef struct udp_header_t{
    WORD src_port;          //源端口
    WORD des_port;          //目的端口 
    WORD len;              //数据报总长度
    WORD checksum;        //校验和
} udp_header_t;

typedef struct icmp_header_t{
    BYTE type;              //8位类型     
    BYTE code;              //8位代码
    WORD checksum;         //16位校验和
    WORD id;               //16位标识符   
    WORD seq;              //16位序列号
} icmp_header_t;

typedef struct arp_packet_t{
    struct ether_header_t etherheader;
    struct arp_header_t arpheader; 
} arp_packet_t;

typedef struct ip_packet_t{
    struct ether_header_t etherheader;
    struct ip_header_t ipheader; 
} ip_packet_t;

typedef struct icmp_packet_t{
    struct ether_header_t etherheader;
    struct ip_header_t ipheader;
    struct icmp_header_t icmpheader;
} icmp_packet_t;

typedef struct tcp_packet_t{
    struct ether_header_t etherheader;
    struct ip_header_t ipheader;
    struct tcp_header_t tcpheader;
} tcp_packet_t;

typedef struct udp_packet_t{
    struct ether_header_t etherheader;
    struct ip_header_t ipheader;
    struct udp_header_t udpheader;
} udp_packet_t;

class rawsocsniffer : public rawsocket
{
    private:
	filter simfilter;
	char *packet;
	const int max_packet_len;
    public:
	rawsocsniffer(int protocol);
	~rawsocsniffer();
	bool init();
	void setfilter(filter myfilter);
	bool testbit(const unsigned int p, int k);
	void setbit(unsigned int &p,int k);
	void sniffer();
	void analyze();
	void ParseRARPPacket();
	void ParseARPPacket();
	void ParseIPPacket();
	void ParseTCPPacket();
	void ParseUDPPacket();
	void ParseICMPPacket();
	void print_hw_addr(const unsigned char *ptr);
	void print_ip_addr(const unsigned long ip);
};
