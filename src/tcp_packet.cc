#include "tcp_packet.h"

#include <iostream>
#include <memory>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <pcap.h>

using namespace std;

namespace Zktraffic {

/* from https://www.tcpdump.org/pcap.html */

/* Ethernet header */
#define ETHER_ADDR_LEN	6
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
  u_char ip_vhl;                /* version << 4 | header length >> 2 */
  u_char ip_tos;                /* type of service */
  u_short ip_len;               /* total length */
  u_short ip_id;                /* identification */
  u_short ip_off;               /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
  u_char ip_ttl;                /* time to live */
  u_char ip_p;                   /* protocol */
  u_short ip_sum;               /* checksum */
  struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport;     /* source port */
  u_short th_dport;     /* destination port */
  tcp_seq th_seq;               /* sequence number */
  tcp_seq th_ack;               /* acknowledgement number */
  u_char th_offx2;      /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;               /* window */
  u_short th_sum;               /* checksum */
  u_short th_urp;               /* urgent pointer */
};

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

std::unique_ptr<TcpPacket> TcpPacket::from_pcap(const struct pcap_pkthdr* header,  const u_char *packet) {
  if (packet == nullptr) {
    return nullptr;
  }

  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  const char *payload; /* Packet payload */

  u_int size_ip_header;
  u_int size_tcp_header;

  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip_header = IP_HL(ip)*4;
  if (size_ip_header < 20) {
    cout << "Invalid IP header length\n";
    return nullptr;
  }

  tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip_header);
  size_tcp_header = TH_OFF(tcp)*4;
  if (size_tcp_header < 20) {
    cout << "Invalid TCP header length\n";
    return nullptr;
  }

  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);

  int data_length = htons(ip->ip_len) - size_ip_header - size_tcp_header;

  if (data_length == 0)
    return nullptr;
  
  payload = (const char *)(packet + SIZE_ETHERNET + size_ip_header + size_tcp_header);
  return std::make_unique<TcpPacket>(
                                     ntohs(tcp->th_sport),
                                     ntohs(tcp->th_dport),
				     src_ip,
				     dst_ip,
                                     payload,
				     data_length);
}

}
