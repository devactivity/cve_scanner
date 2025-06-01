#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef enum { PROTO_TCP, PROTO_UDP } Protocol ;

unsigned short checksum(void *data, int len) {
  unsigned short *ptr = data;
  unsigned long sum = 0;
  while (len > 1) {
    sum += *ptr++;
    len -=2;
  }
  if (len) sum += *(unsigned char *)ptr;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return -sum;
}

int send_packet(const char *src_ip, const char *dst_ip, int port, Protocol proto) {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0) return -1;

  struct sockaddr_in dest = {
    .sin_family = AF_INET,
    .sin_addr = { .s_addr = inet_addr(dst_ip) }
  };

  char packet[4096];
  struct iphdr *ip = (struct iphdr *)packet;
  ip->ihl = 5;
  ip->version = 4;
  ip->ttl = 64;
  ip->saddr = inet_addr(src_ip);
  ip->daddr = inet_addr(dst_ip);

  switch (proto) {
    case PROTO_TCP: {
      struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
      tcp->source = htons(12345); // fixed source port 12345
      tcp->dest = htons(port);
      tcp->seq = htonl(123456);
      tcp->syn = 1;
      tcp->window = htons(4444);
      tcp->check = checksum(tcp, sizeof(struct tcphdr));
      ip->protocol = IPPROTO_TCP;
      ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
      break;
    }
    case PROTO_UDP: {
      struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
      udp->source = htons(12345); // fixed source port 12345
      udp->dest = htons(port);
      udp->len = htons(8);
      udp->check = 0;
      ip->protocol = IPPROTO_UDP;
      ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
      break;
    }
    default:
      close(sock);
      return -2;
  }

  if (sendto(sock, packet, ip->tot_len, 0 , (struct sockaddr *)&dest, sizeof(dest)) < 0) {
    close(sock);
    return -3;
  }

  close(sock);
  return 0;

}
