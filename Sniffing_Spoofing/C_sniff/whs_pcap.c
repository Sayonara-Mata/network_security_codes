#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    /* IP 패킷만 처리 */
    if (ntohs(eth->ether_type) != 0x0800)
        return;

    /* IP Header */
    struct ipheader *ip =
        (struct ipheader *)(packet + sizeof(struct ethheader));

    /* IP Header 길이 */
    int ip_header_len = ip->iph_ihl * 4;

    /* TCP만 처리 */
    if (ip->iph_protocol != IPPROTO_TCP)
        return;

    /* TCP Header */
    struct tcpheader *tcp =
        (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    /* TCP Header 길이 */
    int tcp_header_len = TH_OFF(tcp) * 4;

    /* HTTP Payload 위치 */
    char *payload =
        (char *)packet
        + sizeof(struct ethheader)
        + ip_header_len
        + tcp_header_len;

    /* HTTP Payload 길이 */
    int payload_len =
        ntohs(ip->iph_len)
        - ip_header_len
        - tcp_header_len;

    /* Payload 없는 TCP 패킷은 무시 */
    if (payload_len <= 0)
        return;

    /* Ethernet Header */
    printf("\n================ Ethernet Header ================\n");
    printf("Source MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_shost[0], eth->ether_shost[1],
           eth->ether_shost[2], eth->ether_shost[3],
           eth->ether_shost[4], eth->ether_shost[5]);

    printf("Destination MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_dhost[0], eth->ether_dhost[1],
           eth->ether_dhost[2], eth->ether_dhost[3],
           eth->ether_dhost[4], eth->ether_dhost[5]);

    /* IP Header */
    printf("\n================ IP Header ================\n");
    printf("Source IP       : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP  : %s\n", inet_ntoa(ip->iph_destip));
    printf("Protocol        : TCP\n");

    /* TCP Header */
    printf("\n================ TCP Header ================\n");
    printf("Source Port      : %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port : %d\n", ntohs(tcp->tcp_dport));

    /* HTTP Message */
    if ((ntohs(tcp->tcp_sport) == 80 || ntohs(tcp->tcp_dport) == 80) && payload_len > 0)
    {
        printf("\n================ HTTP Message ================\n");
        fwrite(payload, 1, payload_len, stdout);
        printf("\n");
    }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name eth0
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL) {
    printf("%s\n", errbuf);
    return -1;
  }

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


