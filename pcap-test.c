#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdbool.h>

struct libnet_ethernet_hdr {
    uint8_t  ether_dhost[6]; 
    uint8_t  ether_shost[6]; 
    uint16_t ether_type;    
};


struct libnet_ipv4_hdr {
    uint8_t  ip_hl:4, ip_v:4; 
    uint8_t  ip_tos;          
    uint16_t ip_len;          
    uint16_t ip_id;           
    uint16_t ip_off;
    uint8_t  ip_ttl;          
    uint8_t  ip_p;            
    uint16_t ip_sum;          
    struct in_addr ip_src, ip_dst; 
};


struct libnet_tcp_hdr {
    uint16_t th_sport;       
    uint16_t th_dport;       
    uint32_t th_seq;         
    uint32_t th_ack;         
    uint8_t  th_x2:4, th_off:4; 
    uint8_t  th_flags;       
    uint16_t th_win;         
    uint16_t th_sum;         
    uint16_t th_urp;         
};

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void handle_packet(const u_char *packet) {
    struct libnet_ethernet_hdr *eth_hdr;
    struct libnet_ipv4_hdr *ip_hdr;
    struct libnet_tcp_hdr *tcp_hdr;
    const u_char *data;
    int data_len;

    eth_hdr = (struct libnet_ethernet_hdr *)packet;
    if (ntohs(eth_hdr->ether_type) == 0x0800) {
        ip_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            tcp_hdr = (struct libnet_tcp_hdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl * 4));
            data = (u_char *)tcp_hdr + (tcp_hdr->th_off * 4);
            data_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - (tcp_hdr->th_off * 4);

            printf("ETH + IP + TCP + DATA\n");
            printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
                   eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
            printf("DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
                   eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
            printf("SRC IP: %s\n", inet_ntoa(ip_hdr->ip_src));
            printf("DST IP: %s\n", inet_ntoa(ip_hdr->ip_dst));
            printf("SRC PORT: %u\n", ntohs(tcp_hdr->th_sport));
            printf("DST PORT: %u\n", ntohs(tcp_hdr->th_dport));
            printf("DATA: ");
            for (int i = 0; i < data_len && i < 20; i++) {
                printf("%02x ", data[i]);
            }
            printf("\n");
        }
    }
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        handle_packet(packet);
    }

    pcap_close(pcap);
    return 0;
}
