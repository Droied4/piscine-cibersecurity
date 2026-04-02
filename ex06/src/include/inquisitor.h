#ifndef INQUISITOR_HPP
# define INQUISITOR_HPP

# include <string.h>
# include <arpa/inet.h>
# include <netinet/if_ether.h>

typedef struct session_pair 
{
    unsigned char src_mac[6];
    struct in_addr src_ip;
    unsigned char dst_mac[6];
    struct in_addr dst_ip;
} t_session;

struct arp_packet {
    struct ethhdr  eth;    // 14 bytes Ethernet Header
    struct ether_arp arp;  // 28 bytes ARP Body
} __attribute__((packed));

//[PARSE]
void parse_input(char *av[], t_session *session);

//[INQUISITOR]
void error(const char *message);

#endif 
