#ifndef INQUISITOR_HPP
# define INQUISITOR_HPP

# include <string.h>
# include <arpa/inet.h>
# include <netinet/if_ether.h>

extern volatile int loop;

typedef struct s_pair
{
    unsigned char mac[6];
    struct in_addr ip;
} t_pair;

typedef struct s_session_pair 
{
	t_pair src;
	t_pair dst;
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
