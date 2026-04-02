#include "inquisitor.h"
#include "include/inquisitor.h"

# include <stdio.h>
# include <stdlib.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

//---------------------
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <ifaddrs.h>

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
	int sock_fd;

	sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_fd < 0)
		error("socket failed");
	return (sock_fd);
}

static struct in_addr get_access_point_ip(t_session session)
{
 /*this should be better made but to much for my mental sanity at least for now
  * The thing is i should be able to know which is the ip of the access point
  * but the way of knowing is against the norm and against the way im doing this project for using it on man in the middle project
  * because of course im lazy enough for not doing the same project twice im going to go in deep with c just once :D
  * but this part is tricky and im not going to do it now, so fucked im going to asssume that the ip is the one that starts with .1 
  * on docker that works but in other kind of networks thats not always correct for example on 42 the access_point is 10.11.254.254
  * and of course there is a lot of ways of getting this info but not today baby
  * in terminal u can see this here :D command -> ip route show default                                                                                                                                                         deordone@car14s4
  */
	struct in_addr target_ip;

	target_ip = session.src_ip;	
	unsigned char *bytes = (unsigned char *)&target_ip.s_addr;
	bytes[0] = 1;

	return (target_ip);
}

static void send_arp_request(int socket, int index, t_session session)
{
	struct arp_packet pkt;
	struct sockaddr_ll sll;	
	struct in_addr target;

	//Ethernet header	
	memset(pkt.eth.h_dest, 0xff, 6);          		// Destino: Broadcast (ff:ff:ff:ff:ff:ff)
    memcpy(pkt.eth.h_source, session.src_mac, 6);   // Origen: Tu MAC
    pkt.eth.h_proto = htons(ETH_P_ARP);			// Tipo: ARP (0x0806)
	
    //Body ARP
    pkt.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER); // Hardware: Ethernet (1)
    pkt.arp.ea_hdr.ar_pro = htons(ETH_P_IP);    // Protocolo: IPv4 (0x0800)
    pkt.arp.ea_hdr.ar_hln = 6;                  // Tamaño MAC: 6
    pkt.arp.ea_hdr.ar_pln = 4;                  // Tamaño IP: 4
    pkt.arp.ea_hdr.ar_op = htons(ARPOP_REQUEST); // Operación: REQUEST (1)

    //Directions inside body ARP
    memcpy(pkt.arp.arp_sha, session.src_mac, 6);           // Sender MAC
    memcpy(pkt.arp.arp_spa, &session.src_ip.s_addr, 4);    // Sender IP
    memset(pkt.arp.arp_tha, 0x00, 6);  	                 // Target MAC (desconocida)
	target = get_access_point_ip(session);
//-------------------------------------
	char src_str[INET_ADDRSTRLEN];
	char dst_str[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(session.src_ip), src_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(target), dst_str, INET_ADDRSTRLEN);

	printf("[DEBUG] Source IP: %s\n", src_str);
	printf("[DEBUG] Target IP: %s\n", dst_str);
//-------------------------------------
	memcpy(pkt.arp.arp_tpa, &target, 4);  				// Target IP (el .1)

    //Prepare sendto ---
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = index;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, pkt.eth.h_dest, 6);

    if (sendto(socket, &pkt, sizeof(pkt), 0, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("Error al enviar");
    }
}

static void get_access_point_mac(t_session session)
{
	unsigned int index;
	int socket;
	struct ifaddrs *ifaddr;

	if (getifaddrs(&ifaddr) == -1)\
		error("cannot access mac address of the system");

	char *name = get_nic(ifaddr);
	index = if_nametoindex(name);           
	socket = raw_socket();
	send_arp_request(socket, index, session);

	//DEBUG
	//----------------------------------------------------------------
	printf("NAME: %s\n", name); 
	printf("INDEX: %u\n", index); 

	//----------------------------------------------------------------
	// example
	//----------------------------------------------------------------
	int family, s;
	char host[NI_MAXHOST];

	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
	{
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;

		/* Display interface name and family (including symbolic
				  form of the latter for the common families).  */

		printf("ifa name: %-8s %s (%d)\n", ifa->ifa_name,
		 (family == AF_PACKET) ? "AF_PACKET" :
		 (family == AF_INET) ? "AF_INET" :
		 (family == AF_INET6) ? "AF_INET6" : "???",
		 family);

		/* For an AF_INET* interface address, display the address.  */

		if (family == AF_INET || family == AF_INET6) {
			s = getnameinfo(ifa->ifa_addr,
				   (family == AF_INET) ? sizeof(struct sockaddr_in) :
				   sizeof(struct sockaddr_in6),
				   host, NI_MAXHOST,
				   NULL, 0, NI_NUMERICHOST);
			if (s != 0) {
				printf("getnameinfo() failed: %s\n", gai_strerror(s));
				exit(EXIT_FAILURE);
			}


			printf("\t\taddress: <%s>\n", host);

		} else if (family == AF_PACKET && ifa->ifa_data != NULL) {
			struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;

			printf("%-10s ", ifa->ifa_name);
			for (int i = 0; i < s->sll_halen; i++) {
				printf("%02x%c", s->sll_addr[i], (i + 1 < s->sll_halen) ? ':' : '\n');
			}
			struct rtnl_link_stats *stats = ifa->ifa_data;

			printf("\t\ttx_packets = %10u; rx_packets = %10u\n"
		  "\t\ttx_bytes   = %10u; rx_bytes   = %10u\n",
		  stats->tx_packets, stats->rx_packets,
		  stats->tx_bytes, stats->rx_bytes);
		}
	}
	freeifaddrs(ifaddr);
}

//spoofing() una funcion que haga la request y le haga creer a una ip que tiene x o y direccion mac

int main (int ac, char *av[])
{
	t_session session;
	if (ac != 5)	
		usage();
	parse_input(av, &session);
	get_access_point_mac(session);
	return (0);
}
