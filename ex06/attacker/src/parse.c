#include "inquisitor.h"

static int is_hexdigit(char c)
{
	char hex[17] = "0123456789abcdef";
	int i = 0;
	hex[16] = '\0';
	while(hex[i])
	{
		if (c == hex[i])
			return (1);
		i++;
	}
	return (0);
}

static int is_ip(int protocol, const char *ip, void *net_address)
{
	if (inet_pton(protocol, ip, net_address) == 1)	
		return (1);
	return (0);
}

static int is_mac(char *s)
{
	char separator = ':';
	if (strlen(s) != 17)
		return (0);
	if (s[2] == '-')
		separator = '-';
	else if (s[2] != ':')
		return (0);
	for (int i = 0; i < 17; i++)
	{
		if (i % 3 == 2)
		{
			if (s[i] != separator)
				return (0);
		}
		else 
	{
			if (!is_hexdigit(s[i]))
				return(0);
		}
	}
	return (1);
}

static int htoi(char c) 
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static void str_to_mac(const char *str, unsigned char *mac) 
{
	for (int i = 0; i < 6; i++) 
	{
		int high = htoi(*str++);
		int low = htoi(*str++);

		mac[i] = (unsigned char)((high << 4) | low);

		if (*str == ':' || *str == '-') 
			str++;
	}
}

void parse_input(char *av[], t_session *session)
{
	struct sockaddr_in src;
	struct sockaddr_in dst;

	if (!is_ip(AF_INET, av[1], &src.sin_addr))
		error("ip src not found");
	if (!is_mac(av[2]))
		error("MAC address src invalid");
	if (!is_ip(AF_INET, av[3], &dst.sin_addr))
		error("ip dst not found");
	if (!is_mac(av[4]))
		error("MAC address dst invalid");

	session->src.ip = src.sin_addr;
	str_to_mac(av[2], session->src.mac);
	session->dst.ip = dst.sin_addr; 
	str_to_mac(av[4], session->dst.mac);
}
