#include "inquisitor.h"

static void usage(void)
{
	printf("./inquisitor [IP-src] [MAC-src] [IP-target] [MAC-target]\n");
	exit(1);
}

static void error(const char *message)
{
	printf("[INQUISITOR] error: %s\n", message);
	exit(1);
}

static int is_xdigit(char c)
{
	char hex[16] = "0123456789abcdef";
	int i = 0;
	hex[15] = '\0';
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
			if (!is_xdigit(s[i]))
				return(0);
		}
	}
	return (1);
}

static void parse_input(char *av[], t_info *info)
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
	(void)info;
}

int main (int ac, char *av[])
{
	t_info info;
	if (ac != 5)	
		usage();
	parse_input(av, &info);
	return (0);
}
