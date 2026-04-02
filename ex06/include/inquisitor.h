#ifndef INQUISITOR_HPP
# define INQUISITOR_HPP

# include <stdio.h>
# include <stdlib.h>
# include <arpa/inet.h>
# include <string.h>

typedef struct s_info
{
	int ip_src;
	int ip_dst;
	int mac_src;
	int mac_dst;
} t_info;

#endif 
