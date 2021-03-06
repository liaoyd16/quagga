#ifndef __RECVROUTE__
#define __RECVROUTE__
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<sys/time.h>
#include<linux/if_ether.h>
#include<arpa/inet.h>
#include<net/route.h>
#include<net/if.h>
 
struct selfroute
{
     uint32_t prefixlen;
     uint32_t ip4prefix;
     uint32_t ifindex;
     uint32_t nexthop;
     uint32_t cmdnum;
     char ifname[IF_NAMESIZE];
}buf2;

#endif