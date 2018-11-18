#ifndef __FIND__
#define __FIND__
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<stdint.h>
#include<stdbool.h>
#include<arpa/inet.h>


struct route
{
  struct route *next;
  struct in_addr ip4prefix;
  unsigned int prefixlen;
  struct nexthop *nexthop;
};

struct nexthop
{
  struct nexthop *next;
  char *ifname;
  unsigned int ifindex;   // Nexthop address 
  struct in_addr nexthopaddr;
};

// @m
// struct nextaddr
// {
//   char *ifname;
//   struct in_addr ipv4addr;
//   unsigned int prefixl;
// };

struct route *route_table;

// @m
bool ip_match(uint32_t ip1, uint32_t ip2, uint32_t prefixlen);
int insert_route(
    uint32_t ip4prefix, uint32_t prefixlen, char *ifname, 
    uint32_t ifindex, uint32_t nexthopaddr
);
int lookup_route(uint32_t dstaddr, struct nexthop *nexthopinfo);
int delete_route(uint32_t dstaddr, uint32_t prefixlen);

#endif
