//#include "analyseip.h"
#include "checksum.h"
#include "lookuproute.h"
#include "arpfind.h"
#include <pthread.h>
#include <net/if.h>

#define IP_HEADER_LEN sizeof(struct ip)
#define ETHER_HEADER_LEN sizeof(struct ether_header)


//接收路由信息的线程
void *thr_fn(void *arg) {
	// @m
	static char ifname[IF_NAMESIZE];

	struct selfroute *selfrt;
	selfrt = (struct selfroute*)malloc(sizeof(struct selfroute));
	memset(selfrt,0,sizeof(struct selfroute));

	int sock_fd;
	struct sockaddr_in server_addr;
	sock_fd = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&server_addr, sizeof(struct sockaddr_in));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(800);

	bind(sock_fd, (struct sockaddr *)(&server_addr), sizeof(struct sockaddr));
	listen(sock_fd, 5);

	// add-24 del-25
	while(1) {

		// 抓包
		int conn_fd = accept(sock_fd, (struct sockaddr *)NULL, NULL);
		int ret = recv(conn_fd, selfrt, sizeof(struct selfroute), 0);

		// 抓到
		if(ret == 1) {
			//插入
			if(selfrt->cmdnum == 24) {
				while(ifni->if_index != 0) {
					if(ifni->if_index==selfrt->ifindex)
					{
						printf("if_name is %s\n",ifni->if_name);
							ifname = ifni->if_name;
						break;
					}
					ifni++;
				}

				//插入到路由表里
				// @mektpoy
				printf("insert_route start.\n");
				if_indextoname(selfrt->ifindex, ifname);
				int ok = insert_route(
					selfrt->ip4prefix, selfrt->prefixlen,
					ifname, selfrt->ifindex, selfrt->nexthop
				);
				
				if(ok==0) {
					printf("insert route ok!\n");
				} else {
					printf("insert route failed ...\n");
				}
			}
			else if(selfrt->cmdnum == 25) {
				//从路由表里删除路由
				// @mektpoy
				printf("delete_route start.\n");
				int ok = delete_route(selfrt->ip4prefix, selfrt->prefixlen);
				if (ok==0) {
					printf("delete route ok!\n");
				} else {
					printf("delete_route failed ...\n");
				}
			}
		}
	}
}

int main()	
{
	char skbuf[1514];	   // buffer for ether pack
	// char data[1480];	   // commented @m
	
	int recvfd, datalen;
	int recvlen;		

	struct ip *ip_recvpkt; // buffer for pack received
	
	pthread_t tid;
	ip_recvpkt = (struct ip*)malloc(sizeof(struct ip)); // ?: 需要吗？

	//创建raw socket套接字
	if( (recvfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP))) == -1 )	{
		printf("recvfd() error\n");
		return -1;
	}	
	
	//路由表初始化
	route_table = (struct route*)malloc(sizeof(struct route));
	if(route_table==NULL) {
		printf("malloc error!!\n");
		return -1;
	}
	memset(route_table,0,sizeof(struct route));

	//调用添加函数insert_route往路由表里添加直连路由
	// #empty @m

	//创建线程去接收路由信息
	int pd;
	pd = pthread_create(&tid,NULL,thr_fn,NULL);

	while(1) {
		recvlen = recv(recvfd, skbuf, sizeof(skbuf), 0);		//接收ip数据包模块
		
		if (recvlen>0) 
		{
			struct ether_header *eh = (struct ether_header *)skbuf; //以太网包 @m
			ip_recvpkt = (struct ip *)(skbuf + ETHER_HEADER_LEN);

			//192.168.1.10是测试服务器的IP，现在测试服务器IP是192.168.1.10到192.168.1.80.
			//使用不同的测试服务器要进行修改对应的IP。然后再编译。
			//192.168.6.2是测试时候ping的目的地址。与静态路由相对应。
			// 现在是5.2?
 			if(ip_recvpkt->ip_src.s_addr == inet_addr("192.168.1.10") 
 			&& ip_recvpkt->ip_dst.s_addr == inet_addr("192.168.5.2") ) {
				//	analyseIP(ip_recvpkt);	//分析打印ip数据包的源和目的ip地址

				// commented @m
				// int s;
				// memset(data, 0, 1480);
				// for(s = 0; s < 1480; s ++) {
				// 	data[s] = skbuf[s+34];
				// }

				// 校验计算模块
				// 调用校验函数check_sum，成功返回1

				// commented @m
				// struct _iphdr *iphead;
				// iphead=(struct _iphdr *)malloc(sizeof(struct _iphdr));
				
				// @m
				int c = check_sum(ip_recvpkt);

				if(c == 1){
					printf("checksum is ok!!\n");
				} else {
					printf("checksum is error !!\n");
					return -1;
				}

				//调用计算校验和函数count_check_sum，返回新的校验和 
				// unsigned short new_check_sum = count_check_sum(iphead);
				count_check_sum(ip_recvpkt);

				//查找路由表，获取下一跳ip地址和出接口模块
				struct nexthop *nexthopinfo;
				nexthopinfo = (struct nexthop *)malloc(sizeof(struct nexthop));
				memset(nexthopinfo, 0, sizeof(struct nexthop));

				//调用查找路由函数lookup_route，获取下一跳ip地址和出接口
				// @m
				int lookup = lookup_route(ip_recvpkt->ip_dst.s_addr, nexthopinfo);
				if (lookup==0) {
					printf("lookup_route ok!\n");
				} else {
					printf("lookup_route failed ...\n");
				}

				// @m
				printf("[nexthopinfo] ifname: %s, ifindex: %u, ip: %u\n",
					nexthopinfo->ifname, nexthopinfo->ifindex, nexthopinfo->nexthopaddr.s_addr);
					
				//arp find
				struct arpmac *targmac;
				targmac = (struct arpmac*)malloc(sizeof(struct arpmac));
				memset(targmac,0,sizeof(struct arpmac));

				// 调用arpGet获取下一跳的mac地址
				// @m
				// targmac <= 出接口网卡IP
				int arpRC = arpGet(targmac, nexthopinfo->ifname, nexthopinfo->nexthopaddr);
				if (arpRC == 0) {
					printf("arpGet ok!\n");
				} else {
					printf("arpGet failed ...\n");
				}

				// @m
				/* 请求mac地址 */
				// 请求结构体
				struct ifreq ifr;
				// mac地址
				unsigned char ifmac[6];

				// 建立网络套接字
				int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

				// 请求开始：ifr的网卡名
				strncpy(ifr.ifr_name, nexthopinfo->ifname, IF_NAMESIZE);

				// 获取网卡的MAC地址：请求结果在ifr的ifr_hwaddr中
				// ifr_hwaddr.sa_data 即 ifmac —— 出接口网卡mac地址
				if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {
				    memcpy(ifmac, ifr.ifr_hwaddr.sa_data, 6);
				    puts("get interface MAC succeed.");
				} else {
					puts("failed to get interface MAC address.");
				}
				close(sockfd);

				// 生成ether包头：由ifmac, targmac->mac
				memcpy(eh->ether_shost, ifmac, ETH_ALEN);
				memcpy(eh->ether_dhost, targmac->mac, ETH_ALEN);

				// 发送：创建套接字
				int sendfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
				struct sockaddr_ll sadr_ll;
				sadr_ll.sll_ifindex = nexthopinfo->ifindex;
				sadr_ll.sll_halen = ETH_ALEN;
				memcpy(sadr_ll.sll_addr, ifmac, ETH_ALEN);

				int result = sendto(
					sendfd, skbuf, recvlen, 0, 
					(const struct sockaddr *)&sadr_ll, sizeof(struct sockaddr_ll)
				);
				if (result == -1) {
                 	printf("failed when sending packet.\n");
				} else {
					printf("ALL IN SUCCEED!!!!!!!!\n========================\n");
				}
				close(sendfd);
			}
		}
	}

	close(recvfd);	
	return 0;
}

