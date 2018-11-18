#include "arpfind.h"

int arpGet(struct arpmac *srcmac, char *ifname, char *ip4addr) {
    // @metkpoy

    // request 对象：arp_req
    struct arpreq arp_req;

    // 构建请求对象的协议地址: 
    // arp_pa(协议地址), arp_dev(设备名称)
    struct sockaddr_in *sin;
    sin = (struct sockaddr_in *)&(arp_req.arp_pa);
    memset(&arp_req, 0, sizeof(arp_req));
    sin->sin_family = AF_INET;
    sin->sin_addr = ip4addr;
    strncpy(arp_req.arp_dev, ifname, IF_NAMESIZE - 1);

    // 创建套接字的 设备/文件描述符，用于获知mac地址
    // 设置参数为 设备/文件描述符，指令类型flag(见bits/ioctls.h ARP相关)，请求对象
    int arp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    int ret = ioctl(arp_fd, SIOCGARP, &arp_req);

    if (ret < 0) {
        printf("Get ARP entry failed.");
        return -1;
    }

    if (arp_req.arp_flags & ATF_COM) {
        static unsigned char mac[6];
        // the mac address can be directed copied to eth_header->ether_dhost
        memcpy(mac, (unsigned char *)arp_req.arp_ha.sa_data, sizeof(mac));
        printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        srcmac->mac = &mac;
    } else {
        printf("Entry not found.");
        return -1;
    }

    close(arp_fd);

    return 0;
}
