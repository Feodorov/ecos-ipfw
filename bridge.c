/* this is a simple hello world program */
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <network.h>
#include <cyg/kernel/kapi.h>
#include <net/route.h>
#include <ifaddrs.h>
#include <assert.h>
#include <netinet/ip_fw.h>
#include "ip_fw_private.h"

#define CYGDBG_USE_ASSERTS

enum {
    ERROR_NO_IF_ADDR_FOUND
} ERRORS;

typedef struct ifaddrs ifaddr_t;
typedef struct sockaddr_in sockaddr_in_t;
typedef int ip_fw_chk_t __P((struct ip **, int, struct ifnet *, u_int16_t *,
        struct mbuf **, struct ip_fw_chain **, struct sockaddr_in **));

extern struct ip_fw_chain layer3_chain;

u_int16_t ip_divert_cookie;

int add_route(const char * ifs, const char * dst, const char * msk, const char * gtw) {

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
    }

    struct ecos_rtentry route;
    memset(&route, 0, sizeof (route));

    struct sockaddr_in addrp, gateway, mask;

    gateway.sin_family = AF_INET;
    gateway.sin_addr.s_addr = inet_addr(gtw);
    gateway.sin_len = sizeof (struct sockaddr_in);

    mask.sin_family = AF_INET;
    mask.sin_addr.s_addr = inet_addr(msk);
    mask.sin_len = sizeof (struct sockaddr_in);

    addrp.sin_family = AF_INET;
    addrp.sin_port = 0;
    addrp.sin_addr.s_addr = inet_addr(dst);
    addrp.sin_len = sizeof (struct sockaddr_in);

    memcpy(&route.rt_gateway, &gateway, sizeof (gateway));
    memcpy(&route.rt_dst, &addrp, sizeof (addrp));
    memcpy(&route.rt_genmask, &mask, sizeof (mask));

    route.rt_dev = ifs;
    //originally was RTF_UP | RTF_HOST | RTF_LOCAL |
    route.rt_flags = RTF_UP | /*RTF_HOST*/ RTF_GATEWAY | RTF_LOCAL | RTF_STATIC;
    route.rt_metric = 0;
    if(0== rtioctl(SIOCADDRT, &route, 0)){
    //ioctl returns -1 on fail - works fine
   // if (ioctl(s, SIOCADDRT, &route) != -1) { - works fine, previous version
        diag_printf("My route added - dst: %s",
                inet_ntoa(((struct sockaddr_in *) &route.rt_dst)->sin_addr));
        diag_printf(", mask: %s",
                inet_ntoa(((struct sockaddr_in *) &route.rt_genmask)->sin_addr));
        diag_printf(", gateway: %s",
                inet_ntoa(((struct sockaddr_in *) &route.rt_gateway)->sin_addr));
        diag_printf(", interface %s\n", ifs);
        /*if (errno != EEXIST) {
            perror("SIOCADDRT 3");
        }*/
    }
    close(s);
}
extern int cyg_fw_enable;

int main(void) {
    //firewall
    
     char * ipfw_command2[] = {"add","set",  "3",  "allow",  "all",  "from",  "192.168.2.100",  "to",  "192.168.1.100"};
     char * ipfw_command1[] = {"add","set",  "2",  "allow",  "all",  "from",  "192.168.1.100",  "to",  "192.168.2.100"};
     //char * ipfw_nat_config1[] = {"nat-config", "1", "ip", "192.168.1.1", "redirect_addr",  "192.168.2.100",  "192.168.5.1"};
     //char * ipfw_nat_config2[] = {"nat-config", "2", "if", "eth1", "redirect_addr",  "192.168.1.100",  "192.168.2.1"};
     //char * ipfw_nat1[] = {"add", "nat", "1", "ip", "from", "192.168.2.100", "to","192.168.1.100"};
     //char * ipfw_nat2[] = {"add", "nat", "2", "ip", "from", "192.168.2.100", "to","192.168.2.1"};
    
    //vnet_ipfw_init();
    //ipfw_nat_init();
    //struct cfg_nat cfg;

    //(*ipfw_nat_cfg_ptr)(&cfg);
    //ipfw_config_nat(sizeof(ipfw_nat_config2)/sizeof(char*), ipfw_nat_config2);
    //ipfw_config_nat(sizeof(ipfw_nat_config1)/sizeof(char*), ipfw_nat_config1);
     
    //ipfw_add(&ipfw_nat2);
    //ipfw_add(&ipfw_nat1);
    //ipfw_add(&ipfw_command1);
    //ipfw_add(&ipfw_command2);
    init_all_network_interfaces();
    //routing

    cyg_route_init();
    cyg_route_reinit();
    //example - transfers packets from 192.168.5.0/24 to 192.168.2.100 via eth0
    //add_route("eth0", "192.168.5.1", "255.255.255.0", "192.168.2.100");

    
    //mandatory for proper routing, do not remove
    add_route("eth0", "192.168.2.100", "255.255.255.0", "192.168.2.100");
    add_route("eth1", "192.168.1.100", "255.255.255.0", "192.168.1.100");


    show_network_tables(printf);
    printf("Hello, eCos world!\n");


    while (1) {
        printf("Sleeping\n");
        cyg_thread_delay(1000);
    }
    return 0;
}

