/* netprobe.c — static helper baked into test images.
 * Lists network interfaces via getifaddrs(3) (rtnetlink under the hood),
 * proving network-namespace isolation without needing /proc or /sys. */
#include <stdio.h>
#include <ifaddrs.h>
#include <string.h>

int main(void)
{
    struct ifaddrs *ifas, *p;
    if (getifaddrs(&ifas)) { perror("getifaddrs"); return 1; }
    int n = 0;
    for (p = ifas; p; p = p->ifa_next) {
        if (p->ifa_addr && p->ifa_addr->sa_family == 2 /*AF_INET*/) {
            printf("iface: %s\n", p->ifa_name);
            n++;
        }
    }
    if (!n) printf("no IPv4 interfaces visible\n");
    freeifaddrs(ifas);
    return 0;
}
