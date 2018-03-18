#ifndef ISDITE_FOUNDATION_UDP_SERVER
#define ISDITE_FOUNDATION_UDP_SERVER
#include <stdint.h>

typedef void* isUdpServer;

int isdite_net_udpServer(const char * sIpToBind, uint16_t ui16Port, const char ** sAllowedOrigin, unsigned int uiAllowedOriginCount, void * pPacketHandler); /**/

void isdite_net_udpServerFree(isUdpServer hInstance);

#endif
