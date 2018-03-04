#ifndef ISDITE_FOUNDATION_TCPSERVER
#define ISDITE_FOUNDATION_TCPSERVER

typedef void* isdite_fn_tcp;

isdite_fn_tcp isdite_fn_tcpServer_create(char * ip, int port, int maxcon);
void isdite_net_tcpServer_bindPacketHandler(isdite_fn_tcp server, void * handler, void * custom);
void isdite_net_tcpServer_join(isdite_fn_tcp server);
void isdite_net_tcpServer_bindTlsCert(isdite_fn_tcp server, void* cert);

#endif
