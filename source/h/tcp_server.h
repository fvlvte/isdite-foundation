#ifndef ISDITE_FOUNDATION_TCPSERVER
#define ISDITE_FOUNDATION_TCPSERVER

typedef void* isdite_fn_tcp;

isdite_fn_tcp isdite_fn_tcpServer_create(char * ip, int port, int maxcon);

#endif
