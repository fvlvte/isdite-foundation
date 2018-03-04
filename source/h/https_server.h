#ifndef ISDITE_FOUNDATION_HTTPS_SERVER
#define ISDITE_FOUNDATION_HTTPS_SERVER

struct isdite_net_httpsServer_endpoint
{
  char * literalName;
  void * handler;
};

struct isdite_net_httpsServer_vhost
{
  char * literalName;
  int getEndpointsSize;
  struct isdite_net_httpsServer_endpoint * getEndpoints[1024];
  int postEndpointsSize;
  struct isdite_net_httpsServer_endpoint * postEndpoints[1024];
};

typedef struct isdite_net_httpsServer_vhost* is_httpsVhost;

struct isdite_net_httpsServer
{
  void* cert;
  void * tcpHandle;
  int vhostCount;
  struct isdite_net_httpsServer_vhost * virtualHostTable[64];
};
typedef void* is_tcpServer;
typedef void* is_tcpClient;
typedef struct isdite_net_httpsServer* is_httpsServer;
typedef const char* is_string;

struct isdite_net_httpsServer * isdite_net_httpsServer_create(const char * ip, int port, const char * certificatePath, const char * privateKeyPath);
struct isdite_net_httpsServer_vhost * isdite_net_httpsServer_addVirtualHost(struct isdite_net_httpsServer * instance, const char * hostName);
void isdite_net_httpsServer_bindEndpoint(struct isdite_net_httpsServer_vhost * vhost, const char * path, const char * method, void * handler);
void isdite_net_httpsServer_join(struct isdite_net_httpsServer * instance);

/*
struct _is_qtls_rsa4096_cert
{
  int iIdentType;
  rsa_key sPrivateKey;
  void * pCertificate;
  unsigned int uiCertificateSize;
};
*/

#endif
