#include "https_server.h"
#include "tcp_server.h"
#include "mem.h"
#include "qtls.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>

void is_net_httpsServer_inputHandler(void* internal, void* internal2, void* data, int size, void (*callback)(void *, void*, void*, int, int), struct isdite_net_httpsServer * instance)
{
  char * input = (char*)data;

  char hostBuf[1024];
  int hostCounter = 0;
  char * host = strstr(data, "Host:");

  ((char*)data)[size] = 0x00;

  if(host == NULL)
  {
    callback(internal, internal2, "HTTP/1.1 404 FORBIDDEN\r\nContent-Type: application/json; charset=UTF-8\r\nServer: ira\r\nContent-Length: 23\r\n\r\n{\"message\":\"FORBIDDEN\"}", strlen("HTTP/1.1 404 FORBIDDEN\r\nContent-Type: application/json; charset=UTF-8\r\nServer: ira\r\nContent-Length: 23\r\n\r\n{\"message\":\"FORBIDDEN\"}"), 0);
    return;
  }

  if(host[5] = ' ')
  {
    host++;
  }
  host += 5;

  while(*host != '\r')
    hostBuf[hostCounter++] = *host++;

  hostBuf[hostCounter] = 0x00;

  struct isdite_net_httpsServer_vhost * vhost = NULL;

  for(int i = 0; i < instance->vhostCount;i++)
  {
    if(strcmp(hostBuf, instance->virtualHostTable[i]->literalName) == 0)
    {
      vhost = instance->virtualHostTable[i];
      break;
    }
  }

  if(vhost == NULL)
  {
    callback(internal, internal2, "HTTP/1.1 404 FORBIDDEN\r\nContent-Type: application/json; charset=UTF-8\r\nServer: ira\r\nContent-Length: 23\r\n\r\n{\"message\":\"FORBIDDEN\"}", strlen("HTTP/1.1 404 FORBIDDEN\r\nContent-Type: application/json; charset=UTF-8\r\nServer: ira\r\nContent-Length: 23\r\n\r\n{\"message\":\"FORBIDDEN\"}"), 0);
    return;
  }

  if(*(char*)data == 'G')
  {
    struct isdite_net_httpsServer_endpoint * ep = NULL;

    char pathBuffer[1024];
    int pathCounter = 0;
    char * ptr = ((char*)data) + 4;

    while(*ptr != ' ')
      pathBuffer[pathCounter++] = *ptr++;

    pathBuffer[pathCounter] = 0x00;

    for(int i = 0; i < vhost->getEndpointsSize; i++)
    {
      if(strcmp(pathBuffer, vhost->getEndpoints[i]->literalName) == 0)
        ep = vhost->getEndpoints[i];
    }

    if(ep == NULL)
    {
      callback(internal, internal2, "HTTP/1.1 404 FORBIDDEN\r\nContent-Type: application/json; charset=UTF-8\r\nServer: ira\r\nContent-Length: 23\r\n\r\n{\"message\":\"FORBIDDEN\"}", strlen("HTTP/1.1 404 FORBIDDEN\r\nContent-Type: application/json; charset=UTF-8\r\nServer: ira\r\nContent-Length: 23\r\n\r\n{\"message\":\"FORBIDDEN\"}"), 0);
      return;
    }

    void (*fCallback) (void*, void*, void*, int, void*, void*);
    fCallback = ep->handler;

    fCallback(internal, internal2, data, size, callback, instance);
  }
  else if(*(char*)data == 'P')
  {
    struct isdite_net_httpsServer_endpoint * ep = NULL;

    char pathBuffer[1024];
    int pathCounter = 0;
    char * ptr = ((char*)data) + 5;

    while(*ptr != ' ')
      pathBuffer[pathCounter++] = *ptr++;

    pathBuffer[pathCounter] = 0x00;

    for(int i = 0; i < vhost->postEndpointsSize; i++)
    {
      if(strcmp(pathBuffer, vhost->postEndpoints[i]->literalName) == 0)
        ep = vhost->postEndpoints[i];
    }

    if(ep == NULL)
    {
      callback(internal, internal2, "HTTP/1.1 404 FORBIDDEN\r\nContent-Type: application/json; charset=UTF-8\r\nServer: ira\r\nContent-Length: 23\r\n\r\n{\"message\":\"FORBIDDEN\"}", strlen("HTTP/1.1 404 FORBIDDEN\r\nContent-Type: application/json; charset=UTF-8\r\nServer: ira\r\nContent-Length: 23\r\n\r\n{\"message\":\"FORBIDDEN\"}"), 0);
      return;
    }

    void (*fCallback) (void*, void*, void*, int, void*, void*);
    fCallback = ep->handler;

    fCallback(internal, internal2, data, size, callback, instance);
  }
  else
  {
    callback(internal, internal2, "HTTP/1.1 404 FORBIDDEN\r\nContent-Type: application/json; charset=UTF-8\r\nServer: ira\r\nContent-Length: 23\r\n\r\n{\"message\":\"FORBIDDEN\"}", strlen("HTTP/1.1 404 FORBIDDEN\r\nContent-Type: application/json; charset=UTF-8\r\nServer: ira\r\nContent-Length: 23\r\n\r\n{\"message\":\"FORBIDDEN\"}"), 0);
  }
}

struct isdite_net_httpsServer * isdite_net_httpsServer_create(const char * ip, int port, const char * certificatePath, const char * privateKeyPath)
{
  struct isdite_net_httpsServer * pInstance = isdite_mem_heapCommit(sizeof *pInstance);

  is_qtls_loadCertificateFromFile(IS_QTLS_CERT_RSA4096_WITH_SHA512, certificatePath, privateKeyPath, &pInstance->cert);

  pInstance->vhostCount = 0;

  pInstance->tcpHandle = isdite_fn_tcpServer_create((char*)ip, port, 1000);

  isdite_net_tcpServer_bindPacketHandler(pInstance->tcpHandle, &is_net_httpsServer_inputHandler, pInstance);
  isdite_net_tcpServer_bindTlsCert(pInstance->tcpHandle, pInstance->cert);

  return pInstance;
}

struct isdite_net_httpsServer_vhost * isdite_net_httpsServer_addVirtualHost(struct isdite_net_httpsServer * instance, const char * hostName)
{
  struct isdite_net_httpsServer_vhost * pInstance = isdite_mem_heapCommit(sizeof * pInstance);

  pInstance->getEndpointsSize = 0;
  pInstance->postEndpointsSize = 0;
  int len = strlen(hostName) + 1;
  pInstance->literalName = isdite_mem_heapCommit(len);
  memcpy(pInstance->literalName, hostName, len);

  instance->virtualHostTable[instance->vhostCount++] = pInstance;

  return pInstance;
}
void isdite_net_httpsServer_bindEndpoint(struct isdite_net_httpsServer_vhost * vhost, const char * path, const char * method, void * handler)
{
  struct isdite_net_httpsServer_endpoint * pInstance = isdite_mem_heapCommit(sizeof *pInstance);

  int len = strlen(path) + 1;
  pInstance->literalName = isdite_mem_heapCommit(len);
  memcpy(pInstance->literalName, path, len);

  pInstance->handler = handler;

  if(strcmp(method, "GET") == 0)
  {
    vhost->getEndpoints[vhost->getEndpointsSize++] = pInstance;
  }
  else
  {
    vhost->postEndpoints[vhost->postEndpointsSize++] = pInstance;
  }
}

void isdite_net_httpsServer_join(struct isdite_net_httpsServer * instance)
{
  isdite_net_tcpServer_join(instance->tcpHandle);
}
