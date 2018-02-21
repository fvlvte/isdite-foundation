#define ISDITE_TPLATFORM_LINUX 0

#if ISDITE_PLATFORM != ISDITE_TPLATFORM_LINUX
#error "Not implemented."
#endif

#undef ISDITE_TPLATFORM_LINUX

/* global includes */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

/* local includes */

#include "tcp_server.h"
#include "log.h"

/* old - delete me plz */

struct _isdite_fn_tcpServer_client
{
  int internalId;
  int status;
  int socket;
  struct sockaddr_in sai;
};

const char * mocked = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{\"hello\":\"world\"}";

struct _isdite_fn_tcpServer_descriptorImpl
{
  int acceptorSocket;
  int epollDescriptor;

  pthread_t workerDescriptor;
};

/* local defs cfg - plz undef at end, dont do preprocessor shitparadise */

#define _ISDITE_TCPSRV_CLI_UDATA_SIZE   8192  // Preserved userdata buffer per client.
#define _ISDITE_TCPSRV_MAX_CLI          10000 // Maximum count of active connections (and size of the connection pool).
#define _ISDITE_TCPSRV_CBACKLOG         1024  // Connection backlog.
#define _ISDITE_TCPSRV_KEEPALIVE              // Should we use keep alive?

/* internal structure definition */

struct _isdite_fdn_tcpSrv_cliDesc /* client descriptor */
{
  /* os info tracker */
  int sock;
  int status;

  /* user data - subject to change */
  u_int8_t userData[_ISDITE_TCPSRV_CLI_UDATA_SIZE];
  void * userDataPtr;

  /* remote connection desc */
  struct sockaddr_in addrInfo;
  int addrInfoLen;

#ifdef ISIDTE_WPP
  /* worker pool preferences */
  int prefWorkerThread;
#endif

#ifdef ISDITE_NETSTAT
  /* statistics */
  int establishedTimestamp;
  int lastActiveTimestamp;

  int bytesIn;
  int bytesOut;

  int fingerprintGuid;
#endif
};

struct _isdite_fdn_tcpSrv_srvDesc /* server descriptor */
{
  /* internal sys descriptors */
  int epollFd;
  int netSockFd;

  /* client cache, !NEVER! create new connections on heap */
  struct _isdite_fdn_tcpSrv_cliDesc * clientPool;
  struct _isdite_fdn_tcpSrv_cliDesc ** clientStack;
  int clientStackTop;

  /* net i/o worker thread */
  pthread_t workerFd;

#ifdef ISDITE_NETSTAT
  /* server statistics */
  int connAlive;
  int connPassed;
#endif
};

/* method impl */

static inline void _isdite_fn_tcpServer_setSocketNonBlock(int fd)
{
   int res = fcntl(fd, F_GETFL, 0);

   #if defined(ISDITE_DEBUG) || defined(ISDITE_PEDANTIC_CHECKLOG)

   if(res == -1)
   {
     isdite_fn_fsyslog(ISDITE_LOG_SEVERITY_ERRO, "<_isdite_fn_tcpServer_setSocketNonBlock> Failed to get socket flags for fd %d.", fd);
     return;
   }

   #endif

   res = fcntl(fd, F_SETFL, res | O_NONBLOCK);

   #if defined(ISDITE_DEBUG) || defined(ISDITE_PEDANTIC_CHECKLOG)

   if(res == -1)
   {
     isdite_fn_fsyslog(ISDITE_LOG_SEVERITY_ERRO, "<_isdite_fn_tcpServer_setSocketNonBlock> Failed to set socket flags for fd %d.", fd);
     return;
   }

   #endif
}

void * _isdite_fn_tcpServer_netIoWorker(struct _isdite_fn_tcpServer_descriptorImpl *  desc)
{
  int idCounter = 0;
  struct epoll_event events[1024];
  while(1==1)
  {
    int r = epoll_wait(desc->epollDescriptor, events, 1024, -1);

    for(int i = 0; i < r;i++)
    {
      if(events[i].data.u64 == desc->acceptorSocket) // Accept new connection.
      {
        while(1)
        {
          struct _isdite_fn_tcpServer_client * cliDesc = malloc(sizeof(struct _isdite_fn_tcpServer_client));

          socklen_t slt = sizeof(cliDesc->sai);

          int sck =  accept(desc->acceptorSocket, (struct sockaddr*)&cliDesc->sai, &slt);




          if(sck == -1)
          {
            free(cliDesc);
            break;
          }

          cliDesc->internalId = idCounter++;
          cliDesc->status = 1;

          _isdite_fn_tcpServer_setSocketNonBlock(sck);

          cliDesc->socket = sck;

          printf("Accepting connection %d\n", cliDesc->internalId);

          struct epoll_event event;

          event.events = EPOLLIN |  EPOLLET;
          event.data.ptr = cliDesc;

          epoll_ctl(desc->epollDescriptor, EPOLL_CTL_ADD, cliDesc->socket, &event);


        }
      }
      else // Process existing connection.
      {
        struct _isdite_fn_tcpServer_client * cliDesc = (struct _isdite_fn_tcpServer_client *)events[i].data.ptr;
        printf("Received data from %d connection - %s\n", cliDesc->internalId, "derp");

        send(cliDesc->socket, mocked, strlen(mocked), 0);
        shutdown(cliDesc->socket, 2);
        epoll_ctl(desc->epollDescriptor, EPOLL_CTL_DEL, cliDesc->socket, NULL);
        close(cliDesc->socket);

        free(cliDesc);
      }
    }

  }
  return NULL;
}

isdite_fn_tcp isdite_fn_tcpServer_create(int port)
{
  struct _isdite_fdn_tcpSrv_srvDesc * srvDesc =
    (struct _isdite_fdn_tcpSrv_srvDesc *)
      calloc(0, sizeof(struct _isdite_fdn_tcpSrv_srvDesc));

  #ifdef ISDITE_DEBUG
  if(srvDesc == NULL)
  {
    isdite_fn_fsyslog(ISDITE_LOG_SEVERITY_ERRO, "<isdite_fn_tcpServer_create> Failed to allocate memory for server descriptor (%d).", errno);

    return NULL;
  }
  #endif

  srvDesc->clientPool =
    (struct _isdite_fdn_tcpSrv_cliDesc*)
      malloc(sizeof(struct _isdite_fdn_tcpSrv_cliDesc) * _ISDITE_TCPSRV_MAX_CLI);

  #ifdef ISDITE_DEBUG
  if(srvDesc->clientPool == NULL)
  {
    isdite_fn_fsyslog(ISDITE_LOG_SEVERITY_ERRO, "<isdite_fn_tcpServer_create> Failed to allocate memory for client pool (%d).", errno);

    goto cleanExit;
  }
  #endif

  srvDesc->clientStack = (struct _isdite_fdn_tcpSrv_cliDesc**)
    malloc(sizeof(struct _isdite_fdn_tcpSrv_cliDesc*) * _ISDITE_TCPSRV_MAX_CLI);

  #ifdef ISDITE_DEBUG
  if(srvDesc->clientStack == NULL)
  {
    isdite_fn_fsyslog(ISDITE_LOG_SEVERITY_ERRO, "<isdite_fn_tcpServer_create> Failed to allocate memory for client stack (%d).", errno);

    goto cleanExit;
  }
  #endif

  for(int i = 0; i < _ISDITE_TCPSRV_MAX_CLI;i++)
    srvDesc->clientStack[i] = &srvDesc->clientPool[i];

  srvDesc->clientStackTop = _ISDITE_TCPSRV_MAX_CLI - 1;

  #ifdef ISDITE_NETSTAT
  srvDesc->connAlive = 0;
  srvDesc->connPassed = 0;
  #endif

  // We need to create IPv4 TCP socket so AF_INET and SOCK_STREAM.
  srvDesc->netSockFd = socket(AF_INET, SOCK_STREAM, 0);

  if(srvDesc->netSockFd == -1)
  {
    srvDesc->netSockFd = 0;

    isdite_fn_fsyslog(ISDITE_LOG_SEVERITY_ERRO, "<isdite_fn_tcpServer_create> Failed to create acceptor socket (%d).", errno);

    goto errClean;
  }

  // Set proper flag for acceptor socket.
  _isdite_fn_tcpServer_setSocketNonBlock(srvDesc->netSockFd);

  // Create epoll queue.
  srvDesc->epollFd = epoll_create1(0);

  if(srvDesc->epollFd == -1)
  {
    srvDesc->epollFd = 0;

    isdite_fn_fsyslog(ISDITE_LOG_SEVERITY_ERRO, "<isdite_fn_tcpServer_create> Failed to create epoll queue (%d).", errno);

    goto errClean;
  }

  // Bind acceptor socket to given port.
  struct sockaddr_in serverInfo;
  serverInfo.sin_family = AF_INET;
  serverInfo.sin_addr.s_addr = INADDR_ANY;
  serverInfo.sin_port = htons(port);

  if(bind(srvDesc->netSockFd, (struct sockaddr *)&serverInfo, sizeof(serverInfo)) == -1)
  {
    isdite_fn_fsyslog(ISDITE_LOG_SEVERITY_ERRO, "<isdite_fn_tcpServer_create> Failed to bind acceptor socket (%d).", errno);

    goto errClean;
  }

  // Put acceptor socket into listening state.
  if(listen(srvDesc->netSockFd, _ISDITE_TCPSRV_CBACKLOG) == -1)
  {
    isdite_fn_fsyslog(ISDITE_LOG_SEVERITY_ERRO, "<isdite_fn_tcpServer_create> Failed to set acceptor socket into listening state (%d).", errno);

    goto errClean;
  }

  // Create worker thread.
  int res = pthread_create(&srvDesc->workerFd, NULL, (void * (*)(void *))&_isdite_fn_tcpServer_netIoWorker, srvDesc);

  if(res != 0)
  {
    isdite_fn_fsyslog(ISDITE_LOG_SEVERITY_ERRO, "<isdite_fn_tcpServer_create> Failed to start network i/o worker thread (%d).", res);

    goto errClean;
  }

  goto cleanExit;

  errClean:

  if(srvDesc->epollFd != 0)
    close(srvDesc->epollFd);

  if(srvDesc->netSockFd != 0)
    close(srvDesc->netSockFd);

  if(srvDesc->clientPool != NULL)
    free(srvDesc->clientPool);

  if(srvDesc->clientStack != NULL)
    free(srvDesc->clientStack);

  free(srvDesc);
  srvDesc = NULL;

  cleanExit:
  return srvDesc;
}

#undef _ISDITE_TCPSRV_CLI_UDATA_SIZE
#undef _ISDITE_TCPSRV_MAX_CLI
#undef _ISDITE_TCPSRV_KEEPALIVE
#undef _ISDITE_TCPSRV_CBACKLOG
