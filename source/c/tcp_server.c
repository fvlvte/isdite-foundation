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
#include <signal.h>

/* local includes */

#include "tcp_server.h"
#include "log.h"
#include "ierr.h"

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
#define _ISDITE_TCPSRV_MAX_CLI          100000// Maximum count of active connections (and size of the connection pool).
#define _ISDITE_TCPSRV_CBACKLOG         1024  // Connection backlog.
#define _ISDITE_TCPSRV_KEEPALIVE              // Should we use keep alive?
#define _ISDITE_EQUEUE_SZ                1024  // Epoll queue event buffer size.

/* internal structure definition */

#define _ISDITE_TCPSRV_CLI_STATE_OUT 0
#define _ISDITE_TCPSRV_CLI_STATE_EST 1

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

#ifdef ISIDTE_WPP
  /* worker pool preferences */
  int prefWorkerThread;
#endif

#ifdef ISDITE_NETSTAT
  /* statistics */
  int establishedTimestamp;
  int lastActiveTimestamp;

  int packetIn;
  int packetOut;

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
  struct _isdite_fdn_tcpSrv_cliDesc * clientStack[_ISDITE_TCPSRV_MAX_CLI];
  int clientStackTop;

  struct _isdite_fdn_tcpSrv_cliDesc clientPool[_ISDITE_TCPSRV_MAX_CLI];



  /* net i/o worker thread */
  pthread_t workerFd;

  int work;

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

static inline void _isdite_fdn_tcpSrv_finalizeCon(struct _isdite_fdn_tcpSrv_srvDesc * desc, struct _isdite_fdn_tcpSrv_cliDesc * cliDesc)
{
  printf("CONDEAD\n");
  shutdown(cliDesc->sock, 2);
  epoll_ctl(desc->epollFd, EPOLL_CTL_DEL, cliDesc->sock, NULL);
  close(cliDesc->sock);

  cliDesc->status = _ISDITE_TCPSRV_CLI_STATE_OUT;
  desc->clientStack[++desc->clientStackTop] = cliDesc;
  desc->connAlive--;
}

void _isdite_fn_tcpServer_netIoWorker(struct _isdite_fdn_tcpSrv_srvDesc * desc)
{
  struct epoll_event eventBuffer[_ISDITE_EQUEUE_SZ]; // Event buffer.
  int eventGot;
  int inSz;

  sigset_t signalMask;
  sigemptyset(&signalMask);
  sigaddset(&signalMask, SIGTERM);

  while(desc->work == 1)
  {
    eventGot = epoll_pwait(desc->epollFd, eventBuffer, _ISDITE_EQUEUE_SZ, -1, &signalMask);

    if(eventGot == -1)
      break;

    for(int i = 0; i < eventGot; i++)
    {
      if(eventBuffer[i].data.u64 == desc->netSockFd) // New connection.
      {
        while(1==1)
        {
          printf("Accept\n");
          struct _isdite_fdn_tcpSrv_cliDesc * cliDesc = desc->clientStack[desc->clientStackTop];

          socklen_t sz = sizeof(cliDesc->addrInfo);

          cliDesc->sock = accept(desc->netSockFd, (struct sockaddr*)&cliDesc->addrInfo, &sz);

          if(cliDesc->sock == -1)
            break;

          _isdite_fn_tcpServer_setSocketNonBlock(cliDesc->sock);

          cliDesc->status = _ISDITE_TCPSRV_CLI_STATE_EST;
          cliDesc->userDataPtr = cliDesc->userData;

          #ifdef ISIDTE_WPP
          cliDesc->prefWorkerThread = -1;
          #endif

          #ifdef ISDITE_NETSTAT
          cliDesc->establishedTimestamp = (int)time(NULL);
          cliDesc->lastActiveTimestamp = cliDesc->establishedTimestamp;

          cliDesc->bytesIn = 0;
          cliDesc->bytesOut = 0;

          cliDesc->packetIn = 0;
          cliDesc->packetOut = 0;

          cliDesc->fingerprintGuid = -1;

          desc->connPassed++;
          desc->connAlive++;
          #endif

          struct epoll_event event;
          event.events = EPOLLIN;
          event.data.ptr = cliDesc;

          epoll_ctl(desc->epollFd, EPOLL_CTL_ADD, cliDesc->sock, &event);

          desc->clientStackTop--;
        }
      }
      else // Client data.
      {
        struct _isdite_fdn_tcpSrv_cliDesc * cliDesc =
          (struct _isdite_fdn_tcpSrv_cliDesc *)eventBuffer[i].data.ptr;

        inSz = recv(cliDesc->sock, cliDesc->userDataPtr, _ISDITE_TCPSRV_CLI_UDATA_SIZE, 0);

        if(inSz == 0)
          _isdite_fdn_tcpSrv_finalizeCon(desc, cliDesc);
        else
        {
          ((char*)cliDesc->userDataPtr)[inSz] = 0x00;

          printf("got client packet\n");
          printf("%s\n", cliDesc->userDataPtr);
        }
      }
    }
  }
}

isdite_fn_tcp isdite_fn_tcpServer_create(int port)
{
  // NOTE: Consider switching to malloc, much faster, wow. /fvlvte 22.02.18
  struct _isdite_fdn_tcpSrv_srvDesc * srvDesc =
    (struct _isdite_fdn_tcpSrv_srvDesc *)calloc(sizeof *srvDesc, 1);

  // We have allocated really huge block of memory, it's really worth to check.
  if(srvDesc == NULL)
  {
    isdite_fdn_raiseThreadIntError(ISERR_OOM);
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to allocate memory for server descriptor (%d).",
      errno
    );

    return NULL; // Shoop da whoop.
  }

  for(int i = 0; i < _ISDITE_TCPSRV_MAX_CLI ;i++)
    srvDesc->clientStack[i] = &srvDesc->clientPool[i];

  srvDesc->clientStackTop = _ISDITE_TCPSRV_MAX_CLI - 1;

  #ifdef ISDITE_NETSTAT
  srvDesc->connAlive = 0;
  srvDesc->connPassed = 0;
  #endif

  // We need to create IPv4 TCP socket so AF_INET and SOCK_STREAM.
  srvDesc->netSockFd = socket(AF_INET, SOCK_STREAM, 0);

  srvDesc->work = 1;

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

  struct epoll_event event;
  event.events = EPOLLIN |  EPOLLET;
  event.data.u64 = srvDesc->netSockFd;

  epoll_ctl(srvDesc->epollFd, EPOLL_CTL_ADD, srvDesc->netSockFd, &event);

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

  free(srvDesc);
  srvDesc = NULL;

  cleanExit:
  return srvDesc;
}

#undef _ISDITE_TCPSRV_CLI_UDATA_SIZE
#undef _ISDITE_TCPSRV_MAX_CLI
#undef _ISDITE_TCPSRV_KEEPALIVE
#undef _ISDITE_TCPSRV_CBACKLOG
