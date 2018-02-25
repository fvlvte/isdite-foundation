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
#include <arpa/inet.h>
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
#include "qtls.h"

/* local defs cfg - plz undef at end, dont do preprocessor shitparadise */

#define _ISDITE_TCPSRV_CLI_UDATA_SIZE   8192  // Preserved userdata buffer per client.
#define _ISDITE_TCPSRV_CBACKLOG         1024  // Connection backlog.
#define _ISDITE_TCPSRV_KEEPALIVE              // Should we use keep alive?
#define _ISDITE_EQUEUE_SZ               1024  // Epoll queue event buffer size.

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

  struct isdite_fdn_qtls_context ctx;

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
  struct _isdite_fdn_tcpSrv_cliDesc ** clientStack;
  int clientStackTop;

  int logicThCount;

  #ifdef ISIDTE_WPP
  int conThrBalancer;
  #endif

  struct _isdite_fdn_tcpSrv_cliDesc * clientPool;

  int maxCon;

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
     isdite_fdn_fsyslog
     (
       IL_ERRO,
       "Failed to obtain socket flags (%d).",
       errno
     );

     return;
   }
   #endif

   res = fcntl(fd, F_SETFL, res | O_NONBLOCK); // Make socket nonblocking.

   #if defined(ISDITE_DEBUG) || defined(ISDITE_PEDANTIC_CHECKLOG)
   if(res == -1)
   {
     isdite_fdn_fsyslog
     (
       IL_ERRO,
       "Failed to update socket flags (%d).",
       errno
     );

     return;
   }
   #endif
}

static inline void _isdite_fdn_tcpSrv_finalizeCon
(
  struct _isdite_fdn_tcpSrv_srvDesc * desc,
  struct _isdite_fdn_tcpSrv_cliDesc * cliDesc
)
{
  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Finalizing connection ID %s:%d.",
    inet_ntoa(cliDesc->addrInfo.sin_addr),
    cliDesc->addrInfo.sin_port
  );
  #endif

  shutdown(cliDesc->sock, 2);
  epoll_ctl(desc->epollFd, EPOLL_CTL_DEL, cliDesc->sock, NULL);
  close(cliDesc->sock);

  cliDesc->status = _ISDITE_TCPSRV_CLI_STATE_OUT;
  desc->clientStack[++desc->clientStackTop] = cliDesc;

  #ifdef ISDITE_NETSTAT
  desc->connAlive--;
  #endif
}

void _isdite_fn_tcpServer_netIoWorker(struct _isdite_fdn_tcpSrv_srvDesc * desc)
{
  struct epoll_event eventBuffer[_ISDITE_EQUEUE_SZ];
  int eventGot;
  int inSz;

  sigset_t signalMask;
  sigemptyset(&signalMask);
  sigaddset(&signalMask, SIGTERM);

  while(desc->work == 1)
  {
    eventGot = epoll_pwait
    (
      desc->epollFd,
      eventBuffer,
      _ISDITE_EQUEUE_SZ,
      -1,
      &signalMask
    );

    if(eventGot == -1)
      break;

    for(int i = 0; i < eventGot; i++)
    {
      if(eventBuffer[i].data.u64 == desc->netSockFd)
      {
        while(1==1)
        {
          struct _isdite_fdn_tcpSrv_cliDesc * cliDesc =
            desc->clientStack[desc->clientStackTop];

          socklen_t sz = sizeof(cliDesc->addrInfo);

          cliDesc->sock = accept
            (
              desc->netSockFd,
              (struct sockaddr*)&cliDesc->addrInfo,
              &sz
            );

          if(cliDesc->sock == -1)
            break;

          memset(&cliDesc->ctx, 0, sizeof(cliDesc->ctx));
          cliDesc->ctx.sockFd = cliDesc->sock;

          int buffersize = 8*1024;
          setsockopt
          (
            cliDesc->sock,
            SOL_SOCKET,
            SO_SNDBUF,
            (char *)&buffersize,
            sizeof(buffersize)
          );

          buffersize = 8*1024;
          setsockopt
          (
            cliDesc->sock,
            SOL_SOCKET,
            SO_RCVBUF,
            (char *)&buffersize,
            sizeof(buffersize)
          );

          _isdite_fn_tcpServer_setSocketNonBlock(cliDesc->sock);

          cliDesc->status = _ISDITE_TCPSRV_CLI_STATE_EST;
          cliDesc->userDataPtr = cliDesc->userData;

          #ifdef ISIDTE_WPP
          cliDesc->prefWorkerThread =
            srvDesc->conThrBalancer++ % srvDesc->logicThCount;
          #endif

          #ifdef ISDITE_NETSTAT
          cliDesc->establishedTimestamp = (int)time(NULL);
          cliDesc->lastActiveTimestamp = cliDesc->establishedTimestamp;

          cliDesc->bytesIn = 0;
          cliDesc->bytesOut = 0;

          cliDesc->packetIn = 0;
          cliDesc->packetOut = 0;

          cliDesc->fingerprintGuid = -1;

          cliDesc->ctx.dataPtr = cliDesc->ctx.buf;

          desc->connPassed++;
          desc->connAlive++;
          #endif

          struct epoll_event event;
          event.events = EPOLLIN;
          event.data.ptr = cliDesc;

          epoll_ctl(desc->epollFd, EPOLL_CTL_ADD, cliDesc->sock, &event);

          desc->clientStackTop--;

          #ifdef ISDITE_DEBUG
          isdite_fdn_fsyslog
          (
            IL_TRAC,
            "Accepted client %s:%d.",
            inet_ntoa(cliDesc->addrInfo.sin_addr),
            cliDesc->addrInfo.sin_port
          );
          #endif
        }
      }
      else // Client data.
      {
        struct _isdite_fdn_tcpSrv_cliDesc * cliDesc =
          (struct _isdite_fdn_tcpSrv_cliDesc *)eventBuffer[i].data.ptr;

        #ifdef ISDITE_TLS

        inSz = recv
        (
          cliDesc->sock,
          cliDesc->ctx.buf + cliDesc->ctx.dataSz,
          8192 - cliDesc->ctx.dataSz,
          0
        );

        cliDesc->ctx.dataSz += inSz;

        if(inSz == 0)
          _isdite_fdn_tcpSrv_finalizeCon(desc, cliDesc);
        else
        {
          int iRes = isdite_fdn_qtls_processInput(&cliDesc->ctx);

        //  if(iRes == ISDITE_QTLS_NOT_FINISHED_YET)
            //_isdite_fdn_tcpSrv_finalizeCon(desc, cliDesc);
        }


        #else
        inSz = recv
        (
          cliDesc->sock,
          cliDesc->userDataPtr,
          _ISDITE_TCPSRV_CLI_UDATA_SIZE,
          0
        );

        if(inSz == 0)
          _isdite_fdn_tcpSrv_finalizeCon(desc, cliDesc);
        else
        {
          #ifdef ISDITE_DEBUG
          isdite_fdn_fsyslog
          (
            IL_TRAC,
            "Received packet from client (%d B), sending mocked response.",
            inSz
          );
          #endif

          send(cliDesc->sock, "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=UTF-8\r\nServer: ira\r\nConnection: close\r\nContent-Length: 9\r\n\r\nHELLO IRA", strlen("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=UTF-8\r\nServer: ira\r\nConnection: close\r\nContent-Length: 9\r\n\r\nHELLO IRA"), 0);
        }
        #endif
      }
    }
  }
}

isdite_fn_tcp isdite_fn_tcpServer_create(char * ip, int port, int maxcon)
{
  _isdite_fdn_qtls_initCert();
  #ifdef ISDITE_DEBUG
  float memReq = (((float)sizeof(void*) * (float)maxcon) +
    ((float)sizeof(struct _isdite_fdn_tcpSrv_cliDesc) * (float)maxcon) +
    (float)sizeof(struct _isdite_fdn_tcpSrv_srvDesc)) / (1024.0f * 1024.0f);

  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Net worker I/O cache will require %0.3f MB of memory, trying to allocate "
    "and prepare client stack.",
    memReq
  );
  #endif

  struct _isdite_fdn_tcpSrv_srvDesc * srvDesc =
    (struct _isdite_fdn_tcpSrv_srvDesc *)malloc(sizeof *srvDesc);

  if(srvDesc == NULL)
  {
    isdite_fdn_raiseThreadIntError(ISERR_OOM);
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to allocate memory for server descriptor (%d).",
      errno
    );

    return NULL;
  }

  // NOTE: It's worth to consider to profile indirect malloc per client.
  //       It can be valuable because of the CPU cache.
  srvDesc->clientPool = malloc(sizeof(*srvDesc->clientPool) * maxcon);

  if(srvDesc->clientPool == NULL)
  {
    isdite_fdn_raiseThreadIntError(ISERR_OOM);
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to allocate memory for client pool (%d).",
      errno
    );

    free(srvDesc);

    return NULL;
  }

  srvDesc->clientStack = malloc(sizeof(void*) * maxcon);

  if(srvDesc->clientStack == NULL)
  {
    isdite_fdn_raiseThreadIntError(ISERR_OOM);
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to allocate memory for client stack (%d).",
      errno
    );

    free(srvDesc->clientPool);
    free(srvDesc);

    return NULL;
  }

  for(int i = 0; i < maxcon ;i++)
  {
    struct _isdite_fdn_tcpSrv_cliDesc * desc = &srvDesc->clientPool[i];
    memset(desc, 0, sizeof *desc); // Enforce memory commit.
    srvDesc->clientStack[i] = desc;
  }

  srvDesc->clientStackTop = maxcon - 1;

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Successfully allocated client stack and server descriptor."
  );
  #endif

  srvDesc->maxCon = maxcon;

  // For cleanup purposes.
  srvDesc->netSockFd = 0;
  srvDesc->epollFd = 0;

  // Thread flag.
  srvDesc->work = 1;

  #ifdef ISIDTE_WPP
  srvDesc->conThrBalancer = 0;
  #endif

  #ifdef ISDITE_NETSTAT
  srvDesc->connAlive = 0;
  srvDesc->connPassed = 0;
  #endif

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Creating net socket."
  );
  #endif

  // We need to create IPv4 TCP socket so AF_INET and SOCK_STREAM.
  srvDesc->netSockFd = socket(AF_INET, SOCK_STREAM, 0);

  if(srvDesc->netSockFd == -1)
  {
    srvDesc->netSockFd = 0;

    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to create server socket (%d).",
      errno
    );

    goto errClean;
  }

  // Set proper flag for acceptor socket.
  _isdite_fn_tcpServer_setSocketNonBlock(srvDesc->netSockFd);

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Creating epoll event queue."
  );
  #endif

  // Create epoll queue.
  srvDesc->epollFd = epoll_create1(0);

  if(srvDesc->epollFd == -1)
  {
    srvDesc->epollFd = 0;

    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to create epoll event queue (%d).",
      errno
    );

    goto errClean;
  }

  // Bind acceptor socket to given port.
  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Binding acceptor socket on %s:%d.",
    ip,
    port
  );
  #endif

  struct sockaddr_in serverInfo;
  serverInfo.sin_family = AF_INET;
  serverInfo.sin_addr.s_addr = inet_addr(ip);
  serverInfo.sin_port = htons(port);

  if
  (
    bind
    (
      srvDesc->netSockFd,
      (struct sockaddr *)&serverInfo, sizeof(serverInfo)
    ) == -1
  )
  {
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to bind socket on %s:%d (%d).",
      ip,
      port,
      errno
    );

    goto errClean;
  }

  // Put acceptor socket into listening state.
  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Turning server acceptor socket into the listening state.",
    port
  );
  #endif

  if(listen(srvDesc->netSockFd, _ISDITE_TCPSRV_CBACKLOG) == -1)
  {
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to turn acceptor socket into the listening state (%d).",
      errno
    );

    goto errClean;
  }

  // Add acceptor socket fd to the epoll.

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Adding acceptor socket descriptor to the epoll event queue.",
    port
  );
  #endif

  struct epoll_event event;
  event.events = EPOLLIN;
  event.data.u64 = srvDesc->netSockFd;

  if
  (
    epoll_ctl(srvDesc->epollFd, EPOLL_CTL_ADD, srvDesc->netSockFd, &event) != 0
  )
  {
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to add acceptor socket descriptor to epoll queue (%d).",
      errno
    );

    goto errClean;
  }

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Creating worker thread.",
    port
  );
  #endif

  // Create worker thread.
  int res = pthread_create
  (
    &srvDesc->workerFd,
    NULL,
    (void * (*)(void *))&_isdite_fn_tcpServer_netIoWorker,
    srvDesc
  );

  if(res != 0)
  {
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to create net I/O worker thread (%d).",
      errno
    );

    goto errClean;
  }

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Basic server initialization finished successfully!"
  );
  #endif

  goto cleanExit;

  errClean:

  if(srvDesc->epollFd != 0)
    close(srvDesc->epollFd);

  if(srvDesc->netSockFd != 0)
    close(srvDesc->netSockFd);

  free(srvDesc->clientStack);
  free(srvDesc->clientPool);

  free(srvDesc);

  srvDesc = NULL;

  cleanExit:
  return srvDesc;
}

#undef _ISDITE_TCPSRV_CLI_UDATA_SIZE
#undef _ISDITE_TCPSRV_KEEPALIVE
#undef _ISDITE_TCPSRV_CBACKLOG
