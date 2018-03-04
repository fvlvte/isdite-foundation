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

#include "net/net_sock.in"
#include "tcp_server.h"
#include "log.h"
#include "ierr.h"
#include "qtls.h"
#include "mem.h"

/* local defs cfg - plz undef at end, dont do preprocessor shitparadise */

#define _ISDITE_TCPSRV_CLI_UDATA_SIZE   8192  // Preserved userdata buffer per client.
#define _ISDITE_TCPSRV_CBACKLOG         1024  // Connection backlog.
#define _ISDITE_TCPSRV_KEEPALIVE              // Should we use keep alive?
#define _ISDITE_EQUEUE_SZ               1024  // Epoll queue event buffer size.

/* internal structure definition */

#define _ISDITE_TCPSRV_CLI_STATE_OUT 0
#define _ISDITE_TCPSRV_CLI_STATE_EST 1

struct _isdite_fdn_tcpSrv_clientDesc /* client pServerDescriptor */
{
  /* basic info tracker */
  int iIntDescID;
  struct isdite_net_remoteSocketIn4 sClientSocket;
  int iStatus;

  /* user data - subject to change */
  u_int8_t userData[_ISDITE_TCPSRV_CLI_UDATA_SIZE];
  void * userDataPtr;

  struct isdite_fdn_qtls_context ctx;

#ifdef ISDITE_NETSTAT
  /* statistics */
  int iEstablishedTimestamp;
  int iLastActiveTimestamp;

  int iBytesIn;
  int iBytesOut;

  int iFingerprintId;
#endif
};

struct _isdite_fdn_tcpSrv_serverDesc /* server pServerDescriptor */
{
  struct isdite_net_localSocketIn4 sServerSocket;
  /* internal sys pServerDescriptors */
  int iEpollFd;

  /* client cache, !NEVER! create new connections on heap */
  struct _isdite_fdn_tcpSrv_clientDesc ** aClientStack;
  int iClientStackTop;

  struct _isdite_fdn_tcpSrv_clientDesc * aClientPool;

  int uiMaxConnections;

  void * pHandler;
  void * pCustom;

  void * pCert;

  /* net i/o worker thread */
  pthread_t iNetWorkerFd;

  int iEndJob;

#ifdef ISDITE_NETSTAT
  /* server statistics */
  int iConnectionsAlive;
  int iConnectionsPassed;
#endif
};

/* method impl */

static inline void _isdite_fdn_tcpSrv_finalizeCon
(
  struct _isdite_fdn_tcpSrv_serverDesc * pServerDesc,
  struct _isdite_fdn_tcpSrv_clientDesc * pClientDesc
)
{
  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Finalizing connection with pool ID %d.",
    pClientDesc->iIntDescID
  );
  #endif

  epoll_ctl
  (
    pServerDesc->iEpollFd,
    EPOLL_CTL_DEL,
    pClientDesc->sClientSocket.iSysFd,
    NULL
  );

  isdite_net_remoteSocketDisconnect_IN4(&pClientDesc->sClientSocket);

  isdite_mem_clear(pClientDesc, sizeof *pClientDesc);

  pServerDesc->aClientStack[++pServerDesc->iClientStackTop] = pClientDesc;

  #ifdef ISDITE_NETSTAT
  pServerDesc->iConnectionsAlive--;
  #endif
}

static void _is_net_tcpServer_cbWriteWrap(struct  _isdite_fdn_tcpSrv_serverDesc * pServerDesc, struct  _isdite_fdn_tcpSrv_clientDesc * pClientDesc, void * data, int size, int appendHeaders)
{
  if(data == NULL)
    _isdite_fdn_tcpSrv_finalizeCon(pServerDesc, pClientDesc);
  else
  {
    if(appendHeaders == 0)
      isdite_fdn_qtls_sendData(&pClientDesc->ctx, data, size, pServerDesc, pClientDesc);
    else
    {
      char outbuf[8192];
      int n = sprintf(outbuf, "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nServer: ira\r\nContent-Length: %d\r\n\r\n%s", size, (char*)data);
      isdite_fdn_qtls_sendData(&pClientDesc->ctx, outbuf, n, pServerDesc, pClientDesc);
    }
  }

}

static void _isdite_fn_tcpServer_netIoWorker(struct _isdite_fdn_tcpSrv_serverDesc * pServerDesc)
{
  // Variables.
  struct epoll_event aEventBuf[_ISDITE_EQUEUE_SZ];
  int iEventGot;
  int iInputSize;
  ISDITE_NET_INET4_ADDR_SYS sAddrInfoBuf;
  int iAddrInfoLen;
  void (*fCallback) (void*, void*, void*, int, void*, void*);
  uint8_t aInPacketBuffer[8192];

  // Epoll wait interrupt signal.

  sigset_t signalMask;
  sigemptyset(&signalMask);
  sigaddset(&signalMask, SIGTERM);

  while(pServerDesc->iEndJob == 0) // NOTE: Consider 1==1.
  {
    iEventGot = epoll_pwait
    (
      pServerDesc->iEpollFd,
      aEventBuf,
      _ISDITE_EQUEUE_SZ,
      -1,
      &signalMask
    );

    if(iEventGot == -1)
      break;

    for(int i = 0; i < iEventGot; i++)
    {
      if(aEventBuf[i].data.u64 == pServerDesc->sServerSocket.iSysFd)
      {
        while(1==1)
        {
          struct _isdite_fdn_tcpSrv_clientDesc * pClientDesc =
            pServerDesc->aClientStack[pServerDesc->iClientStackTop];

          if
          (
            isdite_net_socketAcceptFast_IN4
            (
              &pServerDesc->sServerSocket,
              &pClientDesc->sClientSocket,
              &sAddrInfoBuf,
              &iAddrInfoLen,
              ISDITE_NET_SOCK_OPT_NONBLOCK
            ) == IFAULT
          )
            break;

          int buffersize = 8*1024;
          setsockopt
          (
            pClientDesc->sClientSocket.iSysFd,
            SOL_SOCKET,
            SO_SNDBUF,
            (char *)&buffersize,
            sizeof(buffersize)
          );

          buffersize = 8*1024;
          setsockopt
          (
            pClientDesc->sClientSocket.iSysFd,
            SOL_SOCKET,
            SO_RCVBUF,
            (char *)&buffersize,
            sizeof(buffersize)
          );

          pClientDesc->iStatus = _ISDITE_TCPSRV_CLI_STATE_EST;
          pClientDesc->userDataPtr = pClientDesc->userData;
          pClientDesc->ctx.cert = pServerDesc->pCert;

          #ifdef ISDITE_NETSTAT
          pClientDesc->iEstablishedTimestamp = (int)time(NULL);
          pClientDesc->iLastActiveTimestamp = pClientDesc->iEstablishedTimestamp;

          pServerDesc->iConnectionsPassed++;
          pServerDesc->iConnectionsAlive++;
          #endif

          struct epoll_event sEvent;
          sEvent.events = EPOLLIN;
          sEvent.data.ptr = pClientDesc;

          epoll_ctl
          (
            pServerDesc->iEpollFd,
            EPOLL_CTL_ADD,
            pClientDesc->sClientSocket.iSysFd,
            &sEvent
          );

          pServerDesc->iClientStackTop--;

          #ifdef ISDITE_DEBUG
          isdite_fdn_fsyslog
          (
            IL_TRAC,
            "Accepted client %s:%d (Pool ID: %d).",
            inet_ntoa
            (
              *(struct in_addr*)&pClientDesc->sClientSocket.uAddr.ui32RemoteAddr
            ),
            pClientDesc->sClientSocket.ui16RemotePort,
            pClientDesc->iIntDescID
          );
          #endif
        }
      }
      else // Client data.
      {
        struct _isdite_fdn_tcpSrv_clientDesc * pClientDesc =
          (struct _isdite_fdn_tcpSrv_clientDesc *)aEventBuf[i].data.ptr;

        iInputSize =
          isdite_net_socketReceiveFast_IN4
          (
            &pClientDesc->sClientSocket,
            aInPacketBuffer,
            8192
          );

        if(iInputSize < 1)
          _isdite_fdn_tcpSrv_finalizeCon(pServerDesc, pClientDesc);
        else
        {
          int iRes = isdite_qtls_processInput(pServerDesc, pClientDesc, &pClientDesc->ctx, aInPacketBuffer, iInputSize);

          if(iRes == ISDITE_QTLS_INVALID_DATA)
            _isdite_fdn_tcpSrv_finalizeCon(pServerDesc, pClientDesc);
          else if(iRes == ISDITE_QTLS_DATA_READY)
          {
            fCallback = pServerDesc->pHandler;

            fCallback(pServerDesc, pClientDesc, pClientDesc->ctx.conDataBuffer, pClientDesc->ctx.conDataSz, &_is_net_tcpServer_cbWriteWrap, pServerDesc->pCustom);
          }
        }
      }
    }
  }
}

isdite_fn_tcp isdite_fn_tcpServer_create(char * ip, int port, int maxcon)
{
  #ifdef ISDITE_DEBUG

  float fMemReq = (((float)sizeof(void*) * (float)maxcon) +
    ((float)sizeof(struct _isdite_fdn_tcpSrv_clientDesc) * (float)maxcon) +
    (float)sizeof(struct _isdite_fdn_tcpSrv_serverDesc)) / (1024.0f * 1024.0f);

  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Net I/O client cache will require %0.3f MBs of memory, trying to allocate "
    "and prepare client stack.",
    fMemReq
  );
  #endif

  struct _isdite_fdn_tcpSrv_serverDesc * pServerDesc =
    (struct _isdite_fdn_tcpSrv_serverDesc *)
      isdite_mem_heapCharge(sizeof * pServerDesc);

  if(pServerDesc == INULL)
  {
    isdite_fdn_raiseThreadIntError(ISERR_OOM);

    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to allocate memory for server pServerDescriptor (%d).",
      errno
    );

    return INULL;
  }

  // NOTE: It's worth to consider to profile indirect malloc per client.
  //       It can be valuable because of the CPU cache.
  pServerDesc->aClientPool =
    isdite_mem_heapCharge(sizeof(*pServerDesc->aClientPool) * maxcon);

  if(pServerDesc->aClientPool == INULL)
  {
    isdite_fdn_raiseThreadIntError(ISERR_OOM);

    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to allocate memory for client pool (%d).",
      errno
    );

    free(pServerDesc);

    return INULL;
  }

  pServerDesc->aClientStack = isdite_mem_heapCommit(sizeof(void*) * maxcon);

  if(pServerDesc->aClientStack == NULL)
  {
    isdite_fdn_raiseThreadIntError(ISERR_OOM);

    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to allocate memory for client stack (%d).",
      errno
    );

    free(pServerDesc->aClientPool);
    free(pServerDesc);

    return INULL;
  }

  // Populate client stack.

  for(int i = 0; i < maxcon ;i++)
  {
    pServerDesc->aClientPool[i].iIntDescID = i;
    pServerDesc->aClientStack[maxcon - 1 - i] = &pServerDesc->aClientPool[i];
  }

  pServerDesc->iClientStackTop = maxcon - 1;

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Successfully allocated client stack and server pServerDescriptor."
  );
  #endif

  pServerDesc->uiMaxConnections = maxcon;

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Creating acceptor socket."
  );
  #endif

  if
  (
    isdite_net_socketCreate_IN4
    (
      &pServerDesc->sServerSocket,
      ISDITE_NET_SOCK_TCP,
      ISDITE_NET_SOCK_OPT_NONBLOCK
    ) == IFAULT
  )
  {
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to create server socket (%d).",
      errno
    );

    goto lErrClean;
  }

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Creating epoll event queue."
  );
  #endif

  // Create epoll queue.
  pServerDesc->iEpollFd = epoll_create1(0);

  if(pServerDesc->iEpollFd == -1)
  {
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to create epoll event queue (%d).",
      errno
    );

    goto lErrClean;
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

  if
  (
    isdite_net_socketBind_IN4
    (
      &pServerDesc->sServerSocket,
      ip,
      port
    ) == IFAULT
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

    goto lErrClean;
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

  if
  (
    isdite_net_socketListen_IN4
    (
      &pServerDesc->sServerSocket,
      _ISDITE_TCPSRV_CBACKLOG
    ) == IFAULT
  )
  {
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to turn acceptor socket into the listening state (%d).",
      errno
    );

    goto lErrClean;
  }

  // Add acceptor socket fd to the epoll.

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Adding acceptor socket pServerDescriptor to the epoll event queue.",
    port
  );
  #endif

  struct epoll_event sEvent;
  sEvent.events = EPOLLIN;
  sEvent.data.u64 = pServerDesc->sServerSocket.iSysFd;

  if
  (
    epoll_ctl
    (
      pServerDesc->iEpollFd,
      EPOLL_CTL_ADD,
      pServerDesc->sServerSocket.iSysFd,
      &sEvent
    ) != 0
  )
  {
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to add acceptor socket pServerDescriptor to epoll queue (%d).",
      errno
    );

    goto lErrClean;
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

  if
  (
    pthread_create
    (
      &pServerDesc->iNetWorkerFd,
      INULL,
      (void * (*)(void *))&_isdite_fn_tcpServer_netIoWorker,
      pServerDesc
    ) != 0
  )
  {
    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to create Net I/O worker thread (%d).",
      errno
    );

    goto lErrClean;
  }

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Basic server initialization finished successfully!"
  );
  #endif

  return pServerDesc;

  lErrClean:

  if(pServerDesc->iEpollFd <= 0)
    close(pServerDesc->iEpollFd);

  isdite_net_localSocketFree_IN4(&pServerDesc->sServerSocket);

  free(pServerDesc->aClientStack);
  free(pServerDesc->aClientPool);

  free(pServerDesc);

  return INULL;
}

void _isdite_tcpServer_sendPacketDropOnError
(
  void * pServerDesc,
  void * pClientDesc,
  void * pData,
  int iSize
)
{
  if
  (
    isdite_net_socketSendFast_IN4(&((struct _isdite_fdn_tcpSrv_clientDesc *)pClientDesc)->sClientSocket, pData, iSize) != iSize
  )
    _isdite_fdn_tcpSrv_finalizeCon(pServerDesc, pClientDesc);
}

void isdite_net_tcpServer_bindPacketHandler(isdite_fn_tcp server, void * handler, void * custom)
{
  ((struct _isdite_fdn_tcpSrv_serverDesc*)server)->pHandler = handler;
  ((struct _isdite_fdn_tcpSrv_serverDesc*)server)->pCustom = custom;
}

void isdite_net_tcpServer_join(isdite_fn_tcp server)
{
  pthread_join(((struct _isdite_fdn_tcpSrv_serverDesc*)server)->iNetWorkerFd, NULL);
}

void isdite_net_tcpServer_bindTlsCert(isdite_fn_tcp server, void* cert)
{
  ((struct _isdite_fdn_tcpSrv_serverDesc*)server)->pCert = cert;
}

#undef _ISDITE_TCPSRV_CLI_UDATA_SIZE
#undef _ISDITE_TCPSRV_KEEPALIVE
#undef _ISDITE_TCPSRV_CBACKLOG
