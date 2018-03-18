#include "udp_server.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include "log.h"
#include "ierr.h"
#include "mem.h"

struct _isdite_udpserver_handle
{
  int iSocket;

  pthread_t hNetWorker;

  int iAllowedOriginCount;
  int aAllowedOriginPool[128];
};

static void _isdite_net_udpServer_IoWorker(struct _isdite_udpserver_handle * pHandle)
{

}

int isdite_net_udpServer(const char * sIpToBind, uint16_t ui16Port, const char ** sAllowedOrigin, unsigned int uiAllowedOriginCount, void * pPacketHandler)
{
  struct _isdite_udpserver_handle * pHandle =
    isdite_mem_heapCommit(sizeof(*pHandle));

  if(pHandle == NULL)
  {
    isdite_fdn_fsyslog
    (
      IL_TRAC,
      "Failed to allocate %dB of memory for UDP server handle(%d)!",
      sizeof(*pHandle),
      errno
    );

    isdite_fdn_raiseThreadIntError(ISERR_OOM);

    return -10;
  }

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "Creating UDP server (BindIP: %s, BindPort %u, AOC: %u)!",
    sIpToBind,
    ui16Port,
    uiAllowedOriginCount
  );
  #endif

  pHandle->iSocket = socket(AF_INET, SOCK_DGRAM, 0);

  if(pHandle->iSocket != 0)
  {
    free(pHandle);

    isdite_fdn_fsyslog(IL_ERRO, "Failed to create datagram socket(%d).", errno);

    return -1;
  }

  struct sockaddr_in sAddrToBind;
  sAddrToBind.sin_family = AF_INET;
  sAddrToBind.sin_port = htons(ui16Port);
  sAddrToBind.sin_addr.s_addr = inet_addr(sIpToBind);

  if(bind(pHandle->iSocket, (struct sockaddr*)&sAddrToBind, sizeof(sAddrToBind)) != 0)
  {
    close(pHandle->iSocket);
    free(pHandle);

    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to bind %s:%u address to the datagram socket(%d).",
      sIpToBind,
      ui16Port,
      errno
    );

    return -2;
  }

  if
  (
    pthread_create
    (
      &pHandle->hNetWorker,
      NULL,
      (void *(*)(void*))&_isdite_net_udpServer_IoWorker,
      pHandle
    ) != 0
  )
  {
    close(pHandle->iSocket);
    free(pHandle);

    isdite_fdn_fsyslog
    (
      IL_ERRO,
      "Failed to spawn server I/O worker thread(%d).",
      sIpToBind,
      ui16Port,
      errno
    );
  }

  pHandle->iAllowedOriginCount = uiAllowedOriginCount;

  for(unsigned int i = 0; i < uiAllowedOriginCount;i++)
    pHandle->aAllowedOriginPool[i] = inet_addr(sAllowedOrigin[i]);

  #ifdef ISDITE_DEBUG
  isdite_fdn_fsyslog
  (
    IL_TRAC,
    "UDP server (BindIP: %s, BindPort %u, AOC: %u) created successfully!",
    sIpToBind,
    ui16Port,
    uiAllowedOriginCount
  );
  #endif

  return 0;
}
