#include "tcp_server.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <pthread.h>

struct _isdite_fn_tcpServer_client
{
  int internalId;
  int status;
  int socket;
};

struct _isdite_fn_tcpServer_descriptorImpl
{
  int acceptorSocket;
  int epollDescriptor;
  pthread_t workerDescriptor;
};

void * _isdite_fn_tcpServer_ioWorker(void * desc)
{
  epoll_event events[1024];
  while(1==1)
  {
    int r = epoll_wait (desc->epollDescriptor, events, 1024, -1);



  }
  return NULL;
}

isdite_fn_tcp isdite_fn_tcpServer_create(int port)
{
  struct _isdite_fn_tcpServer_descriptorImpl * desc = (struct _isdite_fn_tcpServer_descriptorImpl *)malloc(sizeof(struct _isdite_fn_tcpServer_descriptorImpl));

  desc->acceptorSocket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

  desc->epollDescriptor = epoll_create(1024);

  struct sockaddr_in serv_addr, cli_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(port);
  bind(desc->acceptorSocket, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
  listen(desc->acceptorSocket, 1024);

  struct epoll_event event;

  event.events = EPOLLIN;
  event.data.ptr = desc;

  epoll_ctl(desc->epollDescriptor, EPOLL_CTL_ADD, desc->acceptorSocket, &event);

  pthread_create(&desc->workerDescriptor, NULL, _isdite_fn_tcpServer_ioWorker, desc);

  return desc;
}
