#include "tcp_server.h"

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

struct _isdite_fn_tcpServer_client
{
  int internalId;
  int status;
  int socket;
  struct sockaddr_in sai;
};

const char * mocked = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{\"hello\":\"world\"}";

static inline void _isdite_fn_tcpServer_setSocketNonBlock(int fd)
{
   int flags = fcntl(fd, F_GETFL, 0);
   flags |= O_NONBLOCK;
   fcntl(fd, F_SETFL, flags);
}

struct _isdite_fn_tcpServer_descriptorImpl
{
  int acceptorSocket;
  int epollDescriptor;
  pthread_t workerDescriptor;
};

void * _isdite_fn_tcpServer_ioWorker(struct _isdite_fn_tcpServer_descriptorImpl *  desc)
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
  struct _isdite_fn_tcpServer_descriptorImpl * desc = (struct _isdite_fn_tcpServer_descriptorImpl *)malloc(sizeof(struct _isdite_fn_tcpServer_descriptorImpl));

  desc->acceptorSocket = socket(AF_INET, SOCK_STREAM, 0);

  _isdite_fn_tcpServer_setSocketNonBlock(desc->acceptorSocket);

  desc->epollDescriptor = epoll_create(1024);

  struct sockaddr_in serv_addr, cli_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(port);

  bind(desc->acceptorSocket, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
  listen(desc->acceptorSocket, 1024);

  struct epoll_event event;
  event.events = EPOLLIN | EPOLLET;
  event.data.u64 = desc->acceptorSocket;
  epoll_ctl(desc->epollDescriptor, EPOLL_CTL_ADD, desc->acceptorSocket, &event);

  pthread_create(&desc->workerDescriptor, NULL, (void * (*)(void *))&_isdite_fn_tcpServer_ioWorker, desc);

  return desc;
}
