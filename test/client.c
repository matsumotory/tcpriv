#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#define server "192.168.0.3"
#define port 55226
#define MESSAGE "tcpriv test"

#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN 27
#endif

#ifndef TCP_SAVED_SYN
#define TCP_SAVED_SYN 28
#endif

static void fail(const char *msg)
{
  fprintf(stderr, "%s\n", msg);
  exit(1);
}

static void fail_perror(const char *msg)
{
  perror(msg);
  exit(1);
}

int main()
{
  int srv;
  int one = 1;
  struct sockaddr_in srvaddr;

  memset(&srvaddr, 0, sizeof(srvaddr));

  srvaddr.sin_port = htons(port);
  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = inet_addr(server);

  srv = socket(AF_INET, SOCK_STREAM, 0);

  if (setsockopt(srv, IPPROTO_TCP, TCP_SAVE_SYN, &one, sizeof(one)) < 0)
    fail_perror("setsockopt TCP_SAVE_SYN");

  printf("[tcpriv] connect to %s\n", server);
  connect(srv, (struct sockaddr *)&srvaddr, sizeof(srvaddr));

  for (int i = 0; i < 10; i++) {
    send(srv, MESSAGE, strlen(MESSAGE) + 1, 0);
    sleep(1);
  }

  close(srv);
}
