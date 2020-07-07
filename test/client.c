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
#define TCPRIV_INFO "tcpriv[info]: "
#define TCPRIV_ERRO "tcpriv[erro]: "

#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN 27
#endif

#ifndef TCP_SAVED_SYN
#define TCP_SAVED_SYN 28
#endif

static void fail(const char *msg)
{
  fprintf(stderr, TCPRIV_ERRO "%s\n", msg);
  exit(1);
}

static void fail_perror(const char *msg)
{
  perror(msg);
  exit(1);
}

int main()
{
  int srv_fd;
  int one = 1;
  struct sockaddr_in srv_addr;

  memset(&srv_addr, 0, sizeof(srv_addr));

  srv_addr.sin_port = htons(port);
  srv_addr.sin_family = AF_INET;
  srv_addr.sin_addr.s_addr = inet_addr(server);

  srv_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (setsockopt(srv_fd, IPPROTO_TCP, TCP_SAVE_SYN, &one, sizeof(one)) < 0)
    fail_perror(TCPRIV_ERRO "setsockopt TCP_SAVE_SYN");

  printf(TCPRIV_INFO "connect to %s\n", server);
  connect(srv_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));

  for (int i = 0; i < 10; i++) {
    send(srv_fd, MESSAGE, strlen(MESSAGE) + 1, 0);
  }

  close(srv_fd);

  printf(TCPRIV_INFO "client test done\n");

  return 0;
}
