#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define server "192.168.0.3"
#define port 55226
#define msg "tcpriv test"

int main()
{
  int srv;
  struct sockaddr_in srvaddr;

  memset(&srvaddr, 0, sizeof(srvaddr));

  srvaddr.sin_port = htons(port);
  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = inet_addr(server);

  srv = socket(AF_INET, SOCK_STREAM, 0);

  printf("[tcpriv] connect to %s\n", server);
  connect(srv, (struct sockaddr *)&srvaddr, sizeof(srvaddr));

  for (int i = 0; i < 10; i++) {
    send(srv, msg, strlen(msg) + 1, 0);
    sleep(1);
  }

  close(srv);
}
