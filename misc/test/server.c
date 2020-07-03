// gcc server.c
#include <assert.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define BUF_SIZE 256

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

// ref: https://lwn.net/Articles/645130/
/* Get and validate the saved SYN. */
static void read_saved_syn(int fd, int address_family)
{
  unsigned char syn[500];
  socklen_t syn_len = sizeof(syn);

  memset(syn, 0, sizeof(syn));

  /* Read the saved SYN. */
  if (getsockopt(fd, IPPROTO_TCP, TCP_SAVED_SYN, syn, &syn_len) != 0)
    fail_perror("first getsockopt TCP_SAVED_SYN failed");

  /* Check the length and first byte of the SYN. */
  if (address_family == AF_INET) {
    printf("syn_len: %d\n", syn_len);
    assert(syn_len == 60);
    assert(syn[0] >> 4 == 0x4); /* IPv4 */
  } else if (address_family == AF_INET6) {
    assert(syn_len == 80);
    assert(syn[0] >> 4 == 0x6); /* IPv6 */
  } else {
    assert(!"bad address family");
  }

  /* Check the last few bytes of the SYN, which will be TCP options. */
  assert(syn[syn_len - 4] == 0x01);                             /* TCP option: kind = NOP */
  assert(syn[syn_len - 3] == 0x03);                             /* TCP option: kind = window scale */
  assert(syn[syn_len - 2] == 0x03);                             /* TCP option: length = 3 */
  assert(syn[syn_len - 1] == 0x06 || syn[syn_len - 1] == 0x07); /* TCP option: window scale = 6 or 7
                                                                 */

  /* If we try TCP_SAVED_SYN again it should succeed with 0 length. */
  if (getsockopt(fd, IPPROTO_TCP, TCP_SAVED_SYN, syn, &syn_len) != 0)
    fail("repeated getsockopt TCP_SAVED_SYN failed");
  assert(syn_len == 0);
}

int main()
{
  unsigned short port = 55226;
  int srv;
  int cli;
  int one = 1;

  struct sockaddr_in srvaddr;
  struct sockaddr_in cliaddr;
  int cliaddrsize = sizeof(cliaddr);

  int numrcv;
  char buf[BUF_SIZE];

  memset(&srvaddr, 0, sizeof(srvaddr));
  srvaddr.sin_port = htons(port);
  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

  srv = socket(AF_INET, SOCK_STREAM, 0);

  bind(srv, (struct sockaddr *)&srvaddr, sizeof(srvaddr));

  if (setsockopt(srv, IPPROTO_TCP, TCP_SAVE_SYN, &one, sizeof(one)) < 0)
    fail_perror("setsockopt TCP_SAVE_SYN");

  listen(srv, 1);

  printf("waiting...\n");
  cli = accept(srv, (struct sockaddr *)&cliaddr, &cliaddrsize);
  printf("connected: %s\n", inet_ntoa(cliaddr.sin_addr));

  read_saved_syn(cli, ((struct sockaddr *)&cliaddr)->sa_family);

  close(cli);

  printf("test done\n");

  return 0;
}
