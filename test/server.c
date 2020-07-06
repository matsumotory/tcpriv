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

#define SRV_PORT 55226
#define BUF_SIZE 256

#define TCPOLEN_EXP_TCPRIV_BASE 10
#define TCPOLEN_EXP_TCPRIV_BASE_ALIGNED 12

/* ref: https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml */
#define TCPOPT_TCPRIV_MAGIC 0xF991

#define OPTION_SACK_ADVERTISE (1 << 0)
#define OPTION_TS (1 << 1)
#define OPTION_MD5 (1 << 2)
#define OPTION_WSCALE (1 << 3)
#define OPTION_FAST_OPEN_COOKIE (1 << 8)
#define OPTION_SMC (1 << 9)
#define OPTION_MPTCP (1 << 10)

/* 1 << 10 was used by MPTCP */
#define OPTION_TCPRIV (1 << 11)

#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN 27
#endif

#ifndef TCP_SAVED_SYN
#define TCP_SAVED_SYN 28
#endif

#define TCPOPT_NOP 1       /* Padding */
#define TCPOPT_EOL 0       /* End of options */
#define TCPOPT_MSS 2       /* Segment size negotiating */
#define TCPOPT_WINDOW 3    /* Window scaling */
#define TCPOPT_SACK_PERM 4 /* SACK Permitted */
#define TCPOPT_SACK 5      /* SACK Block */
#define TCPOPT_TIMESTAMP 8 /* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG 19   /* MD5 Signature (RFC2385) */
#define TCPOPT_FASTOPEN 34 /* Fast open (RFC7413) */
#define TCPOPT_EXP 254     /* Experimental */

/* Magic number to be after the option value for sharing TCP
 ** experimental options. See draft-ietf-tcpm-experimental-options-00.txt
 **/
#define TCPOPT_FASTOPEN_MAGIC 0xF989

/*
 **     TCP option lengths
 **/

#define TCPOLEN_MSS 4
#define TCPOLEN_WINDOW 3
#define TCPOLEN_SACK_PERM 2
#define TCPOLEN_TIMESTAMP 10
#define TCPOLEN_MD5SIG 18
#define TCPOLEN_FASTOPEN_BASE 2
#define TCPOLEN_EXP_FASTOPEN_BASE 4

/* But this is what stacks really send out. */
#define TCPOLEN_TSTAMP_ALIGNED 12
#define TCPOLEN_WSCALE_ALIGNED 4
#define TCPOLEN_SACKPERM_ALIGNED 4
#define TCPOLEN_SACK_BASE 2
#define TCPOLEN_SACK_BASE_ALIGNED 4
#define TCPOLEN_SACK_PERBLOCK 8
#define TCPOLEN_MD5SIG_ALIGNED 20
#define TCPOLEN_MSS_ALIGNED 4

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
  unsigned int tcpriv_uid, tcpriv_magic;
  unsigned char tcpriv_kind, tcpriv_len;
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
  for (int i = 0; i < syn_len; i++) {
    if (syn[i] == TCPOPT_EXP && syn[i + 1] == TCPOLEN_EXP_TCPRIV_BASE &&
        ntohl(*(unsigned int *)&syn[i + 1 + 1]) == TCPOPT_TCPRIV_MAGIC) {
      /* tcpriv options field structure
        kind[1] + length[1] + magic[4] + content[4] */
      tcpriv_kind = syn[i];
      tcpriv_len = syn[i + 1];
      tcpriv_magic = ntohl(*(unsigned int *)&syn[i + 1 + 1]);
      tcpriv_uid = ntohl(*(unsigned int *)&syn[i + 1 + 4 + 1]);
      printf("found tcpriv's information: kind=%u length=%u ExID=0x%x uid=%u \n", tcpriv_kind, tcpriv_len, tcpriv_magic,
             tcpriv_uid);
    }
  }

  /* Check the tcpriv option fields */
  assert(tcpriv_kind == TCPOPT_EXP);
  assert(tcpriv_len == TCPOLEN_EXP_TCPRIV_BASE);
  assert(tcpriv_magic == TCPOPT_TCPRIV_MAGIC);
  assert(tcpriv_uid == 1000);

  /* If we try TCP_SAVED_SYN again it should succeed with 0 length. */
  if (getsockopt(fd, IPPROTO_TCP, TCP_SAVED_SYN, syn, &syn_len) != 0)
    fail("repeated getsockopt TCP_SAVED_SYN failed");

  assert(syn_len == 0);
}

int main()
{
  unsigned short port = SRV_PORT;
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

  printf("tcpriv: all test success.\n");

  return 0;
}
