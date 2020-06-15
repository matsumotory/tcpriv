#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/udp.h>
#include <linux/static_key.h>
#include <linux/cred.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/types.h>

#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/net_namespace.h>

#include <asm-generic/unaligned.h>

/* don't implement MPTCP options in 4.15.0-76-generic */
#if IS_ENABLED(CONFIG_MPTCP)
#include <net/mptcp.h>
#endif

MODULE_AUTHOR("matsumotory: Ryosuke Matsumoto");
MODULE_DESCRIPTION("An Access Control Architecture Separating Privilege Transparently via TCP Connection Based on "
                   "Process Information");
MODULE_LICENSE("GPL");
MODULE_INFO(free_form_info, "separate privilege on TCP using task_struct");

#define TCPRIV_INFO "tcpriv[info]: "

/* same as OPTION_TS: __u32 tsval, tsecr; */
/* but, use 8 bytes for tcpriv length */
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

#define tcp_time_stamp tcp_time_stamp_raw()

/*
 *     TCP option lengths
 */
//#define TCPOLEN_MSS            4
//#define TCPOLEN_WINDOW         3
//#define TCPOLEN_SACK_PERM      2
//#define TCPOLEN_TIMESTAMP      10
//#define TCPOLEN_MD5SIG         18
//#define TCPOLEN_FASTOPEN_BASE  2
//#define TCPOLEN_EXP_FASTOPEN_BASE  4
//#define TCPOLEN_EXP_SMC_BASE   6
//
///* But this is what stacks really send out. */
//#define TCPOLEN_TSTAMP_ALIGNED		12
//#define TCPOLEN_WSCALE_ALIGNED		4
//#define TCPOLEN_SACKPERM_ALIGNED	4
//#define TCPOLEN_SACK_BASE		2
//#define TCPOLEN_SACK_BASE_ALIGNED	4
//#define TCPOLEN_SACK_PERBLOCK		8
//#define TCPOLEN_MD5SIG_ALIGNED		20
//#define TCPOLEN_MSS_ALIGNED		4
//#define TCPOLEN_EXP_SMC_BASE_ALIGNED	8

/// TCP Header size: ref: net/tcp.h
//#define MAX_TCP_HEADER  (128 + MAX_HEADER)
//#define MAX_TCP_OPTION_SPACE 40

/* net/ipv4/tcp_ipv4.c: RFC2385 MD5 checksumming requires a mapping of IP address->MD5 Key.*/
// DEFINE_STATIC_KEY_FALSE(tcp_md5_needed);
// EXPORT_SYMBOL(tcp_md5_needed);

static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

/* copy the stcut definition from net/ipv4/tcp_output.c */
static struct tcp_out_options {
  u16 options;                                 /* bit field of OPTION_* */
  u16 mss;                                     /* 0 to disable */
  u8 ws;                                       /* window scale, 0 to disable */
  u8 num_sack_blocks;                          /* number of SACK blocks to include */
  u8 hash_size;                                /* bytes in hash_location */
  __u8 *hash_location;                         /* temporary pointer, overloaded */
  __u32 tsval, tsecr;                          /* need to include OPTION_TS */
  struct tcp_fastopen_cookie *fastopen_cookie; /* Fast open cookie */
  /* don't implement MPTCP options in 4.15.0-76-generic */
#if IS_ENABLED(CONFIG_MPTCP)
  struct mptcp_out_options mptcp;
#endif
};

static struct tcpriv_info {
  u32 uid, gid;
  unsigned int sk_tcpriv : 1;
};

/* TCP write tcpriv option functions */
/* ref: https://elixir.bootlin.com/linux/latest/source/net/ipv4/tcp_output.c#L457 */

static void tcpriv_options_write(__be32 *ptr, u16 *options)
{
  if (unlikely(OPTION_TCPRIV & *options)) {
    kuid_t uid = current_uid();
    kgid_t gid = current_gid();

    *ptr++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | (TCPOPT_EXP << 8) | (TCPOLEN_EXP_TCPRIV_BASE));
    *ptr++ = htonl(TCPOPT_TCPRIV_MAGIC);

    /* TODO; write tcpriv information: allocate 32bit (unsinged int) for owner/uid area */
    *ptr++ = htonl(uid.val);
    *ptr++ = htonl(gid.val);
  }
}

static void tcpriv_tcp_options_write(__be32 *ptr, struct tcp_sock *tp, struct tcp_out_options *opts)
{
  u16 options = opts->options; /* mungable copy */

  if (unlikely(OPTION_MD5 & options)) {
    *ptr++;
    ptr += 4;
  }

  if (unlikely(opts->mss)) {
    *ptr++;
  }

  if (likely(OPTION_TS & options)) {
    if (unlikely(OPTION_SACK_ADVERTISE & options)) {
      *ptr++;
      options &= ~OPTION_SACK_ADVERTISE;
    } else {
      *ptr++;
    }
    *ptr++;
    *ptr++;
  }

  if (unlikely(OPTION_SACK_ADVERTISE & options)) {
    *ptr++;
  }

  if (unlikely(OPTION_WSCALE & options)) {
    *ptr++;
  }

  if (unlikely(opts->num_sack_blocks)) {
    int this_sack;

    *ptr++;

    for (this_sack = 0; this_sack < opts->num_sack_blocks; ++this_sack) {
      *ptr++;
      *ptr++;
    }
  }

  if (unlikely(OPTION_FAST_OPEN_COOKIE & options)) {
    struct tcp_fastopen_cookie *foc = opts->fastopen_cookie;
    u8 *p = (u8 *)ptr;
    u32 len; /* Fast Open option length */

    if (foc->exp) {
      len = TCPOLEN_EXP_FASTOPEN_BASE + foc->len;
      p += TCPOLEN_EXP_FASTOPEN_BASE;
    } else {
      len = TCPOLEN_FASTOPEN_BASE + foc->len;
      *p++;
      *p++ = len;
    }

    ptr += (len + 3) >> 2;
  }

  tcpriv_options_write(ptr, &options);
}

/* TCP parse tcpriv option functions */
static void tcpriv_parse_options(const struct tcphdr *th, struct tcp_options_received *opt_rx, const unsigned char *ptr,
                                 int opsize, const struct nf_hook_state *state)
{
  if (th->syn && !(opsize & 1) && opsize >= TCPOLEN_EXP_TCPRIV_BASE && get_unaligned_be32(ptr) == TCPOPT_TCPRIV_MAGIC) {
    /* TODO: check tcpriv information */
    struct tcpriv_info *trinfo = (struct tcpriv_info *)state->sk->sk_user_data;

    trinfo->sk_tcpriv = 1;
    trinfo->uid = get_unaligned_be32(ptr + 4);
    trinfo->gid = get_unaligned_be32(ptr + 8);

    printk(KERN_INFO TCPRIV_INFO "found client process info: uid=%u gid=%u\n", trinfo->uid, trinfo->gid);
  }
}

/* ref: https://elixir.bootlin.com/linux/latest/source/net/ipv4/tcp_input.c#L3839 */
void tcpriv_tcp_parse_options(const struct net *net, const struct sk_buff *skb, struct tcp_options_received *opt_rx,
                              int estab, struct tcp_fastopen_cookie *foc, const struct nf_hook_state *state)
{
  const unsigned char *ptr;
  const struct tcphdr *th = tcp_hdr(skb);
  int length = (th->doff * 4) - sizeof(struct tcphdr);

  ptr = (const unsigned char *)(th + 1);
  opt_rx->saw_tstamp = 0;

  while (length > 0) {
    int opcode = *ptr++;
    int opsize;

    switch (opcode) {
    case TCPOPT_EOL:
      return;
    case TCPOPT_NOP: /* Ref: RFC 793 section 3.1 */
      length--;
      continue;
    default:
      if (length < 2)
        return;
      opsize = *ptr++;
      if (opsize < 2) /* "silly options" */
        return;
      if (opsize > length)
        return; /* don't parse partial options */
      switch (opcode) {

      case TCPOPT_EXP:
        /* Fast Open or SMC option shares code 254 using a 16 bits magic number. */
        if (opsize >= TCPOLEN_EXP_FASTOPEN_BASE && get_unaligned_be16(ptr) == TCPOPT_FASTOPEN_MAGIC) {
          // do nothing
        } else if (th->syn && !(opsize & 1) && opsize >= TCPOLEN_EXP_SMC_BASE &&
                   get_unaligned_be16(ptr) == TCPOPT_SMC_MAGIC) {
          // do nothing
        } else {
          tcpriv_parse_options(th, opt_rx, ptr, opsize, state);
        }

        break;
      }
      ptr += opsize - 2;
      length -= opsize;
    }
  }
}

/* TCP set tcpriv option functions */
static void tcpriv_set_option(const struct tcp_sock *tp, struct tcp_out_options *opts, unsigned int *remaining)
{
  if (*remaining >= TCPOLEN_EXP_TCPRIV_BASE_ALIGNED) {
    opts->options |= OPTION_TCPRIV;

    /* TODO: store tcpriv information */
    *remaining -= TCPOLEN_EXP_TCPRIV_BASE_ALIGNED;
  }
}

/* Compute TCP options for SYN packets. This is not the final
 * network wire format yet.
 */

/* ref: https://elixir.bootlin.com/linux/latest/source/net/ipv4/tcp_output.c#L590 */
static unsigned int tcpriv_tcp_syn_options(struct sock *sk, struct sk_buff *skb, struct tcp_out_options *opts,
                                           struct tcp_md5sig_key **md5)
{
  struct tcp_sock *tp = tcp_sk(sk);
  unsigned int remaining = MAX_TCP_OPTION_SPACE;
  struct tcp_fastopen_request *fastopen = tp->fastopen_req;

  *md5 = NULL;
#ifdef CONFIG_TCP_MD5SIG
  if (static_branch_unlikely(&tcp_md5_needed) && rcu_access_pointer(tp->md5sig_info)) {
    *md5 = tp->af_specific->md5_lookup(sk, sk);
    if (*md5) {
      remaining -= TCPOLEN_MD5SIG_ALIGNED;
    }
  }
#endif

  /* We always get an MSS option.  The option bytes which will be seen in
   * normal data packets should timestamps be used, must be in the MSS
   * advertised.  But we subtract them from tp->mss_cache so that
   * calculations in tcp_sendmsg are simpler etc.  So account for this
   * fact here if necessary.  If we don't do this correctly, as a
   * receiver we won't recognize data packets as being full sized when we
   * should, and thus we won't abide by the delayed ACK rules correctly.
   * SACKs don't matter, we never delay an ACK when we have any of those
   * going out.  */
  remaining -= TCPOLEN_MSS_ALIGNED;

  if (likely(sock_net(sk)->ipv4.sysctl_tcp_timestamps && !*md5)) {
    remaining -= TCPOLEN_TSTAMP_ALIGNED;
  }
  if (likely(sock_net(sk)->ipv4.sysctl_tcp_window_scaling)) {
    remaining -= TCPOLEN_WSCALE_ALIGNED;
  }
  if (likely(sock_net(sk)->ipv4.sysctl_tcp_sack)) {
    if (unlikely(!(OPTION_TS & opts->options)))
      remaining -= TCPOLEN_SACKPERM_ALIGNED;
  }

  if (fastopen && fastopen->cookie.len >= 0) {
    u32 need = fastopen->cookie.len;

    need += fastopen->cookie.exp ? TCPOLEN_EXP_FASTOPEN_BASE : TCPOLEN_FASTOPEN_BASE;
    need = (need + 3) & ~3U; /* Align to 32 bits */
    if (remaining >= need) {
      remaining -= need;
    }
  }

  tcpriv_set_option(tp, opts, &remaining);

  return MAX_TCP_OPTION_SPACE - remaining;
}

// struct tcp_options_received {
//  /*  PAWS/RTTM data  */
//  int  ts_recent_stamp;/* Time we stored ts_recent (for aging) */
//  u32  ts_recent;  /* Time stamp to echo next    */
//  u32  rcv_tsval;  /* Time stamp value               */
//  u32  rcv_tsecr;  /* Time stamp echo reply          */
//  u16  saw_tstamp : 1,  /* Saw TIMESTAMP on last packet    */
//      tstamp_ok : 1,  /* TIMESTAMP seen on SYN packet    */
//      dsack : 1,  /* D-SACK is scheduled      */
//      wscale_ok : 1,  /* Wscale seen on SYN packet    */
//      sack_ok : 3,  /* SACK seen on SYN packet    */
//      smc_ok : 1,  /* SMC seen on SYN packet    */
//      snd_wscale : 4,  /* Window scaling received from sender  */
//      rcv_wscale : 4;  /* Window scaling to send to receiver  */
//  u8  num_sacks;  /* Number of SACK blocks    */
//  u16  user_mss;  /* mss requested by user in ioctl  */
//  u16  mss_clamp;  /* Maximal mss, negotiated at connection setup */
//};

static inline void tcpriv_tcp_clear_options(struct tcp_options_received *rx_opt)
{
  rx_opt->tstamp_ok = rx_opt->sack_ok = 0;
  rx_opt->wscale_ok = rx_opt->snd_wscale = 0;
#if IS_ENABLED(CONFIG_SMC)
  rx_opt->smc_ok = 0;
#endif
#if IS_ENABLED(CONFIG_MPTCP)
  rx_opt->mptcp.mp_capable = 0;
  rx_opt->mptcp.mp_join = 0;
  rx_opt->mptcp.dss = 0;
#endif
}

static unsigned int hook_local_in_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iphdr = ip_hdr(skb);
  struct tcphdr *tcphdr = tcp_hdr(skb);
  struct tcp_options_received tmp_opt;
  struct tcpriv_info *trinfo;
  int err;

  if (state->sk != NULL) {
    if (iphdr->version == 4) {
      if (iphdr->protocol == IPPROTO_TCP && tcphdr->syn) {
        printk(KERN_INFO TCPRIV_INFO "found local in TCP syn packet from %pI4.\n", &iphdr->saddr);

        trinfo = (struct tcpriv_info *)kzalloc(sizeof(struct tcpriv_info), GFP_KERNEL);
        if (!trinfo) {
          err = -ENOMEM;
          goto error;
        }

        state->sk->sk_user_data = trinfo;

        /* parse tcp options and store tmp_opt buffer */
        memset(&tmp_opt, 0, sizeof(tmp_opt));
        tcpriv_tcp_clear_options(&tmp_opt);
        tcpriv_tcp_parse_options(&init_net, skb, &tmp_opt, 0, NULL, state);
      }
    }
  }

  return NF_ACCEPT;

error:
  kfree(trinfo);
  return err;
}

static unsigned int hook_local_out_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iphdr = ip_hdr(skb);
  struct tcphdr *tcphdr = tcp_hdr(skb);

  if (iphdr->version == 4) {
    if (iphdr->protocol == IPPROTO_TCP && tcphdr->syn) {
      struct tcp_out_options opts;
      struct sock *sk;
      struct tcp_md5sig_key *md5;

      printk(KERN_INFO TCPRIV_INFO "found local out TCP syn packet from %pI4.\n", &iphdr->saddr);

      sk = state->sk;
      memset(&opts, 0, sizeof(opts));
      tcpriv_tcp_syn_options(sk, skb, &opts, &md5);
      tcpriv_tcp_options_write((__be32 *)(tcphdr + 1), NULL, &opts);
    }
  }

  return NF_ACCEPT;
}

/* /proc/net/tcpriv functions */

/* ref: https://github.com/veithen/knetstat/blob/master/knetstat.c
 * Thank you for your great work, knetstat.c! */

static const char *const tcp_state_names[] = {"NONE", "ESTB", "SYNS", "SYNR", "FNW1", "FNW2", "TIMW",
                                              "CLSD", "CLSW", "LACK", "LSTN", "CLSG", "SYNR"};

static void sock_common_options_show(struct seq_file *seq, struct sock *sk)
{
  // Note:
  //  * Linux actually doubles the values for SO_RCVBUF and SO_SNDBUF (see sock_setsockopt in net/core/sock.c)
  //  * If these options are not set explicitly, the kernel may dynamically scale the buffer sizes
  if (sk->sk_userlocks & SOCK_RCVBUF_LOCK) {
    seq_printf(seq, ",SO_RCVBUF=%d", sk->sk_rcvbuf / 2);
  }
  if (sk->sk_userlocks & SOCK_SNDBUF_LOCK) {
    seq_printf(seq, ",SO_SNDBUF=%d", sk->sk_sndbuf / 2);
  }

  if (sk->sk_rcvtimeo != MAX_SCHEDULE_TIMEOUT) {
    seq_printf(seq, ",SO_RCVTIMEO=%ldms", sk->sk_rcvtimeo * 1000 / HZ);
  }
  if (sk->sk_sndtimeo != MAX_SCHEDULE_TIMEOUT) {
    seq_printf(seq, ",SO_SNDTIMEO=%ldms", sk->sk_sndtimeo * 1000 / HZ);
  }

  if (sock_flag(sk, SOCK_LINGER)) {
    seq_printf(seq, ",SO_LINGER=%lds", sk->sk_lingertime / HZ);
  }
}

static void addr_port_show(struct seq_file *seq, sa_family_t family, const void *addr, __u16 port)
{
  seq_setwidth(seq, 23);
  seq_printf(seq, family == AF_INET6 ? "%pI6c" : "%pI4", addr);
  if (port == 0) {
    seq_puts(seq, ":*");
  } else {
    seq_printf(seq, ":%d", port);
  }
  seq_pad(seq, ' ');
}

static int tcp_seq_show(struct seq_file *seq, void *v)
{
  if (v == SEQ_START_TOKEN) {
    seq_printf(seq, "TCPRIV Information\n");
  } else {

    struct tcp_iter_state *st = seq->private;
    struct tcp_seq_afinfo *afinfo = PDE_DATA(file_inode(seq->file));
    sa_family_t family = afinfo->family;

    int rx_queue;
    int tx_queue;
    const void *dest;
    const void *src;
    __u16 destp;
    __u16 srcp;
    int state;
    struct sock *sk;
    int fo_qlen = 0;
    u8 defer = 0;

    switch (st->state) {
    case TCP_SEQ_STATE_LISTENING:
    case TCP_SEQ_STATE_ESTABLISHED: {

      sk = v;

      if (sk->sk_state == TCP_TIME_WAIT) {

        const struct inet_timewait_sock *tw = v;

        rx_queue = 0;
        tx_queue = 0;

        if (family == AF_INET6) {
          dest = &tw->tw_v6_daddr;
          src = &tw->tw_v6_rcv_saddr;
        } else {
          dest = &tw->tw_daddr;
          src = &tw->tw_rcv_saddr;
        }

        destp = ntohs(tw->tw_dport);
        srcp = ntohs(tw->tw_sport);
        state = tw->tw_substate;
        sk = NULL;

      } else {

        const struct tcp_sock *tp;
        const struct inet_sock *inet;
        const struct fastopen_queue *fq;

        tp = tcp_sk(sk);
        inet = inet_sk(sk);
        defer = inet_csk(sk)->icsk_accept_queue.rskq_defer_accept;

        switch (sk->sk_state) {
        case TCP_LISTEN:

          rx_queue = sk->sk_ack_backlog;
          tx_queue = 0;
          fq = &inet_csk(sk)->icsk_accept_queue.fastopenq;

          if (fq != NULL) {
            fo_qlen = fq->max_qlen;
          }

          break;
        case TCP_NEW_SYN_RECV:

          rx_queue = 0;
          tx_queue = 0;

          break;

        default:
          rx_queue = max_t(int, tp->rcv_nxt - tp->copied_seq, 0);
          tx_queue = tp->write_seq - tp->snd_una;
        }

        if (family == AF_INET6) {
          dest = &sk->sk_v6_daddr;
          src = &sk->sk_v6_rcv_saddr;
        } else {
          dest = &inet->inet_daddr;
          src = &inet->inet_rcv_saddr;
        }

        destp = ntohs(inet->inet_dport);
        srcp = ntohs(inet->inet_sport);
        state = sk->sk_state;

        if (sk->sk_state == TCP_NEW_SYN_RECV) {
          sk = NULL;
        }
      }
      break;
    }

    default:
      return 0;
    }

    if (state < 0 || state >= TCP_MAX_STATES) {
      state = 0;
    }

    seq_printf(seq, "%6d %6d ", rx_queue, tx_queue);
    addr_port_show(seq, family, src, srcp);
    addr_port_show(seq, family, dest, destp);
    seq_printf(seq, "%s ", tcp_state_names[state]);

    if (sk != NULL) {

      seq_setwidth(seq, 4);

      if (state == TCP_ESTABLISHED) {

        const struct tcp_sock *tp = tcp_sk(sk);

        if (tp->rcv_wnd == 0 && tp->snd_wnd == 0) {
          // Both receiver and sender windows are 0; we can neither receive nor send more data
          seq_puts(seq, ">|<");
        } else if (tp->rcv_wnd == 0) {
          // Receiver window is 0; we cannot receive more data
          seq_puts(seq, "|<");
        } else if (tp->snd_wnd == 0) {
          // Sender window is 0; we cannot send more data
          seq_puts(seq, ">|");
        } else if (tp->snd_nxt > tp->snd_una && tcp_time_stamp - tp->rcv_tstamp > HZ) {
          // There are unacknowledged packets and the last ACK was received more than 1 second ago;
          // this is an indication for network problems
          seq_puts(seq, ">#");
        }
      }
      seq_pad(seq, ' ');

      seq_printf(seq, "SO_REUSEADDR=%d,SO_REUSEPORT=%d,SO_KEEPALIVE=%d", sk->sk_reuse, sk->sk_reuseport,
                 sock_flag(sk, SOCK_KEEPOPEN));

      if (tcp_sk(sk)->keepalive_time > 0) {
        seq_printf(seq, ",TCP_KEEPIDLE=%u", tcp_sk(sk)->keepalive_time / HZ);
      }

      if (tcp_sk(sk)->keepalive_probes > 0) {
        seq_printf(seq, ",TCP_KEEPCNT=%u", tcp_sk(sk)->keepalive_probes);
      }

      if (tcp_sk(sk)->keepalive_intvl > 0) {
        seq_printf(seq, ",TCP_KEEPINTVL=%u", tcp_sk(sk)->keepalive_intvl / HZ);
      }

      sock_common_options_show(seq, sk);

      seq_printf(seq, ",TCP_NODELAY=%d", !!(tcp_sk(sk)->nonagle & TCP_NAGLE_OFF));

      if (state == TCP_LISTEN) {
        seq_printf(seq, ",TCP_FASTOPEN=%d", fo_qlen);
      }

      seq_printf(seq, ",TCP_DEFER_ACCEPT=%d", defer);
    }

    seq_printf(seq, "\n");
  }
  return 0;
}

static const struct seq_operations tcpriv_seq_ops = {
    .show = tcp_seq_show,
    .start = tcp_seq_start,
    .next = tcp_seq_next,
    .stop = tcp_seq_stop,
};

static struct tcp_seq_afinfo tcpriv_seq_afinfo = {
    .family = AF_INET,
};

static int __net_init tcpriv_net_init(struct net *net)
{
  if (!proc_create_net_data("tcpriv", 0444, net->proc_net, &tcpriv_seq_ops, sizeof(struct tcp_iter_state),
                            &tcpriv_seq_afinfo)) {
    remove_proc_entry("tcpriv", net->proc_net);
    return -ENOMEM;
  }

  return 0;
}

static void __net_exit tcpriv_net_exit(struct net *net)
{
  remove_proc_entry("tcpriv", net->proc_net);
}

static struct pernet_operations tcpriv_net_ops = {
    .init = tcpriv_net_init,
    .exit = tcpriv_net_exit,
};

static int __init tcpriv_init(void)
{
  int ret;

  printk(KERN_INFO TCPRIV_INFO "open\n");
  printk(KERN_INFO TCPRIV_INFO "An Access Control Architecture Separating Privilege Transparently via TCP Connection "
                               "Based on Process Information\n");

  ret = register_pernet_subsys(&tcpriv_net_ops);
  if (ret < 0)
    return ret;

  nfho_in.hook = hook_local_in_func;
  nfho_in.hooknum = NF_INET_LOCAL_IN;
  nfho_in.pf = PF_INET;
  nfho_in.priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(&init_net, &nfho_in);

  nfho_out.hook = hook_local_out_func;
  nfho_out.hooknum = NF_INET_LOCAL_OUT;
  nfho_out.pf = PF_INET;
  nfho_out.priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(&init_net, &nfho_out);

  return 0;
}

static void __exit tcpriv_exit(void)
{
  nf_unregister_net_hook(&init_net, &nfho_in);
  nf_unregister_net_hook(&init_net, &nfho_out);

  unregister_pernet_subsys(&tcpriv_net_ops);

  printk(KERN_INFO TCPRIV_INFO "close\n");
}

module_init(tcpriv_init);
module_exit(tcpriv_exit);
