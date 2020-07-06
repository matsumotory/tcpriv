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
static int tcp_seq_show(struct seq_file *seq, void *v)
{
  if (v == SEQ_START_TOKEN)
    seq_printf(seq, "enabled\n");

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

  nfho_out.hook = hook_local_out_func;
  nfho_out.hooknum = NF_INET_LOCAL_OUT;
  nfho_out.pf = PF_INET;
  nfho_out.priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(&init_net, &nfho_out);

  return 0;
}

static void __exit tcpriv_exit(void)
{
  nf_unregister_net_hook(&init_net, &nfho_out);

  unregister_pernet_subsys(&tcpriv_net_ops);

  printk(KERN_INFO TCPRIV_INFO "close\n");
}

module_init(tcpriv_init);
module_exit(tcpriv_exit);
