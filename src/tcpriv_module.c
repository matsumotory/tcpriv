#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_AUTHOR("matsumotory");
MODULE_DESCRIPTION("tcpriv separate privilege on TCP using Linux owner information");
MODULE_LICENSE("MITL");
MODULE_INFO(free_form_info, "separate privilege on TCP using task_struct");

#define TCPRIV_INFO "tcpriv[info]: "

static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

static unsigned int hook_local_in_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iphdr = ip_hdr(skb);
  struct tcphdr *tcphdr = tcp_hdr(skb);
  struct tcp_options_received tmp_opt;

//struct tcp_options_received {
//  /*	PAWS/RTTM data	*/
//  int	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
//  u32	ts_recent;	/* Time stamp to echo next		*/
//  u32	rcv_tsval;	/* Time stamp value             	*/
//  u32	rcv_tsecr;	/* Time stamp echo reply        	*/
//  u16	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
//      tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
//      dsack : 1,	/* D-SACK is scheduled			*/
//      wscale_ok : 1,	/* Wscale seen on SYN packet		*/
//      sack_ok : 3,	/* SACK seen on SYN packet		*/
//      smc_ok : 1,	/* SMC seen on SYN packet		*/
//      snd_wscale : 4,	/* Window scaling received from sender	*/
//      rcv_wscale : 4;	/* Window scaling to send to receiver	*/
//	u8	num_sacks;	/* Number of SACK blocks		*/
//	u16	user_mss;	/* mss requested by user in ioctl	*/
//	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
//};

  if (iphdr->version == 4) {
    if (iphdr->protocol == IPPROTO_TCP && tcphdr->syn) {
      printk(KERN_INFO TCPRIV_INFO "tcpriv found local in TCP syn packet from %pI4.\n", &iphdr->saddr);
    }
  }

  /* parse tcp options and store tmp_opt buffer */
  memset(&tmp_opt, 0, sizeof(tmp_opt));
  tcp_clear_options(&tmp_opt);
  tcp_parse_options(&init_net, skb, &tmp_opt, 0, NULL);

  return NF_ACCEPT;
}

static unsigned int hook_local_out_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iphdr = ip_hdr(skb);
  struct tcphdr *tcphdr = tcp_hdr(skb);

  if (iphdr->version == 4) {
    if (iphdr->protocol == IPPROTO_TCP && tcphdr->syn) {
      printk(KERN_INFO TCPRIV_INFO "tcpriv found local out TCP syn packet from %pI4.\n", &iphdr->saddr);
    }
  }

  return NF_ACCEPT;
}

static int __init tcpriv_init(void)
{
  printk(KERN_INFO TCPRIV_INFO "open\n");

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
  printk(KERN_INFO TCPRIV_INFO "close\n");
}

module_init(tcpriv_init);
module_exit(tcpriv_exit);
