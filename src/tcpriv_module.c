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

  if (iphdr->version == 4) {
    if (iphdr->protocol == IPPROTO_TCP && tcphdr->syn) {
      printk(KERN_INFO TCPRIV_INFO "tcpriv found local in TCP syn packet from %pI4.\n", &iphdr->daddr);
    }
  }

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
