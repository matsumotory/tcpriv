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

#include <net/ip.h>
#include <net/tcp.h>

MODULE_AUTHOR("matsumotory");
MODULE_DESCRIPTION("tcpriv separate privilege on TCP using Linux owner information");
MODULE_LICENSE("MITL");
MODULE_INFO(free_form_info, "separate privilege on TCP using task_struct");

#define TCPRIV_INFO "tcpriv[info]: "

static struct nf_hook_ops nfho;

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  printk(KERN_INFO TCPRIV_INFO "tcpriv find packet.\n");
  return NF_ACCEPT;
}

static int __init tcpriv_init(void)
{
  printk(KERN_INFO TCPRIV_INFO "open\n");

  nfho.hook = hook_func;
  nfho.hooknum = NF_INET_LOCAL_OUT;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(&init_net, &nfho);

  return 0;
}

static void __exit tcpriv_exit(void)
{
  nf_unregister_net_hook(&init_net, &nfho);
  printk(KERN_INFO TCPRIV_INFO "close\n");
}

module_init(tcpriv_init);
module_exit(tcpriv_exit);
