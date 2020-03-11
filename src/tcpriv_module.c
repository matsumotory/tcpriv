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
MODULE_LICENSE("GPL");
MODULE_INFO(free_form_info, "separate privilege on TCP using task_struct");

/* very useful information: https://kel.bz/post/netfilter */

#define TCPRIV_INFO "tcpriv[info]: "

static struct nf_hook_ops nfho;

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  printk(KERN_INFO TCPRIV_INFO "Packet!\n");
  return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
  .hook = hook_func,
  .hooknum = NF_INET_PRE_ROUTING,
  .pf = PF_INET,
  .priority = NF_IP_PRI_FIRST,
};

static int __init tcpriv_init(void)
{
  printk(KERN_INFO TCPRIV_INFO "open\n");

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
