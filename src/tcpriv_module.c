#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_AUTHOR("matsumotory");
MODULE_DESCRIPTION("tcpriv separate privilege on TCP using Linux owner information");
MODULE_LICENSE("GPL");
MODULE_INFO(free_form_info, "separate privilege on TCP using task_struct");

/* very useful information: https://kel.bz/post/netfilter */

#define TCPRIV_INFO "tcpriv[info]: "

static struct nf_hook_ops nfho;

static int __init tcpriv_init(void)
{
  printk(KERN_INFO TCPRIV_INFO "open\n");

  nfho.hook = hook_func;
  nfho.hooknum = NF_INET_PRE_ROUTING;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;

  nf_register_hook(&nfho);

  return 0;
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in,
                       const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  printk(KERN_INFO TCPRIV_INFO "Packet!\n");
  return NF_ACCEPT;
}

static void __exit tcpriv_exit(void)
{
  nf_unregister_hook(&nfho);
  printk(KERN_INFO TCPRIV_INFO "close\n");
}

module_init(tcpriv_init);
module_exit(tcpriv_exit);
