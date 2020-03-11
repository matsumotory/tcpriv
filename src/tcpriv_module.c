#include <linux/module.h>

MODULE_AUTHOR("matsumotory");
MODULE_DESCRIPTION("run kthread");
MODULE_LICENSE("GPL");
MODULE_INFO(free_form_info, "separate privilege on TCP using task_struct");

static int __init tcpriv_init(void)    
{
  printk(KERN_INFO "open\n");
  return 0;
}
 
static void __exit tcpriv_exit(void)    
{
  printk(KERN_INFO "close\n");
}
 
module_init(tcpriv_init);
module_exit(tcpriv_exit); 
