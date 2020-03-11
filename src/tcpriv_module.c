#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kthread.h>

MODULE_AUTHOR("matsumotory");
MODULE_DESCRIPTION("run kthread");
MODULE_LICENSE("GPL");

struct task_struct *k;

static int kthread_cb(void *arg)
{
  printk("[%s] running as kthread\n", k->comm);
  while(!kthread_should_stop()) {
    schedule();
  }

  return 0;
}

static int __init run_kthread_init(void)
{
  k = kthread_create(kthread_cb, NULL, "matsumotory");
  printk(KERN_INFO "[%s] wake up as kthread\n", k->comm);
  wake_up_process(k);

  return 0;
}

static void __exit run_kthread_exit(void)
{
  printk(KERN_INFO "[%s] stop kthread\n", k->comm);
  kthread_stop(k);
}

module_init(run_kthread_init);
module_exit(run_kthread_exit);
