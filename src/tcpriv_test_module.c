#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/kthread.h>
#include <asm-generic/uaccess.h>

MODULE_AUTHOR("matsumotory");
MODULE_DESCRIPTION("kill kthread");
MODULE_LICENSE("GPL");

static int file_value;
static struct dentry *dentry_file;
struct task_struct *k;

static ssize_t kill_kthread_by_pid(struct file *file, const char __user *ubuf, size_t len, loff_t *ppos)
{
  pid_t pid;
  char kbuf[64];
  struct pid *pid_s;

  if (len > sizeof(kbuf) -1) {
    printk(KERN_INFO "kill_kthread_by_pid: invalid pid\n");
    return -EINVAL;
  }

  if (copy_from_user(kbuf, ubuf, len)) {
    printk(KERN_INFO "kill_kthread_by_pid: copy from user land to kernel failed\n");
    return -EFAULT;
  }

  kbuf[len] = '\0';

  if (!(pid = simple_strtoul(kbuf, NULL, 10))) {
    printk(KERN_INFO "kill_kthread_by_pid: convert pid failed, invalid pid\n");
    return -EINVAL;
  }

  if (!(pid_s = find_get_pid(pid))) {
    printk(KERN_INFO "kill_kthread_by_pid: not found pid struct\n");
    return -ESRCH;
  }

  if (!(k = get_pid_task(pid_s, PIDTYPE_PID))) {
    printk(KERN_INFO "kill_kthread_by_pid: not found task struct\n");
    put_pid(pid_s);
    return -ESRCH;
  }

  printk(KERN_INFO "[%s=%d] kill kthread by kthread_stop\n", k->comm, pid);
  kthread_stop(k);

  return len;
}

static struct file_operations fops = {
  .write = kill_kthread_by_pid,
};

static int __init kill_kthread_module_init(void)
{
  dentry_file = debugfs_create_file("kill_kthread", 0644, NULL, &file_value, &fops);

  if (!dentry_file) {
    printk(KERN_ERR "kill_kthread_module_init failed");
    return -ENODEV;
  }
    
  return 0;
}

static void __exit kill_kthread_module_exit(void)
{
  debugfs_remove(dentry_file);
}

module_init(kill_kthread_module_init);
module_exit(kill_kthread_module_exit);
