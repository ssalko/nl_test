#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

#define MAJOR_NUM 60
#define DEVICE_NAME "nl_test"

enum msg_id_t {
	TEE_REGISTER_SERVER = 1,
	TEE_TEST_SERVER,
	TEE_RESERVED = 0xFFFF,
};

struct tee_msg {
	enum msg_id_t msg_id;
	uint16_t flags;
	uint32_t msg_data_len;
	char msg_data[MAX_PAYLOAD - 8];
};

enum ioctls_cmds {
	NLTEST_TEST_SERVER = 0,
};

struct sock *nl_sk = NULL;
struct tee_msg *waiting_msg = NULL;
int server_pid = -1;

DECLARE_WAIT_QUEUE_HEAD(nltest_queue);

static int send_message(struct tee_msg *msg)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nlh;
	int msg_size = sizeof(*msg);
	int ret;

	if (server_pid < 0) {
		pr_err("No server attached!\n");
		return -EFAULT;
	}

pr_err("msg_size: %d msg: %s\n", msg_size, msg->msg_data);
	skb_out = nlmsg_new(msg_size, 0);

	if (!skb_out)
	{
		printk(KERN_ERR "Failed to allocate new skb\n");
		return -ENOMEM;
	}
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0; // not in mcast group

	memcpy(nlmsg_data(nlh), msg, msg_size);

	ret = nlmsg_unicast(nl_sk, skb_out, server_pid);

	if (ret < 0)
		printk(KERN_INFO "Error while sending bak to user\n");

	pr_info("sent msg to pid %d\n", server_pid);

	return ret;
}

static int nltest_test_server(unsigned long arg)
{
	struct tee_msg __user *user_msg = (struct tee_msg __user *)arg;
	struct tee_msg *msg;

	msg = kmalloc(sizeof(user_msg), GFP_KERNEL);

	if (copy_from_user(msg, user_msg, sizeof(*user_msg))) {
		pr_err("Reading message failed\n");
		return -EFAULT;
	}
pr_err("msg: %p data: %s\n", &user_msg->msg_data, msg->msg_data);

	waiting_msg =	NULL;
	send_message(msg);

	wait_event(nltest_queue, waiting_msg != NULL);
pr_err("msg: %p data: %s\n", msg->msg_data, msg->msg_data);

	copy_to_user(user_msg, waiting_msg, sizeof(*waiting_msg));
	waiting_msg =	NULL;
	kfree(msg);

	return 0;
}

static int nltest_open(struct inode *inode, struct file *file)
{
	pr_info("open\n");
	return 0;
}

static int nltest_release(struct inode *inode, struct file *file)
{
	pr_info("release\n");
	return 0;
}

static ssize_t nltest_read(struct file *filp, char *buf, size_t len, loff_t *offs)
{
	pr_err("read\n");
	return -EINVAL;
}

static ssize_t nltest_write(struct file *filp, const char *buf, size_t len, loff_t *offs)
{
	pr_err("write\n");
	return -EINVAL;
}

static ssize_t nltest_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	pr_err("ioctl\n");

	switch (cmd) {
	case NLTEST_TEST_SERVER:
		pr_info("test server\n");
		ret = nltest_test_server(arg);
		break;
	default:
		pr_err("Invalid ioctl cmd!\n");
		ret = -EINVAL;
		break;
	}

	return ret;
}

static struct file_operations fops = {
	.open = nltest_open,
	.release = nltest_release,
	.read = nltest_read,
	.write = nltest_write,
	.unlocked_ioctl = nltest_ioctl,
	.mmap = NULL,
};

static void nltest_input(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct tee_msg *msg;
	int pid;

	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

	nlh = (struct nlmsghdr *)skb->data;
	pid = nlh->nlmsg_pid;
	msg = nlmsg_data(nlh);

	if (server_pid >= 0 && pid != server_pid) {
		pr_err("Wrong process! %d %d\n", pid, server_pid);
		return;
	}
	
	if (msg->msg_id == TEE_REGISTER_SERVER) {
		pr_info("Registering server process %d\n", pid);
		server_pid = pid;
		return;
	}

pr_err("msg: %p data: %s\n", msg->msg_data, msg->msg_data);

	waiting_msg = msg;
	wake_up(&nltest_queue);
}

static int __init nltest_init(void)
{
	int ret;
	struct netlink_kernel_cfg cfg = {
		.groups = 1,
		.input = nltest_input,
	};

	printk("Entering: %s\n", __FUNCTION__);
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if (!nl_sk)
	{
		printk(KERN_ALERT "Error creating socket.\n");
		return -ENOMEM;
	}

	ret = register_chrdev(MAJOR_NUM, DEVICE_NAME, &fops);
	if (ret < 0) {
		pr_err("??\n");
		netlink_kernel_release(nl_sk);
		return ret;
	}

	return 0;
}

static void __exit nltest_exit(void)
{
	printk(KERN_INFO "exiting hello module\n");
	netlink_kernel_release(nl_sk);

	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
}

module_init(nltest_init);
module_exit(nltest_exit);

MODULE_LICENSE("GPL");
