/*
 * Copyright (C) 2017 Samsung Electronics.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_platform.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include <linux/dev_ril_bridge.h>

#define LOG_TAG "drb: "

#define drb_err(fmt, ...) \
	pr_err(LOG_TAG "%s: " pr_fmt(fmt), __func__, ##__VA_ARGS__)

#define drb_debug(fmt, ...) \
	pr_debug(LOG_TAG "%s: " pr_fmt(fmt), __func__, ##__VA_ARGS__)

#define drb_info(fmt, ...) \
	pr_info(LOG_TAG "%s: " pr_fmt(fmt), __func__, ##__VA_ARGS__)

struct drb_dev {
	atomic_t opened;
	wait_queue_head_t wq;
	struct sk_buff_head sk_rx_q;
	struct miscdevice miscdev;
};

static struct drb_dev *drb_dev;

int dev_ril_bridge_send_msg(int id, int size, void *buf)
{
	struct sk_buff *skb;
	struct sk_buff_head *rxq;
	struct sipc_fmt_hdr *sipc_hdr;
	unsigned int alloc_size;
	unsigned int headroom;

	drb_info("id=%d size=%d\n", id, size);
	if (!drb_dev) {
		drb_err("ERR! dev_ril_bridge is not ready\n");
		return -ENODEV;
	}

	rxq = &drb_dev->sk_rx_q;
	headroom = sizeof(struct sipc_fmt_hdr);
	alloc_size = size + headroom;

	skb = alloc_skb(alloc_size, GFP_ATOMIC);
	if (!skb) {
		drb_err("ERR! alloc_skb fail\n");
		return -ENOMEM;
	}

	skb_reserve(skb, headroom);
	memcpy(skb_put(skb, size), buf, size);

	sipc_hdr = (struct sipc_fmt_hdr *)skb_push(skb, headroom);
	sipc_hdr->len = alloc_size;
	sipc_hdr->main_cmd = 0x27;
	sipc_hdr->sub_cmd = id;
	sipc_hdr->cmd_type = 0x05;

	skb_queue_tail(rxq, skb);

	if (atomic_read(&drb_dev->opened) > 0)
		wake_up(&drb_dev->wq);
	else
		return -EPIPE;

	return 0;
}

static RAW_NOTIFIER_HEAD(dev_ril_bridge_chain);

int register_dev_ril_bridge_event_notifier(struct notifier_block *nb)
{
	if (!nb)
		return -ENOENT;

	return raw_notifier_chain_register(&dev_ril_bridge_chain, nb);
}

static int misc_open(struct inode *inode, struct file *filp)
{
	filp->private_data = (void *)drb_dev;
	atomic_inc(&drb_dev->opened);

	drb_info("drb (opened %d) by %s\n",
			atomic_read(&drb_dev->opened), current->comm);

	return 0;
}

static int misc_release(struct inode *inode, struct file *filp)
{
	struct drb_dev *drb_dev = (struct drb_dev *)filp->private_data;

	if (atomic_dec_and_test(&drb_dev->opened)) {
		skb_queue_purge(&drb_dev->sk_rx_q);
	}
	
	filp->private_data = NULL;

	drb_info("drb (opened %d) by %s\n",
			atomic_read(&drb_dev->opened), current->comm);

	return 0;
}

static unsigned int misc_poll(struct file *filp, struct poll_table_struct *wait)
{
	struct drb_dev *drb_dev = (struct drb_dev *)filp->private_data;
	struct sk_buff_head *rxq;
	int ret = 0;

	if (!drb_dev)
		return POLLERR;

	rxq = &drb_dev->sk_rx_q;

	if (skb_queue_empty(rxq))
		poll_wait(filp, &drb_dev->wq, wait);

	if (!skb_queue_empty(rxq))
		ret = POLLIN | POLLRDNORM;

	drb_info("poll done by %s (%d)\n", current->comm, ret);

	return ret;
}

static ssize_t misc_read(struct file *filp, char *buf, size_t count,
			loff_t *fops)
{
	struct drb_dev *drb_dev = (struct drb_dev *)filp->private_data;
	struct sk_buff_head *rxq = &drb_dev->sk_rx_q;
	struct sk_buff *skb;
	unsigned int copied;

	if (skb_queue_empty(rxq)) {
		long tmo = msecs_to_jiffies(100);
		wait_event_timeout(drb_dev->wq, !skb_queue_empty(rxq), tmo);
	}

	skb = skb_dequeue(rxq);
	if (unlikely(!skb)) {
		drb_err("No data in RXQ\n");
		return 0;
	}

	copied = skb->len > count ? count : skb->len;

	if (copy_to_user(buf, skb->data, copied)) {
		drb_err("ERR! copy_to_user fail\n");
		dev_kfree_skb_any(skb);
		return -EFAULT;
	}

	drb_info("data:%d copied:%d qlen:%d\n", skb->len, copied, rxq->qlen);

	if (skb->len > copied) {
		skb_pull(skb, copied);
		skb_queue_head(rxq, skb);
	} else {
		dev_kfree_skb_any(skb);
	}

	return copied;
}

static const struct file_operations misc_io_fops = {
	.owner = THIS_MODULE,
	.open = misc_open,
	.release = misc_release,
	.poll = misc_poll,
	.read = misc_read,
};

static ssize_t notify_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	/* no need to prepare read function */
	return 0;
}

static ssize_t notify_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	/* buf head may be consist of some structures */

	drb_info("event notify (%ld) ++\n", size);
	raw_notifier_call_chain(&dev_ril_bridge_chain, size, (void *)buf);
	drb_info("event notify (%ld) --\n", size);

	return size;
}
static DEVICE_ATTR_RW(notify);

static struct attribute *dev_ril_bridge_attrs[] = {
	&dev_attr_notify.attr,
	NULL,
};
ATTRIBUTE_GROUPS(dev_ril_bridge);

static struct class *dev_ril_bridge_class;
static struct device *dev_ril_bridge_device;

static int dev_ril_bridge_probe(struct platform_device *pdev)
{
	int err = 0;

	drb_info("+++\n");

	/* node /sys/class/dev_ril_bridge/dev_ril_bridge/notify */

	dev_ril_bridge_class = class_create(THIS_MODULE, "dev_ril_bridge");
	if (IS_ERR(dev_ril_bridge_class)) {
		drb_err("couldn't register device class\n");
		err = PTR_ERR(dev_ril_bridge_class);
		goto out;
	}

	dev_ril_bridge_device = device_create_with_groups(dev_ril_bridge_class,
			NULL, 0, MKDEV(0, 0), dev_ril_bridge_groups, "%s",
			"dev_ril_bridge");
	if (IS_ERR(dev_ril_bridge_device)) {
		drb_err("couldn't register system device\n");
		err = PTR_ERR(dev_ril_bridge_device);
		goto out_class;
	}

	drb_dev = kzalloc(sizeof(struct drb_dev), GFP_KERNEL);
	if (drb_dev == NULL)
		return -ENOMEM;

	init_waitqueue_head(&drb_dev->wq);
	skb_queue_head_init(&drb_dev->sk_rx_q);

	drb_dev->miscdev.minor = MISC_DYNAMIC_MINOR;
	drb_dev->miscdev.name = "drb";
	drb_dev->miscdev.fops = &misc_io_fops;

	err = misc_register(&drb_dev->miscdev);
	if (err) {
		drb_err("misc_register fail\n");
		goto out;
	}

	drb_info("---\n");

	return 0;

out_class:
	class_destroy(dev_ril_bridge_class);
out:
	drb_info("err = %d ---\n", err);
	return err;
}

static void dev_ril_bridge_shutdown(struct platform_device *pdev)
{
	misc_deregister(&drb_dev->miscdev);
	kfree(drb_dev);
	device_unregister(dev_ril_bridge_device);
	class_destroy(dev_ril_bridge_class);
}

#ifdef CONFIG_PM
static int dev_ril_bridge_suspend(struct device *dev)
{
	return 0;
}

static int dev_ril_bridge_resume(struct device *dev)
{
	return 0;
}
#else
#define dev_ril_bridge_suspend NULL
#define dev_ril_bridge_resume NULL
#endif

static const struct dev_pm_ops dev_ril_bridge_pm_ops = {
	.suspend = dev_ril_bridge_suspend,
	.resume = dev_ril_bridge_resume,
};

static const struct of_device_id dev_ril_bridge_match[] = {
	{ .compatible = "samsung,dev_ril_bridge_pdata", },
	{},
};
MODULE_DEVICE_TABLE(of, dev_ril_bridge_match);

static struct platform_driver dev_ril_bridge_driver = {
	.probe = dev_ril_bridge_probe,
	.shutdown = dev_ril_bridge_shutdown,
	.driver = {
		.name = "dev_ril_bridge",
		.owner = THIS_MODULE,
		.suppress_bind_attrs = true,
		.pm = &dev_ril_bridge_pm_ops,
#ifdef CONFIG_OF
		.of_match_table = of_match_ptr(dev_ril_bridge_match),
#endif
	},
};
module_platform_driver(dev_ril_bridge_driver);

MODULE_DESCRIPTION("dev_ril_bridge driver");
MODULE_LICENSE("GPL");
