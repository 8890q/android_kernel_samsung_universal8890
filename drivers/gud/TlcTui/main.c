/*
 * Copyright (c) 2013-2014 TRUSTONIC LIMITED
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "tui_ioctl.h"
#include "tlcTui.h"
#include "mobicore_driver_api.h"
#include "dciTui.h"
#include "tui-hal.h"
#include "build_tag.h"

/*static int tui_dev_major_number = 122; */

/*module_param(tui_dev_major_number, int, 0000); */
/*MODULE_PARM_DESC(major, */
/* "The device major number used to register a unique char device driver"); */

/* Static variables */
static struct cdev tui_cdev;

int tui_force_close(uint32_t arg)
{
	int ret = 0;

	pr_info("Force TUI_IO_NOTIFY %d\n", arg);

	if (tlc_notify_event(arg))
		ret = 0;
	else
		ret = -EFAULT;
}
EXPORT_SYMBOL(tui_force_close);

static long tui_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int ret = -ENOTTY;
	int __user *uarg = (int __user *)arg;

	if (_IOC_TYPE(cmd) != TUI_IO_MAGIC)
		return -EINVAL;

	pr_info("t-base-tui module: ioctl 0x%x ", cmd);

	switch (cmd) {
	case TUI_IO_NOTIFY:
		pr_info("TUI_IO_NOTIFY\n");

		if (tlc_notify_event(arg))
			ret = 0;
		else
			ret = -EFAULT;
		break;

	case TUI_IO_WAITCMD: {
		uint32_t cmd_id;

		pr_info("TUI_IO_WAITCMD\n");

		ret = tlc_wait_cmd(&cmd_id);
		if (ret) {
			pr_debug("ERROR %s:%d tlc_wait_cmd returned (0x%08X)\n",
				__func__, __LINE__, ret);
			return ret;
		}

		/* Write command id to user */
		pr_debug("IOCTL: sending command %d to user.\n", cmd_id);

		if (copy_to_user(uarg, &cmd_id, sizeof(cmd_id)))
			ret = -EFAULT;
		else
			ret = 0;

		break;
	}

	case TUI_IO_ACK: {
		struct tlc_tui_response_t rsp_id;

		pr_info("TUI_IO_ACK\n");

		/* Read user response */
		if (copy_from_user(&rsp_id, uarg, sizeof(rsp_id)))
			ret = -EFAULT;
		else
			ret = 0;

		pr_debug("IOCTL: User completed command %d.\n", rsp_id.id);
		ret = tlc_ack_cmd(&rsp_id);
		if (ret)
			return ret;
		break;
	}

	case TUI_IO_INIT_DRIVER: {
		pr_info("TUI_IO_INIT_DRIVER : no action\n");
		return 0;
	}

	case TUI_IO_DISPLAY_NOTIFY: {
		struct tlc_tui_display_t response;
		pr_info("TUI_IO_DISPLAY_NOTIFY\n");

		/* Read user response */
		if (copy_from_user(&response, uarg, sizeof(response)))
			ret = -EFAULT;
		else
			ret = 0;
    
		pr_info("IOCTL: User completed command w=%d, h=%d.\n", response.width, response.height);
    
		ret = tlc_display_cmd(&response);
		if(ret != 0)
		return ret;
        
		break;
	}

	default:
		pr_info("undefined!\n");
		return -ENOTTY;
	}

	return ret;
}

atomic_t fileopened;
static int tui_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "TUI file opened");
	atomic_inc(&fileopened);
	return 0;
}

static int tui_release(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "TUI file closed");
	atomic_dec(&fileopened);
	return 0;
}

static const struct file_operations tui_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tui_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tui_ioctl,
#endif
	.open = tui_open,
	.release = tui_release,
};

/*--------------------------------------------------------------------------- */
static int __init tlc_tui_init(void)
{
	pr_info("Loading t-base-tui module.\n");
	pr_debug("\n=============== Running TUI Kernel TLC ===============\n");
	pr_info("%s\n", MOBICORE_COMPONENT_BUILD_TAG);

	dev_t devno;
	int err;
	static struct class *tui_class;

	atomic_set(&fileopened, 0);

	err = alloc_chrdev_region(&devno, 0, 1, TUI_DEV_NAME);
	if (err) {
		pr_debug(KERN_ERR "Unable to allocate Trusted UI device number\n");
		return err;
	}

	cdev_init(&tui_cdev, &tui_fops);
	tui_cdev.owner = THIS_MODULE;
	/*    tui_cdev.ops = &tui_fops; */

	err = cdev_add(&tui_cdev, devno, 1);
	if (err) {
		pr_debug(KERN_ERR "Unable to add Trusted UI char device\n");
		unregister_chrdev_region(devno, 1);
		return err;
	}

	tui_class = class_create(THIS_MODULE, "tui_cls");
	device_create(tui_class, NULL, devno, NULL, TUI_DEV_NAME);

	if (!hal_tui_init())
		return -EPERM;
	return 0;
}

static void __exit tlc_tui_exit(void)
{
	pr_info("Unloading t-base-tui module.\n");

	unregister_chrdev_region(tui_cdev.dev, 1);
	cdev_del(&tui_cdev);

	hal_tui_exit();
}

module_init(tlc_tui_init);
module_exit(tlc_tui_exit);

MODULE_AUTHOR("Trustonic Limited");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("<t-base TUI");
