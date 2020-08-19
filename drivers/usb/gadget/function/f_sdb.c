/*
 * Gadget Driver for Samsung SDB (based on Android ADB)
 *
 * Copyright (C) 2008 Google, Inc.
 * Author: Mike Lockwood <lockwood@android.com>
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

/* #define DEBUG */
/* #define VERBOSE_DEBUG */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/err.h>
#include <linux/interrupt.h>

#include <linux/types.h>
#include <linux/device.h>
#include <linux/miscdevice.h>

#define SDB_BULK_BUFFER_SIZE           4096

/* number of tx requests to allocate */
#define SDB_TX_REQ_MAX 4

static const char sdb_shortname[] = "samsung_sdb";

static DEFINE_MUTEX(sdb_lock);

struct sdb_ep_descs {
	struct usb_endpoint_descriptor	*in;
	struct usb_endpoint_descriptor	*out;
};

struct f_sdb {
	struct usb_function function;
	u8	inf_id;

	struct sdb_ep_descs	fs;
	struct sdb_ep_descs hs;

	struct usb_ep *ep_in;
	struct usb_ep *ep_out;

	struct list_head bulk_in_q;
};

struct sdb_dev {
	struct f_sdb *sdb_func;
	spinlock_t lock;

	int online;
	int error;

	atomic_t read_excl;
	atomic_t write_excl;
	atomic_t open_excl;

	struct list_head *tx_idle;

	wait_queue_head_t read_wq;
	wait_queue_head_t write_wq;

	struct usb_request *rx_req;
	int rx_done;
};

static struct usb_interface_descriptor sdb_interface_desc = {
	.bLength                = USB_DT_INTERFACE_SIZE,
	.bDescriptorType        = USB_DT_INTERFACE,
	/* .bInterfaceNumber	= DYNAMIC */
	.bNumEndpoints          = 2,
	.bInterfaceClass        = 0xFF,
	.bInterfaceSubClass     = 0x20,
	.bInterfaceProtocol     = 0x02,
	/* .iInterface			= DYNAMIC */
};

static struct usb_endpoint_descriptor sdb_fullspeed_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	/* .wMaxPacketSize set by autoconfiguration */
};

static struct usb_endpoint_descriptor sdb_fullspeed_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	/* .wMaxPacketSize set by autoconfiguration */
};

static struct usb_descriptor_header *fs_sdb_descs[] = {
	(struct usb_descriptor_header *) &sdb_interface_desc,
	(struct usb_descriptor_header *) &sdb_fullspeed_in_desc,
	(struct usb_descriptor_header *) &sdb_fullspeed_out_desc,
	NULL,
};

static struct usb_endpoint_descriptor sdb_highspeed_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	/* bEndpointAddress copied from sdb_fullspeed_in_desc
		during sdb_function_bind() */
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor sdb_highspeed_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	/* bEndpointAddress copied from sdb_fullspeed_in_desc
		during sdb_function_bind() */
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(512),
};

static struct usb_descriptor_header *hs_sdb_descs[] = {
	(struct usb_descriptor_header *) &sdb_interface_desc,
	(struct usb_descriptor_header *) &sdb_highspeed_in_desc,
	(struct usb_descriptor_header *) &sdb_highspeed_out_desc,
	NULL,
};

/* string descriptors: */

#define F_SDB_IDX	0

/* static strings, in UTF-8 */
static struct usb_string sdb_string_defs[] = {
	[F_SDB_IDX].s = "Samsung SDB",
	{  /* ZEROES END LIST */ },
};

static struct usb_gadget_strings sdb_string_table = {
	.language =		0x0409,	/* en-us */
	.strings =		sdb_string_defs,
};

static struct usb_gadget_strings *sdb_strings[] = {
	&sdb_string_table,
	NULL,
};

/* temporary variable used between sdb_open() and sdb_gadget_bind() */
static struct sdb_dev *_sdb_dev;


static inline struct f_sdb *func_to_sdb(struct usb_function *f)
{
	return container_of(f, struct f_sdb, function);
}


static struct usb_request *sdb_request_new(struct usb_ep *ep, int buffer_size)
{
	struct usb_request *req = usb_ep_alloc_request(ep, GFP_KERNEL);
	if (!req)
		return NULL;

	/* now allocate buffers for the requests */
	req->buf = kmalloc(buffer_size, GFP_KERNEL);
	if (!req->buf) {
		usb_ep_free_request(ep, req);
		return NULL;
	}

	return req;
}

static void sdb_request_free(struct usb_request *req, struct usb_ep *ep)
{
	if (req) {
		kfree(req->buf);
		usb_ep_free_request(ep, req);
	}
}

static inline int _sdb_lock(atomic_t *excl)
{
	if (atomic_inc_return(excl) == 1) {
		return 0;
	} else {
		atomic_dec(excl);
		return -1;
	}
}

static inline void _sdb_unlock(atomic_t *excl)
{
	atomic_dec(excl);
}

/* add a request to the tail of a list */
static void sdb_req_put(struct sdb_dev *dev, struct list_head *head,
		struct usb_request *req)
{
	unsigned long flags;

	if (!dev || !req)
		return;

	spin_lock_irqsave(&dev->lock, flags);
	if (head)
		list_add_tail(&req->list, head);
	spin_unlock_irqrestore(&dev->lock, flags);
}

/* remove a request from the head of a list */
static struct usb_request *sdb_req_get(struct sdb_dev *dev,
				struct list_head *head)
{
	unsigned long flags;
	struct usb_request *req;

	if (!dev)
		return NULL;

	spin_lock_irqsave(&dev->lock, flags);
	if (!head)
		req = NULL;
	else {
		if (list_empty(head)) {
			req = NULL;
		} else {
			req = list_first_entry(head, struct usb_request, list);
			list_del(&req->list);
		}
	}
	spin_unlock_irqrestore(&dev->lock, flags);
	return req;
}

static void sdb_complete_in(struct usb_ep *ep, struct usb_request *req)
{
	struct sdb_dev *dev = _sdb_dev;
	struct f_sdb *sdb_func = ep->driver_data;

	if (req->status != 0)
		dev->error = 1;

	sdb_req_put(dev, &sdb_func->bulk_in_q, req);
	wake_up(&dev->write_wq);
}

static void sdb_complete_out(struct usb_ep *ep, struct usb_request *req)
{
	struct sdb_dev *dev = _sdb_dev;

	dev->rx_done = 1;
	if (req->status != 0)
		dev->error = 1;

	wake_up(&dev->read_wq);
}

static int sdb_create_bulk_endpoints(struct f_sdb *sdb_func,
				struct usb_endpoint_descriptor *in_desc,
				struct usb_endpoint_descriptor *out_desc)
{
	struct usb_composite_dev *cdev = sdb_func->function.config->cdev;
	struct usb_request *req;
	struct sdb_dev *dev = _sdb_dev;
	struct usb_ep *ep;
	int i;

	DBG(cdev, "sdb_create_bulk_endpoints dev: %p\n", dev);

	ep = usb_ep_autoconfig(cdev->gadget, in_desc);
	if (!ep) {
		ERROR(cdev, "usb_ep_autoconfig for ep_in failed\n");
		return -ENODEV;
	}
	DBG(cdev, "usb_ep_autoconfig for ep_in got %s\n", ep->name);
	ep->driver_data = cdev;		/* claim the endpoint */
	sdb_func->ep_in = ep;

	ep = usb_ep_autoconfig(cdev->gadget, out_desc);
	if (!ep) {
		ERROR(cdev, "usb_ep_autoconfig for ep_out failed\n");
		return -ENODEV;
	}
	DBG(cdev, "usb_ep_autoconfig for sdb ep_out got %s\n", ep->name);
	ep->driver_data = cdev;		/* claim the endpoint */
	sdb_func->ep_out = ep;

	/* now allocate requests for our endpoints */
	req = sdb_request_new(sdb_func->ep_out, SDB_BULK_BUFFER_SIZE);
	if (!req)
		return -ENOMEM;
	req->complete = sdb_complete_out;
	dev->rx_req = req;

	for (i = 0; i < SDB_TX_REQ_MAX; i++) {
		req = sdb_request_new(sdb_func->ep_in, SDB_BULK_BUFFER_SIZE);
		if (!req)
			goto fail;
		req->complete = sdb_complete_in;
		sdb_req_put(dev, &sdb_func->bulk_in_q, req);
	}

	return 0;

fail:
	while (!!(req = sdb_req_get(dev, &sdb_func->bulk_in_q)))
		sdb_request_free(req, sdb_func->ep_in);

	sdb_request_free(dev->rx_req, sdb_func->ep_out);
	dev->rx_req = NULL;

	if (sdb_func->ep_in)
		sdb_func->ep_in->driver_data = NULL;
	if (sdb_func->ep_out)
		sdb_func->ep_out->driver_data = NULL;

	printk(KERN_ERR "sdb_bind() could not allocate requests\n");
	return -ENOMEM;
}

static ssize_t sdb_read(struct file *fp, char __user *buf,
				size_t count, loff_t *pos)
{
	struct sdb_dev *dev = fp->private_data;
	int r = count, xfer;
	int ret;

	if (count > SDB_BULK_BUFFER_SIZE)
		return -EINVAL;

	if (_sdb_lock(&dev->read_excl))
		return -EBUSY;

	/* we will block until we're online */
	while (!(dev->online || dev->error)) {
		ret = wait_event_interruptible(dev->read_wq,
				(dev->online || dev->error));
		if (ret < 0) {
			_sdb_unlock(&dev->read_excl);
			return ret;
		}
	}
	if (dev->error) {
		r = -EIO;
		goto done;
	}

requeue_req:
	/* queue a request */
	mutex_lock(&sdb_lock);
	if (!dev->sdb_func || !dev->rx_req)
		ret = -ENODEV;
	else {
		dev->rx_req->length = count;
		dev->rx_done = 0;
		ret = usb_ep_queue(dev->sdb_func->ep_out,
				dev->rx_req, GFP_ATOMIC);
	}
	mutex_unlock(&sdb_lock);

	if (ret < 0) {
		r = -EIO;
		dev->error = 1;
		goto done;
	}

	/* wait for a request to complete */
	ret = wait_event_interruptible(dev->read_wq, dev->rx_done);
	if (ret < 0) {
		dev->error = 1;
		r = ret;
		goto done;
	}
	if (!dev->error) {
		/* If we got a 0-len packet, throw it back and try again. */
		if (dev->rx_req->actual == 0)
			goto requeue_req;

		mutex_lock(&sdb_lock);
		if (!dev->sdb_func || !dev->rx_req)
			r = -ENODEV;
		else {
			xfer = (dev->rx_req->actual < count)
					? dev->rx_req->actual : count;
			if (copy_to_user(buf, dev->rx_req->buf, xfer))
				r = -EFAULT;
		}
		mutex_unlock(&sdb_lock);
	} else
		r = -EIO;

done:
	_sdb_unlock(&dev->read_excl);
	return r;
}

static ssize_t sdb_write(struct file *fp, const char __user *buf,
				 size_t count, loff_t *pos)
{
	struct sdb_dev *dev = fp->private_data;
	struct usb_request *req = 0;
	int r = count, xfer;
	int ret;

	if (_sdb_lock(&dev->write_excl))
		return -EBUSY;

	while (count > 0) {
		if (dev->error) {
			r = -EIO;
			break;
		}

		/* get an idle tx request to use */
		req = 0;
		ret = wait_event_interruptible(dev->write_wq,
				(!!(req = sdb_req_get(dev, dev->tx_idle))
				 || dev->error));

		if (ret < 0) {
			r = ret;
			break;
		}

		if (req != 0) {
			if (count > SDB_BULK_BUFFER_SIZE)
				xfer = SDB_BULK_BUFFER_SIZE;
			else
				xfer = count;

			mutex_lock(&sdb_lock);
			if (!dev->sdb_func) {
				mutex_unlock(&sdb_lock);
				r = -ENODEV;
				break;
			} else if (copy_from_user(req->buf, buf, xfer)) {
				mutex_unlock(&sdb_lock);
				r = -EFAULT;
				break;
			}

			req->length = xfer;
			ret = usb_ep_queue(dev->sdb_func->ep_in,
					req, GFP_ATOMIC);
			mutex_unlock(&sdb_lock);

			if (ret < 0) {
				dev->error = 1;
				r = -EIO;
				break;
			}

			buf += xfer;
			count -= xfer;

			/* zero this so we don't try to free it on error exit */
			req = 0;
		}
	}

	if (req)
		sdb_req_put(dev, dev->tx_idle, req);

	_sdb_unlock(&dev->write_excl);
	return r;
}

static int sdb_open(struct inode *ip, struct file *fp)
{
	printk(KERN_INFO "sdb_open\n");
	if (_sdb_lock(&_sdb_dev->open_excl))
		return -EBUSY;

	fp->private_data = _sdb_dev;

	/* clear the error latch */
	_sdb_dev->error = 0;

	return 0;
}

static int sdb_release(struct inode *ip, struct file *fp)
{
	printk(KERN_INFO "sdb_release\n");

	if (_sdb_dev != NULL)
		_sdb_unlock(&_sdb_dev->open_excl);

	return 0;
}

/* file operations for SDB device /dev/samsung_sdb */
static const struct file_operations sdb_fops = {
	.owner = THIS_MODULE,
	.read = sdb_read,
	.write = sdb_write,
	.open = sdb_open,
	.release = sdb_release,
};

static struct miscdevice sdb_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = sdb_shortname,
	.fops = &sdb_fops,
};

static int
sdb_function_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct f_sdb *sdb_func = func_to_sdb(f);
	int			id;
	int			ret;

	DBG(cdev, "sdb_function_bind sdb_func: %p\n", sdb_func);

	/* allocate interface ID(s) */
	id = usb_interface_id(c, f);
	if (id < 0)
		return id;

	sdb_func->inf_id = id;
	sdb_interface_desc.bInterfaceNumber = id;

	/* allocate endpoints */
	ret = sdb_create_bulk_endpoints(sdb_func, &sdb_fullspeed_in_desc,
			&sdb_fullspeed_out_desc);
	if (ret)
		return ret;

	f->descriptors = usb_copy_descriptors(fs_sdb_descs);
	if (!f->descriptors)
		goto desc_alloc_fail;

	sdb_func->fs.in = usb_find_endpoint(fs_sdb_descs, f->descriptors,
					&sdb_fullspeed_in_desc);
	sdb_func->fs.out = usb_find_endpoint(fs_sdb_descs, f->descriptors,
					&sdb_fullspeed_out_desc);

	/* support high speed hardware */
	if (gadget_is_dualspeed(cdev->gadget)) {
		sdb_highspeed_in_desc.bEndpointAddress =
			sdb_fullspeed_in_desc.bEndpointAddress;
		sdb_highspeed_out_desc.bEndpointAddress =
			sdb_fullspeed_out_desc.bEndpointAddress;

		f->hs_descriptors = usb_copy_descriptors(hs_sdb_descs);
		if (!f->hs_descriptors)
			goto desc_alloc_fail;

		sdb_func->hs.in = usb_find_endpoint(hs_sdb_descs,
				f->hs_descriptors, &sdb_highspeed_in_desc);
		sdb_func->hs.out = usb_find_endpoint(hs_sdb_descs,
				f->hs_descriptors, &sdb_highspeed_out_desc);
	}

	return 0;

desc_alloc_fail:
	if (f->descriptors)
		usb_free_descriptors(f->descriptors);

	return -ENOMEM;
}

static void
sdb_function_unbind(struct usb_configuration *c, struct usb_function *f)
{
	struct sdb_dev *dev = _sdb_dev;
	struct f_sdb *sdb_func = func_to_sdb(f);
	struct usb_request *req;

	dev->online = 0;
	dev->error = 1;

	if (gadget_is_dualspeed(c->cdev->gadget))
		usb_free_descriptors(f->hs_descriptors);
	usb_free_descriptors(f->descriptors);

	mutex_lock(&sdb_lock);

	while (!!(req = sdb_req_get(dev, &sdb_func->bulk_in_q)))
		sdb_request_free(req, sdb_func->ep_in);

	sdb_request_free(dev->rx_req, sdb_func->ep_out);

	kfree(sdb_func);
	dev->sdb_func = NULL;
	dev->rx_req = NULL;

	mutex_unlock(&sdb_lock);

	wake_up(&dev->read_wq);
	wake_up(&dev->write_wq);
}

static int sdb_function_set_alt(struct usb_function *f,
		unsigned intf, unsigned alt)
{
	struct f_sdb *sdb_func = func_to_sdb(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	struct sdb_dev *dev = _sdb_dev;
	int ret;

	if (sdb_func->inf_id != intf) {
		printk(KERN_ERR "sdb_function_set_alt error wrong intf:%d alt:%d\n",
						intf, alt);
		return -EINVAL;
	}

	if (sdb_func->ep_in->driver_data)
		usb_ep_disable(sdb_func->ep_in);
	ret = usb_ep_enable(sdb_func->ep_in,
			ep_choose(cdev->gadget,
				sdb_func->hs.in, sdb_func->fs.in));
	if (ret) {
		printk(KERN_ERR "error, usb_ep_enable for sdb ep_in\n");
		return ret;
	}
	sdb_func->ep_in->driver_data = sdb_func;

	if (sdb_func->ep_out->driver_data)
		usb_ep_disable(sdb_func->ep_out);
	ret = usb_ep_enable(sdb_func->ep_out,
			ep_choose(cdev->gadget,
				sdb_func->hs.out, sdb_func->fs.out));
	if (ret) {
		usb_ep_disable(sdb_func->ep_in);
		sdb_func->ep_in->driver_data = NULL;
		printk(KERN_ERR "error, usb_ep_enable for sdb ep_out\n");
		return ret;
	}
	sdb_func->ep_out->driver_data = sdb_func;

	dev->tx_idle = &sdb_func->bulk_in_q;
	dev->sdb_func = sdb_func;
	dev->online = 1;

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);
	return 0;
}

static void sdb_function_disable(struct usb_function *f)
{
	struct sdb_dev *dev = _sdb_dev;
	struct f_sdb *sdb_func = func_to_sdb(f);

	dev->online = 0;
	dev->error = 1;

	spin_lock(&dev->lock);
	dev->tx_idle = NULL;
	spin_unlock(&dev->lock);

	usb_ep_disable(sdb_func->ep_in);
	sdb_func->ep_in->driver_data = NULL;

	usb_ep_disable(sdb_func->ep_out);
	sdb_func->ep_out->driver_data = NULL;

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);
	wake_up(&dev->write_wq);
}

static int sdb_setup(struct usb_composite_dev *cdev)
{
	struct sdb_dev *dev;
	int ret;

	printk(KERN_INFO "sdb_bind_config\n");

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	if (sdb_string_defs[F_SDB_IDX].id == 0) {
		ret = usb_string_id(cdev);
		if (ret < 0) {
			kfree(dev);
			return ret;
		}
		sdb_string_defs[F_SDB_IDX].id = ret;
		sdb_interface_desc.iInterface = ret;
	}

	spin_lock_init(&dev->lock);

	init_waitqueue_head(&dev->read_wq);
	init_waitqueue_head(&dev->write_wq);

	atomic_set(&dev->open_excl, 0);
	atomic_set(&dev->read_excl, 0);
	atomic_set(&dev->write_excl, 0);


	/* _sdb_dev must be set before calling usb_gadget_register_driver */
	_sdb_dev = dev;

	ret = misc_register(&sdb_device);
	if (ret)
		goto err1;

	return 0;

err1:
	kfree(dev);
	_sdb_dev = NULL;
	printk(KERN_ERR "sdb gadget driver failed to initialize\n");
	return ret;
}

static int sdb_bind_config(struct usb_configuration *c)
{
	int ret;
	struct f_sdb *sdb_func;

	if (!_sdb_dev) {
		printk(KERN_ERR "Error There is no _sdb_dev!!\n");
		return -ENODEV;
	}

	sdb_func = kzalloc(sizeof(*sdb_func), GFP_KERNEL);
	if (!sdb_func) {
		printk(KERN_ERR "sdb_func memory alloc failed !!!\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&sdb_func->bulk_in_q);

	sdb_func->function.name = "sdb";
	sdb_func->function.strings = sdb_strings;
	sdb_func->function.bind = sdb_function_bind;
	sdb_func->function.unbind = sdb_function_unbind;
	sdb_func->function.set_alt = sdb_function_set_alt;
	sdb_func->function.disable = sdb_function_disable;

	ret = usb_add_function(c, &sdb_func->function);
	if (ret)
		printk(KERN_ERR "Error in usb_add_function failed for sdb\n");

	return ret;
}

static void sdb_cleanup(void)
{
	struct sdb_dev	*dev = _sdb_dev;

	misc_deregister(&sdb_device);

	if (!dev)
		return;
	_sdb_dev = NULL;
	kfree(dev);
}
