/*
 * Copyright (c) 2013-2015 TRUSTONIC LIMITED
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

#include <linux/slab.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/freezer.h>

#include "public/mc_user.h"
#include "public/mc_admin.h"

#include "mci/mcloadformat.h"

#include "main.h"
#include "mmu.h"	/* For load_check and load_token */
#include "mcp.h"
#include "client.h"
#include "admin.h"

static struct admin_ctx {
	struct mutex admin_tgid_mutex;	/* Lock for admin_tgid below */
	pid_t admin_tgid;
	int (*tee_start_cb)(void);
	void (*tee_stop_cb)(void);
	int last_start_ret;
} admin_ctx;

static struct mc_admin_driver_request {
	/* Global */
	struct mutex mutex;		/* Protects access to this struct */
	struct mutex states_mutex;	/* Protect access to the states */
	enum client_state {
		IDLE,
		REQUEST_SENT,
		BUFFERS_READY,
	} client_state;
	enum server_state {
		NOT_CONNECTED,		/* Device not open */
		READY,			/* Waiting for requests */
		REQUEST_RECEIVED,	/* Got a request, is working */
		RESPONSE_SENT,		/* Has sent a response header */
		DATA_SENT,		/* Blocked until data is consumed */
	} server_state;
	/* Request */
	u32 request_id;
	struct mc_admin_request request;
	struct completion client_complete;
	/* Response */
	struct mc_admin_response response;
	struct completion server_complete;
	void *buffer;			/* Reception buffer (pre-allocated) */
	size_t size;			/* Size of the reception buffer */
	bool lock_channel_during_freeze;/* Is freezing ongoing ? */
} g_request;

/* The mutex around the channel communication has to be wrapped in order
 * to handle this use case :
 * client 1 calls request_send()
 *	    wait on wait_for_completion_interruptible (with channel mutex taken)
 * client 2 calls request_send()
 *	    waits on mutex_lock(channel mutex)
 * kernel starts freezing tasks (suspend or reboot ongoing)
 * if we do nothing, then the freezing will be aborted because client 1
 * and 2 have to enter the refrigerator by themselves.
 * Note : mutex cannot be held during freezing, so client 1 has release it
 * => step 1 : client 1 sets a bool that says that the channel is still in use
 * => step 2 : client 1 release the lock and enter the refrigerator
 * => now any client trying to use the channel will face the bool preventing
 * to use the channel. They also have to enter the refrigerator.
 *
 * These 3 functions handle this
 */
static void check_freezing_ongoing(void)
{
	/* We don't want to let the channel be used. Let everyone know
	 * that we're using it
	 */
	g_request.lock_channel_during_freeze = 1;
	/* Now we can safely release the lock */
	mutex_unlock(&g_request.mutex);
	/* Let's try to freeze */
	try_to_freeze();
	/* Either freezing happened or was canceled.
	 * In both cases, reclaim the lock
	 */
	mutex_lock(&g_request.mutex);
	g_request.lock_channel_during_freeze = 0;
}

static void channel_lock(void)
{
	while (1) {
		mutex_lock(&g_request.mutex);
		/* We took the lock, but is there any freezing ongoing? */
		if (g_request.lock_channel_during_freeze == 0)
			break;

		/* yes, so let's freeze */
		mutex_unlock(&g_request.mutex);
		try_to_freeze();
		/* Either freezing succeeded or was canceled.
		 * In both case, try again to get the lock.
		 * Give some CPU time to let the contender
		 * finish his channel operation
		 */
		msleep(500);
	};
}

static void channel_unlock(void)
{
	mutex_unlock(&g_request.mutex);
}

static struct tee_object *tee_object_alloc(bool is_sp_trustlet, size_t length)
{
	struct tee_object *obj;
	size_t size = sizeof(*obj) + length;
	size_t header_length = 0;

	/* Determine required size */
	if (is_sp_trustlet) {
		/* Need space for lengths info and containers */
		header_length = sizeof(struct mc_blob_len_info);
		size += header_length + 3 * MAX_SO_CONT_SIZE;
	}

	/* Check size for overflow */
	if (size < length) {
		mc_dev_err("cannot allocate object of size %zu", length);
		return NULL;
	}

	/* Allocate memory */
	obj = vzalloc(size);
	if (!obj)
		return NULL;

	/* A non-zero header_length indicates that we have a SP trustlet */
	obj->header_length = (u32)header_length;
	obj->length = (u32)length;
	return obj;
}

void tee_object_free(struct tee_object *robj)
{
	vfree(robj);
}

static inline void client_state_change(enum client_state state)
{
	mutex_lock(&g_request.states_mutex);
	g_request.client_state = state;
	mutex_unlock(&g_request.states_mutex);
}

static inline bool client_state_is(enum client_state state)
{
	bool is;

	mutex_lock(&g_request.states_mutex);
	is = g_request.client_state == state;
	mutex_unlock(&g_request.states_mutex);
	return is;
}

static inline void server_state_change(enum server_state state)
{
	mutex_lock(&g_request.states_mutex);
	g_request.server_state = state;
	mutex_unlock(&g_request.states_mutex);
}

static inline bool server_state_is(enum server_state state)
{
	bool is;

	mutex_lock(&g_request.states_mutex);
	is = g_request.server_state == state;
	mutex_unlock(&g_request.states_mutex);
	return is;
}

static void request_cancel(void);

static int request_send(u32 command, const struct mc_uuid_t *uuid, bool is_gp,
			u32 spid)
{
	int counter = 10;
	int ret = 0;

	/* Prepare request */
	mutex_lock(&g_request.states_mutex);
	/* Wait a little for daemon to connect */
	while ((g_request.server_state == NOT_CONNECTED) && counter--) {
		mutex_unlock(&g_request.states_mutex);
		ssleep(1);
		mutex_lock(&g_request.states_mutex);
	}

	WARN_ON(g_request.client_state != IDLE);
	if (g_request.server_state != READY) {
		mutex_unlock(&g_request.states_mutex);
		if (g_request.server_state != NOT_CONNECTED) {
			mc_dev_err("invalid daemon state %d\n",
				   g_request.server_state);
			ret = -EPROTO;
			goto end;
		} else {
			mc_dev_err("daemon not connected\n");
			ret = -ENOTCONN;
			goto end;
		}
	}

	memset(&g_request.request, 0, sizeof(g_request.request));
	memset(&g_request.response, 0, sizeof(g_request.response));
	g_request.request.request_id = g_request.request_id;
	g_request.request.command = command;
	if (uuid)
		memcpy(&g_request.request.uuid, uuid, sizeof(*uuid));
	else
		memset(&g_request.request.uuid, 0, sizeof(*uuid));

	g_request.request.is_gp = is_gp;
	g_request.request.spid = spid;
	g_request.client_state = REQUEST_SENT;
	mutex_unlock(&g_request.states_mutex);

	/* Send request */
	complete(&g_request.client_complete);

	/* Wait for header */
	do {
		ret = wait_for_completion_interruptible(
						&g_request.server_complete);
		if (!ret)
			break;
		/* we may have to freeze now */
		check_freezing_ongoing();
		/* freezing happened or was canceled,
		 * let's sleep and try again
		 */
		msleep(500);
	} while (1);

	/* Server should be waiting with some data for us */
	mutex_lock(&g_request.states_mutex);
	switch (g_request.server_state) {
	case NOT_CONNECTED:
		/* Daemon gone */
		ret = -EPIPE;
		break;
	case READY:
		/* No data to come, likely an error */
		ret = -g_request.response.error_no;
		break;
	case RESPONSE_SENT:
	case DATA_SENT:
		/* Normal case, data to come */
		ret = 0;
		break;
	case REQUEST_RECEIVED:
		/* Should not happen as complete means the state changed */
		mc_dev_err("daemon is in a bad state: %d\n",
			   g_request.server_state);
		ret = -EPIPE;
		break;
	}

	mutex_unlock(&g_request.states_mutex);

end:
	if (ret)
		request_cancel();

	return ret;
}

static int request_receive(void *address, u32 size)
{
	/*
	 * At this point we have received the header and prepared some buffers
	 * to receive data that we know are coming from the server.
	 */

	/* Check server state */
	bool server_ok;

	mutex_lock(&g_request.states_mutex);
	server_ok = (g_request.server_state == RESPONSE_SENT) ||
		    (g_request.server_state == DATA_SENT);
	mutex_unlock(&g_request.states_mutex);
	if (!server_ok) {
		mc_dev_err("expected server state %d or %d, not %d\n",
			   RESPONSE_SENT, DATA_SENT, g_request.server_state);
		request_cancel();
		return -EPIPE;
	}

	/* Setup reception buffer */
	g_request.buffer = address;
	g_request.size = size;
	client_state_change(BUFFERS_READY);

	/* Unlock write of data */
	complete(&g_request.client_complete);

	/* Wait for data */
	do {
		int ret = 0;

		ret = wait_for_completion_interruptible(
					     &g_request.server_complete);
		if (!ret)
			break;
		/* We may have to freeze now */
		check_freezing_ongoing();
		/* freezing happened or was canceled,
		 * let's sleep and try again
		 */
		msleep(500);
	} while (1);

	/* Reset reception buffer */
	g_request.buffer = NULL;
	g_request.size = 0;

	/* Return to idle state */
	client_state_change(IDLE);
	return 0;
}

/* Must be called instead of request_receive() to cancel a pending request */
static void request_cancel(void)
{
	/* Unlock write of data */
	mutex_lock(&g_request.states_mutex);
	if (g_request.server_state == DATA_SENT)
		complete(&g_request.client_complete);

	/* Return to idle state */
	g_request.client_state = IDLE;
	mutex_unlock(&g_request.states_mutex);
}

static int admin_get_root_container(void *address)
{
	int ret = 0;

	/* Lock communication channel */
	channel_lock();

	/* Send request and wait for header */
	ret = request_send(MC_DRV_GET_ROOT_CONTAINER, 0, 0, 0);
	if (ret)
		goto end;

	/* Check length against max */
	if (g_request.response.length >= MAX_SO_CONT_SIZE) {
		request_cancel();
		mc_dev_err("response length exceeds maximum\n");
		ret = EREMOTEIO;
		goto end;
	}

	/* Get data */
	ret = request_receive(address, g_request.response.length);
	if (!ret)
		ret = g_request.response.length;

end:
	channel_unlock();
	return ret;
}

static int admin_get_sp_container(void *address, u32 spid)
{
	int ret = 0;

	/* Lock communication channel */
	channel_lock();

	/* Send request and wait for header */
	ret = request_send(MC_DRV_GET_SP_CONTAINER, 0, 0, spid);
	if (ret)
		goto end;

	/* Check length against max */
	if (g_request.response.length >= MAX_SO_CONT_SIZE) {
		request_cancel();
		mc_dev_err("response length exceeds maximum\n");
		ret = EREMOTEIO;
		goto end;
	}

	/* Get data */
	ret = request_receive(address, g_request.response.length);
	if (!ret)
		ret = g_request.response.length;

end:
	channel_unlock();
	return ret;
}

static int admin_get_trustlet_container(void *address,
					const struct mc_uuid_t *uuid, u32 spid)
{
	int ret = 0;

	/* Lock communication channel */
	channel_lock();

	/* Send request and wait for header */
	ret = request_send(MC_DRV_GET_TRUSTLET_CONTAINER, uuid, 0, spid);
	if (ret)
		goto end;

	/* Check length against max */
	if (g_request.response.length >= MAX_SO_CONT_SIZE) {
		request_cancel();
		mc_dev_err("response length exceeds maximum\n");
		ret = EREMOTEIO;
		goto end;
	}

	/* Get data */
	ret = request_receive(address, g_request.response.length);
	if (!ret)
		ret = g_request.response.length;

end:
	channel_unlock();
	return ret;
}

static struct tee_object *admin_get_trustlet(const struct mc_uuid_t *uuid,
					     bool is_gp, u32 *spid)
{
	struct tee_object *obj = NULL;
	bool is_sp_tl;
	int ret = 0;

	/* Lock communication channel */
	channel_lock();

	/* Send request and wait for header */
	ret = request_send(MC_DRV_GET_TRUSTLET, uuid, is_gp, 0);
	if (ret)
		goto end;

	/* Allocate memory */
	is_sp_tl = g_request.response.service_type == SERVICE_TYPE_SP_TRUSTLET;
	obj = tee_object_alloc(is_sp_tl, g_request.response.length);
	if (!obj) {
		request_cancel();
		ret = -ENOMEM;
		goto end;
	}

	/* Get data */
	ret = request_receive(&obj->data[obj->header_length], obj->length);
	*spid = g_request.response.spid;

end:
	channel_unlock();
	if (ret)
		return ERR_PTR(ret);

	return obj;
}

static void mc_admin_sendcrashdump(void)
{
	int ret = 0;

	/* Lock communication channel */
	channel_lock();

	/* Send request and wait for header */
	ret = request_send(MC_DRV_SIGNAL_CRASH, NULL, false, 0);
	if (ret)
		goto end;

	/* Done */
	request_cancel();

end:
	channel_unlock();
}

static int tee_object_make(u32 spid, struct tee_object *obj)
{
	struct mc_blob_len_info *l_info = (struct mc_blob_len_info *)obj->data;
	u8 *address = &obj->data[obj->header_length + obj->length];
	struct mclf_header_v2 *thdr;
	int ret;

	/* Get root container */
	ret = admin_get_root_container(address);
	if (ret < 0)
		goto err;

	l_info->root_size = ret;
	address += ret;

	/* Get SP container */
	ret = admin_get_sp_container(address, spid);
	if (ret < 0)
		goto err;

	l_info->sp_size = ret;
	address += ret;

	/* Get trustlet container */
	thdr = (struct mclf_header_v2 *)&obj->data[obj->header_length];
	ret = admin_get_trustlet_container(address, &thdr->uuid, spid);
	if (ret < 0)
		goto err;

	l_info->ta_size = ret;
	address += ret;

	/* Setup lengths information */
	l_info->magic = MC_TLBLOBLEN_MAGIC;
	obj->length += sizeof(*l_info);
	obj->length += l_info->root_size + l_info->sp_size + l_info->ta_size;
	ret = 0;

err:
	return ret;
}

struct tee_object *tee_object_read(u32 spid, uintptr_t address, size_t length)
{
	char __user *addr = (char __user *)address;
	struct tee_object *obj;
	u8 *data;
	struct mclf_header_v2 thdr;
	int ret;

	/* Check length */
	if (length < sizeof(thdr)) {
		mc_dev_err("buffer shorter than header size\n");
		return ERR_PTR(-EFAULT);
	}

	/* Read header */
	if (copy_from_user(&thdr, addr, sizeof(thdr))) {
		mc_dev_err("header: copy_from_user failed\n");
		return ERR_PTR(-EFAULT);
	}

	/* Allocate memory */
	obj = tee_object_alloc(thdr.service_type == SERVICE_TYPE_SP_TRUSTLET,
			       length);
	if (!obj)
		return ERR_PTR(-ENOMEM);

	/* Copy header */
	data = &obj->data[obj->header_length];
	memcpy(data, &thdr, sizeof(thdr));
	/* Copy the rest of the data */
	data += sizeof(thdr);
	if (copy_from_user(data, &addr[sizeof(thdr)], length - sizeof(thdr))) {
		mc_dev_err("data: copy_from_user failed\n");
		vfree(obj);
		return ERR_PTR(-EFAULT);
	}

	if (obj->header_length) {
		ret = tee_object_make(spid, obj);
		if (ret) {
			vfree(obj);
			return ERR_PTR(ret);
		}
	}

	return obj;
}

struct tee_object *tee_object_select(const struct mc_uuid_t *uuid)
{
	struct tee_object *obj;
	struct mclf_header_v2 *thdr;

	obj = tee_object_alloc(false, sizeof(*thdr));
	if (!obj)
		return ERR_PTR(-ENOMEM);

	thdr = (struct mclf_header_v2 *)&obj->data[obj->header_length];
	memcpy(&thdr->uuid, uuid, sizeof(thdr->uuid));
	return obj;
}

struct tee_object *tee_object_get(const struct mc_uuid_t *uuid, bool is_gp)
{
	struct tee_object *obj;
	u32 spid = 0;

	/* admin_get_trustlet creates the right object based on service type */
	obj = admin_get_trustlet(uuid, is_gp, &spid);
	if (IS_ERR(obj))
		return obj;

	/* SP trustlet: create full secure object with all containers */
	if (obj->header_length) {
		int ret;

		/* Do not return EINVAL in this case as SPID was not found */
		if (!spid) {
			vfree(obj);
			return ERR_PTR(-ENOENT);
		}

		ret = tee_object_make(spid, obj);
		if (ret) {
			vfree(obj);
			return ERR_PTR(ret);
		}
	}

	return obj;
}

static inline int load_driver(struct tee_client *client,
			      struct mc_admin_load_info *info)
{
	struct tee_object *obj;
	struct mclf_header_v2 *thdr;
	struct mc_identity identity = {
		.login_type = LOGIN_PUBLIC,
	};
	uintptr_t dci = 0;
	u32 dci_len = 0;
	u32 sid;
	int ret;

	obj = tee_object_read(info->spid, info->address, info->length);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	thdr = (struct mclf_header_v2 *)&obj->data[obj->header_length];
	if (!(thdr->flags & MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE)) {
		/*
		 * The driver requires a DCI, although we won't be able to use
		 * it to communicate.
		 */
		dci_len = PAGE_SIZE;
		ret = client_cbuf_create(client, dci_len, &dci, NULL);
		if (ret)
			goto end;
	}

	/* Open session */
	ret = client_add_session(client, obj, dci, dci_len, &sid, false,
				 &identity);
	if (!ret)
		mc_dev_devel("driver loaded with sid %x", sid);

	/*
	 * Always 'free' the buffer (will remain as long as used), never freed
	 * otherwise
	 */
	client_cbuf_free(client, dci);
end:
	vfree(obj);
	return ret;
}

static inline int load_token(struct mc_admin_load_info *token)
{
	struct tee_mmu *mmu;
	struct mcp_buffer_map map;
	int ret;

	mmu = tee_mmu_create(current, (void *)(uintptr_t)token->address,
			     token->length);
	if (IS_ERR(mmu))
		return PTR_ERR(mmu);

	tee_mmu_buffer(mmu, &map);
	ret = mcp_load_token(token->address, &map);
	tee_mmu_delete(mmu);
	return ret;
}

static inline int load_check(struct mc_admin_load_info *info)
{
	struct tee_object *obj;
	struct tee_mmu *mmu;
	struct mcp_buffer_map map;
	int ret;

	obj = tee_object_read(info->spid, info->address, info->length);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	mmu = tee_mmu_create(NULL, obj->data, obj->length);
	if (IS_ERR(mmu))
		return PTR_ERR(mmu);

	tee_mmu_buffer(mmu, &map);
	ret = mcp_load_check(obj, &map);
	tee_mmu_delete(mmu);
	return ret;
}

static ssize_t admin_write(struct file *file, const char __user *user,
			   size_t len, loff_t *off)
{
	int ret;

	/* No offset allowed [yet] */
	if (*off) {
		mc_dev_err("offset not supported\n");
		g_request.response.error_no = EPIPE;
		ret = -ECOMM;
		goto err;
	}

	if (server_state_is(REQUEST_RECEIVED)) {
		/* Check client state */
		if (!client_state_is(REQUEST_SENT)) {
			mc_dev_err("expected client state %d, not %d\n",
				   REQUEST_SENT, g_request.client_state);
			g_request.response.error_no = EPIPE;
			ret = -EPIPE;
			goto err;
		}

		/* Receive response header */
		if (copy_from_user(&g_request.response, user,
				   sizeof(g_request.response))) {
			mc_dev_err("failed to get response from daemon\n");
			g_request.response.error_no = EPIPE;
			ret = -ECOMM;
			goto err;
		}

		/* Check request ID */
		if (g_request.request.request_id !=
						g_request.response.request_id) {
			mc_dev_err("expected id %d, not %d\n",
				   g_request.request.request_id,
				   g_request.response.request_id);
			g_request.response.error_no = EPIPE;
			ret = -EBADE;
			goto err;
		}

		/* Response header is acceptable */
		ret = sizeof(g_request.response);
		if (g_request.response.length)
			server_state_change(RESPONSE_SENT);
		else
			server_state_change(READY);

		goto end;
	} else if (server_state_is(RESPONSE_SENT)) {
		/* Server is waiting */
		server_state_change(DATA_SENT);

		/* Get data */
		ret = wait_for_completion_interruptible(
						&g_request.client_complete);

		/* Server received a signal, let see if it tries again */
		if (ret) {
			server_state_change(RESPONSE_SENT);
			return ret;
		}

		/* Check client state */
		if (!client_state_is(BUFFERS_READY)) {
			mc_dev_err("expected client state %d, not %d\n",
				   BUFFERS_READY, g_request.client_state);
			g_request.response.error_no = EPIPE;
			ret = -EPIPE;
			goto err;
		}

		/* We do not deal with several writes */
		if (len != g_request.size)
			len = g_request.size;

		ret = copy_from_user(g_request.buffer, user, len);
		if (ret) {
			mc_dev_err("failed to get data from daemon\n");
			g_request.response.error_no = EPIPE;
			ret = -ECOMM;
			goto err;
		}

		ret = len;
		server_state_change(READY);
		goto end;
	} else {
		ret = -ECOMM;
		goto err;
	}

err:
	server_state_change(READY);
end:
	complete(&g_request.server_complete);
	return ret;
}

static long admin_ioctl(struct file *file, unsigned int cmd,
			unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	int ret = -EINVAL;

	mc_dev_devel("%u from %s\n", _IOC_NR(cmd), current->comm);

	switch (cmd) {
	case MC_ADMIN_IO_GET_DRIVER_REQUEST: {
		/* Update TGID as it may change (when becoming a daemon) */
		if (admin_ctx.admin_tgid != current->tgid) {
			admin_ctx.admin_tgid = current->tgid;
			mc_dev_info("admin PID changed to %d\n",
				    admin_ctx.admin_tgid);
		}

		/* Block until a request is available */
		ret = wait_for_completion_interruptible(
						&g_request.client_complete);
		if (ret)
			/* Interrupted by signal */
			break;

		/* Check client state */
		if (!client_state_is(REQUEST_SENT)) {
			mc_dev_err("expected client state %d, not %d\n",
				   REQUEST_SENT, g_request.client_state);
			g_request.response.error_no = EPIPE;
			complete(&g_request.server_complete);
			ret = -EPIPE;
			break;
		}

		/* Send request (the driver request mutex is held) */
		ret = copy_to_user(uarg, &g_request.request,
				   sizeof(g_request.request));
		if (ret) {
			server_state_change(READY);
			complete(&g_request.server_complete);
			ret = -EPROTO;
			break;
		}

		/* Now that the daemon got it, update the request ID */
		g_request.request_id++;

		server_state_change(REQUEST_RECEIVED);
		break;
	}
	case MC_ADMIN_IO_GET_INFO: {
		struct mc_admin_driver_info info;

		info.drv_version = MC_VERSION(MCDRVMODULEAPI_VERSION_MAJOR,
					      MCDRVMODULEAPI_VERSION_MINOR);
		info.initial_cmd_id = g_request.request_id;
		ret = copy_to_user(uarg, &info, sizeof(info));
		break;
	}
	case MC_ADMIN_IO_LOAD_DRIVER: {
		struct tee_client *client = file->private_data;
		struct mc_admin_load_info info;

		if (copy_from_user(&info, uarg, sizeof(info))) {
			ret = -EFAULT;
			break;
		}

		/* Make sure we have a local client */
		if (!client) {
			client = client_create(true);
			/* Store client for future use/close */
			file->private_data = client;
		}

		if (!client) {
			ret = -ENOMEM;
			break;
		}

		ret = load_driver(client, &info);
		break;
	}
	case MC_ADMIN_IO_LOAD_TOKEN: {
		struct mc_admin_load_info info;

		if (copy_from_user(&info, uarg, sizeof(info))) {
			ret = -EFAULT;
			break;
		}

		ret = load_token(&info);
		break;
	}
	case MC_ADMIN_IO_LOAD_CHECK: {
		struct mc_admin_load_info info;

		if (copy_from_user(&info, uarg, sizeof(info))) {
			ret = -EFAULT;
			break;
		}

		ret = load_check(&info);
		break;
	}
	default:
		ret = -ENOIOCTLCMD;
	}

	return ret;
}

/*
 * mc_fd_release() - This function will be called from user space as close(...)
 * The client data are freed and the associated memory pages are unreserved.
 *
 * @inode
 * @file
 *
 * Returns 0
 */
static int admin_release(struct inode *inode, struct file *file)
{
	/* ExySp: print close process info */
	mc_dev_info("closed by PID(%d), name(%s)\n", current->pid, current->comm);

	/* Close client if any */
	if (file->private_data)
		client_close((struct tee_client *)file->private_data);

	/* Requests from driver to daemon */
	mutex_lock(&g_request.states_mutex);
	g_request.server_state = NOT_CONNECTED;
	/* A non-zero command indicates that a thread is waiting */
	if (g_request.client_state != IDLE) {
		g_request.response.error_no = ESHUTDOWN;
		complete(&g_request.server_complete);
	}

	mutex_unlock(&g_request.states_mutex);
	mc_dev_info("admin connection closed, PID %d\n", admin_ctx.admin_tgid);
	admin_ctx.admin_tgid = 0;
	/*
	 * ret is quite irrelevant here as most apps don't care about the
	 * return value from close() and it's quite difficult to recover
	 */
	return 0;
}

static int admin_open(struct inode *inode, struct file *file)
{
	int ret = 0;
	/* ExySp: print open process info */
	mc_dev_info("opened by PID(%d), name(%s)\n", current->pid, current->comm);

	/* Only one connection allowed to admin interface */
	mutex_lock(&admin_ctx.admin_tgid_mutex);
	if (admin_ctx.admin_tgid) {
		mc_dev_err("admin connection already open, PID %d\n",
			   admin_ctx.admin_tgid);
		ret = -EBUSY;
	} else {
		admin_ctx.admin_tgid = current->tgid;
	}
	mutex_unlock(&admin_ctx.admin_tgid_mutex);
	if (ret)
		return ret;

	/* Any value will do */
	g_request.request_id = 42;

	/* Setup the usual variables */
	mc_dev_devel("accept %s as TEE daemon\n", current->comm);

	/*
	 * daemon is connected so now we can safely suppose
	 * the secure world is loaded too
	 */
	if (admin_ctx.last_start_ret > 0)
		admin_ctx.last_start_ret = admin_ctx.tee_start_cb();

	/* Failed to start the TEE, either now or before */
	if (admin_ctx.last_start_ret) {
		mutex_lock(&admin_ctx.admin_tgid_mutex);
		admin_ctx.admin_tgid = 0;
		mutex_unlock(&admin_ctx.admin_tgid_mutex);
		return admin_ctx.last_start_ret;
	}

	/* Requests from driver to daemon */
	server_state_change(READY);
	mc_dev_info("admin connection open, PID %d\n", admin_ctx.admin_tgid);
	return 0;
}

/* function table structure of this device driver. */
static const struct file_operations mc_admin_fops = {
	.owner = THIS_MODULE,
	.open = admin_open,
	.release = admin_release,
	.unlocked_ioctl = admin_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = admin_ioctl,
#endif
	.write = admin_write,
};

bool mc_is_admin_tgid(pid_t tgid)
{
	bool match;

	mutex_lock(&admin_ctx.admin_tgid_mutex);
	match = admin_ctx.admin_tgid == tgid;
	mutex_unlock(&admin_ctx.admin_tgid_mutex);
	return match;
}

int mc_admin_init(struct cdev *cdev, int (*tee_start_cb)(void),
		  void (*tee_stop_cb)(void))
{
	mutex_init(&admin_ctx.admin_tgid_mutex);
	/* Requests from driver to daemon */
	mutex_init(&g_request.mutex);
	mutex_init(&g_request.states_mutex);
	init_completion(&g_request.client_complete);
	init_completion(&g_request.server_complete);
	mcp_register_crashhandler(mc_admin_sendcrashdump);
	/* Create char device */
	cdev_init(cdev, &mc_admin_fops);
	/* Register the call back for starting the secure world */
	admin_ctx.tee_start_cb = tee_start_cb;
	admin_ctx.tee_stop_cb = tee_stop_cb;
	admin_ctx.last_start_ret = 1;
	return 0;
}

void mc_admin_exit(void)
{
	if (!admin_ctx.last_start_ret)
		admin_ctx.tee_stop_cb();
}
