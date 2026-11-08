/*
 * drivers/media/platform/exynos/mfc/s5p_mfc.c
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <video/videonode.h>
#include <linux/of.h>
#include <linux/smc.h>
#include <linux/cpuidle.h>

#include "s5p_mfc_common.h"

#include "s5p_mfc_irq.h"
#include "s5p_mfc_dec.h"
#include "s5p_mfc_enc.h"

#include "s5p_mfc_ctrl.h"
#include "s5p_mfc_hwlock.h"
#include "s5p_mfc_nal_q.h"
#include "s5p_mfc_watchdog.h"
#include "s5p_mfc_opr.h"
#include "s5p_mfc_sync.h"

#include "s5p_mfc_inst.h"
#include "s5p_mfc_pm.h"
#include "s5p_mfc_reg.h"

#include "s5p_mfc_qos.h"
#include "s5p_mfc_queue.h"
#include "s5p_mfc_utils.h"
#include "s5p_mfc_buf.h"
#include "s5p_mfc_mem.h"

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
static int s5p_mfc_fw_protect(struct s5p_mfc_dev *dev, bool protect)
{
#ifdef CONFIG_SOC_EXYNOS8890
	return exynos_smc(protect ? SMC_DRM_SECBUF_PROT : SMC_DRM_SECBUF_UNPROT,
			s5p_mfc_mem_get_paddr(dev->drm_fw_buf.alloc), dev->fw.size,
			ION_EXYNOS_HEAP_ID_VIDEO_FW);
#else
	return exynos_smc(protect ? SMC_DRM_PPMP_MFCFW_PROT :
			SMC_DRM_PPMP_MFCFW_UNPROT, dev->drm_fw_buf.daddr, 0, 0);
#endif
}
#endif

#define CREATE_TRACE_POINTS
#include <trace/events/mfc.h>

#define S5P_MFC_NAME		"s5p-mfc"
#define S5P_MFC_DEC_NAME	"s5p-mfc-dec"
#define S5P_MFC_ENC_NAME	"s5p-mfc-enc"
#define S5P_MFC_DEC_DRM_NAME	"s5p-mfc-dec-secure"
#define S5P_MFC_ENC_DRM_NAME	"s5p-mfc-enc-secure"

int debug;
module_param(debug, int, S_IRUGO | S_IWUSR);

int debug_ts;
module_param(debug_ts, int, S_IRUGO | S_IWUSR);

int dbg_enable;
module_param(dbg_enable, int, S_IRUGO | S_IWUSR);

int nal_q_dump;
module_param(nal_q_dump, int, S_IRUGO | S_IWUSR);

int nal_q_disable;
module_param(nal_q_disable, int, S_IRUGO | S_IWUSR);

int nal_q_parallel_enable;
module_param(nal_q_parallel_enable, int, S_IRUGO | S_IWUSR);

struct _mfc_trace g_mfc_trace[MFC_TRACE_COUNT_MAX];
struct _mfc_trace g_mfc_trace_longterm[MFC_TRACE_COUNT_MAX];
struct _mfc_trace_logging g_mfc_trace_logging[MFC_TRACE_LOG_COUNT_MAX];
struct s5p_mfc_dev *g_mfc_dev;

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
static struct proc_dir_entry *mfc_proc_entry;

#define MFC_PROC_ROOT			"mfc"
#define MFC_PROC_INSTANCE_NUMBER	"instance_number"
#define MFC_PROC_DRM_INSTANCE_NUMBER	"drm_instance_number"
#define MFC_PROC_FW_STATUS		"fw_status"
#endif

#define DEF_DEC_SRC_FMT	9
#define DEF_DEC_DST_FMT	5

#define DEF_ENC_SRC_FMT	5
#define DEF_ENC_DST_FMT	13

void s5p_mfc_butler_worker(struct work_struct *work)
{
	struct s5p_mfc_dev *dev;

	dev = container_of(work, struct s5p_mfc_dev, butler_work);

	s5p_mfc_try_run(dev);
}

extern struct s5p_mfc_ctrls_ops decoder_ctrls_ops;
extern struct vb2_ops s5p_mfc_dec_qops;
extern struct s5p_mfc_fmt dec_formats[];

static void mfc_deinit_dec_ctx(struct s5p_mfc_ctx *ctx)
{
	s5p_mfc_cleanup_assigned_iovmm(ctx);

	s5p_mfc_delete_queue(&ctx->src_buf_queue);
	s5p_mfc_delete_queue(&ctx->dst_buf_queue);
	s5p_mfc_delete_queue(&ctx->src_buf_nal_queue);
	s5p_mfc_delete_queue(&ctx->dst_buf_nal_queue);
	s5p_mfc_delete_queue(&ctx->ref_buf_queue);
}

static int mfc_init_dec_ctx(struct s5p_mfc_ctx *ctx)
{
	struct s5p_mfc_dec *dec;
	int ret = 0;
	int i;

	dec = kzalloc(sizeof(struct s5p_mfc_dec), GFP_KERNEL);
	if (!dec) {
		mfc_err_dev("failed to allocate decoder private data\n");
		return -ENOMEM;
	}
	ctx->dec_priv = dec;

	ctx->inst_no = MFC_NO_INSTANCE_SET;

	s5p_mfc_create_queue(&ctx->src_buf_queue);
	s5p_mfc_create_queue(&ctx->dst_buf_queue);
	s5p_mfc_create_queue(&ctx->src_buf_nal_queue);
	s5p_mfc_create_queue(&ctx->dst_buf_nal_queue);
	s5p_mfc_create_queue(&ctx->ref_buf_queue);

	for (i = 0; i < MFC_MAX_BUFFERS; i++) {
		INIT_LIST_HEAD(&ctx->src_ctrls[i]);
		INIT_LIST_HEAD(&ctx->dst_ctrls[i]);
	}
	ctx->src_ctrls_avail = 0;
	ctx->dst_ctrls_avail = 0;

	ctx->capture_state = QUEUE_FREE;
	ctx->output_state = QUEUE_FREE;

	ctx->type = MFCINST_DECODER;
	ctx->c_ops = &decoder_ctrls_ops;
	ctx->src_fmt = &dec_formats[DEF_DEC_SRC_FMT];
	ctx->dst_fmt = &dec_formats[DEF_DEC_DST_FMT];

	s5p_mfc_qos_reset_framerate(ctx);

	ctx->qos_ratio = 100;
#ifdef CONFIG_MFC_USE_BUS_DEVFREQ
	INIT_LIST_HEAD(&ctx->qos_list);
#endif
	INIT_LIST_HEAD(&ctx->ts_list);

	dec->display_delay = -1;
	dec->is_interlaced = 0;
	dec->immediate_display = 0;
	dec->is_dts_mode = 0;
	dec->tiled_buf_cnt = 0;
	dec->err_reuse_flag = 0;
	dec->dec_only_release_flag = 0;

	dec->is_dynamic_dpb = 1;
	dec->dynamic_used = 0;
	dec->is_dpb_full = 0;
	s5p_mfc_cleanup_assigned_fd(ctx);
	s5p_mfc_clear_assigned_dpb(ctx);
	mutex_init(&dec->dpb_mutex);

	dec->sh_handle.fd = -1;
	dec->ref_info = kzalloc(
		(sizeof(struct dec_dpb_ref_info) * MFC_MAX_DPBS), GFP_KERNEL);
	if (!dec->ref_info) {
		mfc_err_dev("failed to allocate decoder information data\n");
		ret = -ENOMEM;
		goto fail_dec_init;
	}
	for (i = 0; i < MFC_MAX_BUFFERS; i++)
		dec->ref_info[i].dpb[0].fd[0] = MFC_INFO_INIT_FD;

	dec->profile = -1;

	/* Init videobuf2 queue for OUTPUT */
	ctx->vq_src.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	ctx->vq_src.drv_priv = ctx;
	ctx->vq_src.buf_struct_size = sizeof(struct s5p_mfc_buf);
	ctx->vq_src.io_modes = VB2_MMAP | VB2_USERPTR | VB2_DMABUF;
	ctx->vq_src.ops = &s5p_mfc_dec_qops;
	ctx->vq_src.mem_ops = s5p_mfc_mem_ops();
	ctx->vq_src.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	ret = vb2_queue_init(&ctx->vq_src);
	if (ret) {
		mfc_err_dev("Failed to initialize videobuf2 queue(output)\n");
		goto fail_dec_init;
	}
	/* Init videobuf2 queue for CAPTURE */
	ctx->vq_dst.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	ctx->vq_dst.drv_priv = ctx;
	ctx->vq_dst.buf_struct_size = sizeof(struct s5p_mfc_buf);
	ctx->vq_dst.io_modes = VB2_MMAP | VB2_USERPTR | VB2_DMABUF;
	ctx->vq_dst.ops = &s5p_mfc_dec_qops;
	ctx->vq_dst.mem_ops = s5p_mfc_mem_ops();
	ctx->vq_dst.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	ret = vb2_queue_init(&ctx->vq_dst);
	if (ret) {
		mfc_err_dev("Failed to initialize videobuf2 queue(capture)\n");
		goto fail_dec_init;
	}

	return ret;

fail_dec_init:
	mfc_deinit_dec_ctx(ctx);
	return ret;
}

extern struct s5p_mfc_ctrls_ops encoder_ctrls_ops;
extern struct vb2_ops s5p_mfc_enc_qops;
extern struct s5p_mfc_fmt enc_formats[];

static void mfc_deinit_enc_ctx(struct s5p_mfc_ctx *ctx)
{
	s5p_mfc_delete_queue(&ctx->src_buf_queue);
	s5p_mfc_delete_queue(&ctx->dst_buf_queue);
	s5p_mfc_delete_queue(&ctx->src_buf_nal_queue);
	s5p_mfc_delete_queue(&ctx->dst_buf_nal_queue);
	s5p_mfc_delete_queue(&ctx->ref_buf_queue);
}

static int mfc_init_enc_ctx(struct s5p_mfc_ctx *ctx)
{
	struct s5p_mfc_enc *enc;
	struct s5p_mfc_enc_params *p;
	int ret = 0;
	int i;

	enc = kzalloc(sizeof(struct s5p_mfc_enc), GFP_KERNEL);
	if (!enc) {
		mfc_err_dev("failed to allocate encoder private data\n");
		return -ENOMEM;
	}
	ctx->enc_priv = enc;

	ctx->inst_no = MFC_NO_INSTANCE_SET;

	s5p_mfc_create_queue(&ctx->src_buf_queue);
	s5p_mfc_create_queue(&ctx->dst_buf_queue);
	s5p_mfc_create_queue(&ctx->src_buf_nal_queue);
	s5p_mfc_create_queue(&ctx->dst_buf_nal_queue);
	s5p_mfc_create_queue(&ctx->ref_buf_queue);

	for (i = 0; i < MFC_MAX_BUFFERS; i++) {
		INIT_LIST_HEAD(&ctx->src_ctrls[i]);
		INIT_LIST_HEAD(&ctx->dst_ctrls[i]);
	}
	ctx->src_ctrls_avail = 0;
	ctx->dst_ctrls_avail = 0;

	ctx->type = MFCINST_ENCODER;
	ctx->c_ops = &encoder_ctrls_ops;
	ctx->src_fmt = &enc_formats[DEF_ENC_SRC_FMT];
	ctx->dst_fmt = &enc_formats[DEF_ENC_DST_FMT];

	s5p_mfc_qos_reset_framerate(ctx);

	ctx->qos_ratio = 100;

	/* disable IVF header by default (VP8, VP9) */
	p = &enc->params;
	p->ivf_header_disable = 1;

#ifdef CONFIG_MFC_USE_BUS_DEVFREQ
	INIT_LIST_HEAD(&ctx->qos_list);
#endif
	INIT_LIST_HEAD(&ctx->ts_list);

	enc->sh_handle_svc.fd = -1;
	enc->sh_handle_roi.fd = -1;

	/* Init videobuf2 queue for OUTPUT */
	ctx->vq_src.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	ctx->vq_src.drv_priv = ctx;
	ctx->vq_src.buf_struct_size = sizeof(struct s5p_mfc_buf);
	ctx->vq_src.io_modes = VB2_MMAP | VB2_USERPTR | VB2_DMABUF;
	ctx->vq_src.ops = &s5p_mfc_enc_qops;
	ctx->vq_src.mem_ops = s5p_mfc_mem_ops();
	ctx->vq_src.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	ret = vb2_queue_init(&ctx->vq_src);
	if (ret) {
		mfc_err_dev("Failed to initialize videobuf2 queue(output)\n");
		goto fail_enc_init;
	}

	/* Init videobuf2 queue for CAPTURE */
	ctx->vq_dst.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	ctx->vq_dst.drv_priv = ctx;
	ctx->vq_dst.buf_struct_size = sizeof(struct s5p_mfc_buf);
	ctx->vq_dst.io_modes = VB2_MMAP | VB2_USERPTR | VB2_DMABUF;
	ctx->vq_dst.ops = &s5p_mfc_enc_qops;
	ctx->vq_dst.mem_ops = s5p_mfc_mem_ops();
	ctx->vq_dst.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	ret = vb2_queue_init(&ctx->vq_dst);
	if (ret) {
		mfc_err_dev("Failed to initialize videobuf2 queue(capture)\n");
		goto fail_enc_init;
	}

	return 0;

fail_enc_init:
	mfc_deinit_enc_ctx(ctx);
	return 0;
}

extern int set_hmp_family_boost(int enable);
/* Open an MFC node */
static int s5p_mfc_open(struct file *file)
{
	struct s5p_mfc_ctx *ctx = NULL;
	struct s5p_mfc_dev *dev = video_drvdata(file);
	int ret = 0;
	enum s5p_mfc_node_type node;
	struct video_device *vdev = NULL;

	mfc_debug(2, "mfc driver open called\n");

	if (!dev) {
		mfc_err_dev("no mfc device to run\n");
		goto err_no_device;
	}

	if (mutex_lock_interruptible(&dev->mfc_mutex))
		return -ERESTARTSYS;

	node = s5p_mfc_get_node_type(file);
	if (node == MFCNODE_INVALID) {
		mfc_err_dev("cannot specify node type\n");
		ret = -ENOENT;
		goto err_node_type;
	}

	dev->num_inst++;	/* It is guarded by mfc_mutex in vfd */

	/* for family boost */
	if (node == MFCNODE_ENCODER) {
		dev->num_enc++;
		mfc_debug(1, "encoder count: %d\n", dev->num_enc);
		if (dev->num_enc == 1) {
			disable_priv_cpuidle();
			mfc_debug(1, "call cpuidle_pause()\n");
			set_hmp_family_boost(1);
			mfc_debug(1, "call set_hmp_family_boost(1)\n");
		}
	}

	/* Allocate memory for context */
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		mfc_err_dev("Not enough memory.\n");
		ret = -ENOMEM;
		goto err_ctx_alloc;
	}

	switch (node) {
	case MFCNODE_DECODER:
		vdev = dev->vfd_dec;
		break;
	case MFCNODE_ENCODER:
		vdev = dev->vfd_enc;
		break;
	case MFCNODE_DECODER_DRM:
		vdev = dev->vfd_dec_drm;
		break;
	case MFCNODE_ENCODER_DRM:
		vdev = dev->vfd_enc_drm;
		break;
	default:
		mfc_err_dev("Invalid node(%d)\n", node);
		break;
	}

	if (!vdev)
		goto err_vdev;

	v4l2_fh_init(&ctx->fh, vdev);
	file->private_data = &ctx->fh;
	v4l2_fh_add(&ctx->fh);

	ctx->dev = dev;

	/* Get context number */
	ctx->num = 0;
	while (dev->ctx[ctx->num]) {
		ctx->num++;
		if (ctx->num >= MFC_NUM_CONTEXTS) {
			mfc_err_dev("Too many open contexts.\n");
			mfc_err_dev("Print information to check if there was an error or not\n");
			s5p_mfc_dump_context_info(dev);
			ret = -EBUSY;
			goto err_ctx_num;
		}
	}

	init_waitqueue_head(&ctx->cmd_wq);
	s5p_mfc_init_listable_wq_ctx(ctx);
	spin_lock_init(&ctx->buf_queue_lock);

	if (s5p_mfc_is_decoder_node(node))
		ret = mfc_init_dec_ctx(ctx);
	else
		ret = mfc_init_enc_ctx(ctx);
	if (ret)
		goto err_ctx_init;

	ret = call_cop(ctx, init_ctx_ctrls, ctx);
	if (ret) {
		mfc_err_ctx("failed in init_ctx_ctrls\n");
		goto err_ctx_ctrls;
	}

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	if (s5p_mfc_is_drm_node(node)) {
		if (dev->num_drm_inst < MFC_MAX_DRM_CTX) {
			if (ctx->raw_protect_flag || ctx->stream_protect_flag) {
				mfc_err_ctx("protect_flag(%#lx/%#lx) remained\n",
						ctx->raw_protect_flag,
						ctx->stream_protect_flag);
				ret = -EINVAL;
				goto err_drm_start;
			}
			dev->num_drm_inst++;
			ctx->is_drm = 1;

			mfc_info_ctx("DRM instance is opened [%d:%d]\n",
					dev->num_drm_inst, dev->num_inst);
		} else {
			mfc_err_ctx("Too many instance are opened for DRM\n");
			mfc_err_dev("Print information to check if there was an error or not\n");
			s5p_mfc_dump_context_info(dev);
			ret = -EINVAL;
			goto err_drm_start;
		}
	} else {
		mfc_info_ctx("NORMAL instance is opened [%d:%d]\n",
				dev->num_drm_inst, dev->num_inst);
	}
#endif

	/* Mark context as idle */
	s5p_mfc_clear_bit(ctx->num, &dev->work_bits);
	dev->ctx[ctx->num] = ctx;

	/* Load firmware if this is the first instance */
	if (dev->num_inst == 1) {
		dev->watchdog_timer.expires = jiffies +
					msecs_to_jiffies(WATCHDOG_TICK_INTERVAL);
		add_timer(&dev->watchdog_timer);

		/* Load the FW */
		if (!dev->fw.status) {
			ret = s5p_mfc_alloc_firmware(dev);
			if (ret)
				goto err_fw_alloc;
			dev->fw.status = 1;
		}

		ret = s5p_mfc_load_firmware(dev);
		if (ret)
			goto err_fw_load;

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
		trace_mfc_dcpp_start(ctx->num, 1, dev->fw.drm_status);
		if (!dev->drm_fw_buf.daddr) {
			mfc_err_ctx("DRM F/W buffer is not allocated.\n");
			dev->fw.drm_status = 0;
		} else {
			/* Request buffer protection for DRM F/W */
			ret = s5p_mfc_fw_protect(dev, true);
			if (ret != DRMDRV_OK) {
				mfc_err_ctx("failed MFC DRM F/W prot(%#x)\n", ret);
				dev->fw.drm_status = 0;
			} else {
				dev->fw.drm_status = 1;
			}
		}
#endif
		trace_mfc_dcpp_end(ctx->num, 1, dev->fw.drm_status);

		ret = s5p_mfc_alloc_common_context(dev);
		if (ret)
			goto err_context_alloc;

		if (dbg_enable)
			s5p_mfc_alloc_dbg_info_buffer(dev);

		ret = s5p_mfc_get_hwlock_dev(dev);
		if (ret < 0) {
			mfc_err_dev("Failed to get hwlock.\n");
			mfc_err_dev("dev.hwlock.dev = 0x%lx, bits = 0x%lx, owned_by_irq = %d, wl_count = %d, transfer_owner = %d\n",
			dev->hwlock.dev, dev->hwlock.bits, dev->hwlock.owned_by_irq,
			dev->hwlock.wl_count, dev->hwlock.transfer_owner);
			goto err_hw_lock;
		}

		mfc_debug(2, "power on\n");
		ret = s5p_mfc_pm_power_on(dev);
		if (ret < 0) {
			mfc_err_ctx("power on failed\n");
			goto err_pwr_enable;
		}

		dev->curr_ctx = ctx->num;
		dev->preempt_ctx = MFC_NO_INSTANCE_SET;
		dev->curr_ctx_is_drm = ctx->is_drm;

		ret = s5p_mfc_init_hw(dev);
		if (ret) {
			mfc_err_ctx("Failed to init mfc h/w\n");
			goto err_hw_init;
		}

		s5p_mfc_release_hwlock_dev(dev);

#ifdef NAL_Q_ENABLE
		dev->nal_q_handle = s5p_mfc_nal_q_create(dev);
		if (dev->nal_q_handle == NULL)
			mfc_err_dev("NAL Q: Can't create nal q\n");
#endif
	}

	trace_mfc_node_open(ctx->num, dev->num_inst, ctx->type, ctx->is_drm);
	mfc_info_ctx("MFC open completed [%d:%d] version = %d\n",
			dev->num_drm_inst, dev->num_inst, MFC_DRIVER_INFO);
	MFC_TRACE_CTX_LT("[INFO] %s %s opened (ctx:%d, total:%d)\n", ctx->is_drm ? "DRM" : "Normal",
			s5p_mfc_is_decoder_node(node) ? "DEC" : "ENC", ctx->num, dev->num_inst);
	mutex_unlock(&dev->mfc_mutex);
	return ret;

	/* Deinit when failure occured */
err_hw_init:
	s5p_mfc_pm_power_off(dev);

err_pwr_enable:
	s5p_mfc_release_hwlock_dev(dev);

err_hw_lock:
	s5p_mfc_release_common_context(dev);

err_context_alloc:
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	if (dev->fw.drm_status) {
		int smc_ret = 0;
		dev->fw.drm_status = 0;
		/* Request buffer unprotection for DRM F/W */
		smc_ret = s5p_mfc_fw_protect(dev, false);
		if (smc_ret != DRMDRV_OK)
			mfc_err_ctx("failed MFC DRM F/W unprot(%#x)\n", smc_ret);
	}
#endif

err_fw_load:
err_fw_alloc:
	del_timer_sync(&dev->watchdog_timer);
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	if (ctx->is_drm)
		dev->num_drm_inst--;

err_drm_start:
#endif
	call_cop(ctx, cleanup_ctx_ctrls, ctx);

err_ctx_ctrls:
	if (s5p_mfc_is_decoder_node(node)) {
		kfree(ctx->dec_priv->ref_info);
		kfree(ctx->dec_priv);
	} else {
		kfree(ctx->enc_priv);
	}

err_ctx_init:
	dev->ctx[ctx->num] = 0;

err_ctx_num:
	v4l2_fh_del(&ctx->fh);
	v4l2_fh_exit(&ctx->fh);
err_vdev:
	kfree(ctx);

err_ctx_alloc:
	dev->num_inst--;
	if (node == MFCNODE_ENCODER) {
		dev->num_enc--;
		mfc_debug(1, "encoder count: %c\n", dev->num_enc);
		if (dev->num_enc == 0) {
			set_hmp_family_boost(0);
			mfc_debug(1, "call set_hmp_family_boost(0)\n");
			enable_priv_cpuidle();
			mfc_debug(1, "call cpuidle_resume()\n");
		}
	}

err_node_type:
	mfc_info_dev("MFC driver open is failed [%d:%d]\n",
			dev->num_drm_inst, dev->num_inst);
	mutex_unlock(&dev->mfc_mutex);

err_no_device:

	return ret;
}

/* Release MFC context */
static int s5p_mfc_release(struct file *file)
{
	struct s5p_mfc_ctx *ctx = fh_to_mfc_ctx(file->private_data);
	struct s5p_mfc_dev *dev = ctx->dev;
	struct s5p_mfc_dec *dec = NULL;
	struct s5p_mfc_enc *enc = NULL;
	int ret = 0;

	mutex_lock(&dev->mfc_mutex);

	mfc_info_ctx("MFC driver release is called [%d:%d], is_drm(%d)\n",
			dev->num_drm_inst, dev->num_inst, ctx->is_drm);

	MFC_TRACE_CTX_LT("[INFO] release is called (ctx:%d, total:%d)\n", ctx->num, dev->num_inst);

	s5p_mfc_clear_bit(ctx->num, &dev->work_bits);

	/* If a H/W operation is in progress, wait for it complete */
	if (need_to_wait_nal_abort(ctx)) {
		if (s5p_mfc_wait_for_done_ctx(ctx, S5P_FIMV_R2H_CMD_NAL_ABORT_RET)) {
			mfc_err_ctx("Failed to wait nal abort.\n");
			s5p_mfc_cleanup_work_bit_and_try_run(ctx);
		}
	}
	ret = s5p_mfc_get_hwlock_ctx(ctx);
	if (ret < 0) {
		mfc_err_dev("Failed to get hwlock.\n");
		MFC_TRACE_CTX_LT("[ERR][Release] failed to get hwlock (shutdown: %d)\n", dev->shutdown);
		mutex_unlock(&dev->mfc_mutex);
		return -EBUSY;
	}

	if (call_cop(ctx, cleanup_ctx_ctrls, ctx) < 0)
		mfc_err_ctx("failed in cleanup_ctx_ctrl\n");

	v4l2_fh_del(&ctx->fh);
	v4l2_fh_exit(&ctx->fh);

	/* Mark context as idle */
	s5p_mfc_clear_bit(ctx->num, &dev->work_bits);

	/* If instance was initialised then
	 * return instance and free reosurces */
	if (!atomic_read(&dev->watchdog_run) &&
		(ctx->inst_no != MFC_NO_INSTANCE_SET)) {
		s5p_mfc_clean_ctx_int_flags(ctx);
		s5p_mfc_change_state(ctx, MFCINST_RETURN_INST);
		s5p_mfc_set_bit(ctx->num, &dev->work_bits);

		/* To issue the command 'CLOSE_INSTANCE' */
		ret = s5p_mfc_just_run(dev, ctx->num);
		if (ret) {
			mfc_err_ctx("failed to run MFC, state: %d\n", ctx->state);
			MFC_TRACE_CTX_LT("[ERR][Release] failed to run MFC, state: %d\n", ctx->state);
			ret = -EIO;
			goto err_release_try;
		}

		/* Wait until instance is returned or timeout occured */
		if (s5p_mfc_wait_for_done_ctx(ctx, S5P_FIMV_R2H_CMD_CLOSE_INSTANCE_RET) == 1) {
			mfc_err_ctx("failed to wait CLOSE_INSTANCE\n");

			if (s5p_mfc_wait_for_done_ctx(ctx,
				S5P_FIMV_R2H_CMD_CLOSE_INSTANCE_RET)) {
				mfc_err_ctx("waited once more but failed to wait CLOSE_INSTANCE\n");
				dev->logging_data->cause |= (1 << MFC_CAUSE_FAIL_CLOSE_INST);
				s5p_mfc_dump_info_and_stop_hw(dev);
			}
		}
		ctx->inst_no = MFC_NO_INSTANCE_SET;
	}

	if (ctx->is_drm)
		dev->num_drm_inst--;
	dev->num_inst--;

	/* for family boost */
	if (ctx->type == MFCINST_ENCODER && !ctx->is_drm) {
		dev->num_enc--;
		mfc_debug(1, "encoder count: %c\n", dev->num_enc);
		if (dev->num_enc == 0) {
			set_hmp_family_boost(0);
			mfc_debug(1, "call set_hmp_family_boost(0)\n");
			enable_priv_cpuidle();
			mfc_debug(1, "call cpuidle_resume()\n");
		}
	}

	if (dev->num_inst == 0) {
		s5p_mfc_deinit_hw(dev);
		del_timer_sync(&dev->watchdog_timer);

		flush_workqueue(dev->butler_wq);

		mfc_debug(2, "power off\n");
		s5p_mfc_pm_power_off(dev);

		if (dbg_enable)
			s5p_mfc_release_dbg_info_buffer(dev);

		s5p_mfc_release_common_context(dev);

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
		if (dev->fw.drm_status) {
			dev->fw.drm_status = 0;
			/* Request buffer unprotection for DRM F/W */
			ret = s5p_mfc_fw_protect(dev, false);
			if (ret != DRMDRV_OK)
				mfc_err_ctx("failed MFC DRM F/W unprot(%#x)\n", ret);
		}
#endif

#ifdef NAL_Q_ENABLE
		if (dev->nal_q_handle)
			s5p_mfc_nal_q_destroy(dev, dev->nal_q_handle);
#endif
	}

	s5p_mfc_qos_off(ctx);

	s5p_mfc_release_codec_buffers(ctx);
	s5p_mfc_release_instance_context(ctx);

	s5p_mfc_release_hwlock_ctx(ctx);

	/* Free resources */
	vb2_queue_release(&ctx->vq_src);
	vb2_queue_release(&ctx->vq_dst);

	if (ctx->type == MFCINST_DECODER) {
		dec = ctx->dec_priv;
		mfc_deinit_dec_ctx(ctx);
		s5p_mfc_mem_cleanup_user_shared_handle(ctx, &dec->sh_handle);
		kfree(ctx->dec_priv->ref_info);
		kfree(ctx->dec_priv);
	} else if (ctx->type == MFCINST_ENCODER) {
		enc = ctx->enc_priv;
		mfc_deinit_enc_ctx(ctx);
		s5p_mfc_mem_cleanup_user_shared_handle(ctx, &enc->sh_handle_svc);
		s5p_mfc_mem_cleanup_user_shared_handle(ctx, &enc->sh_handle_roi);
		s5p_mfc_release_enc_roi_buffer(ctx);
		kfree(ctx->enc_priv);
	}

	s5p_mfc_destroy_listable_wq_ctx(ctx);

	trace_mfc_node_close(ctx->num, dev->num_inst, ctx->type, ctx->is_drm);

	MFC_TRACE_CTX_LT("[INFO] Release finished (ctx:%d, total:%d)\n", ctx->num, dev->num_inst);

	dev->ctx[ctx->num] = 0;
	kfree(ctx);

	mfc_info_dev("mfc driver release finished [%d:%d]\n", dev->num_drm_inst, dev->num_inst);

	if (s5p_mfc_is_work_to_do(dev))
		queue_work(dev->butler_wq, &dev->butler_work);

	mutex_unlock(&dev->mfc_mutex);
	return ret;

err_release_try:
	s5p_mfc_release_hwlock_ctx(ctx);
	s5p_mfc_cleanup_work_bit_and_try_run(ctx);
	mutex_unlock(&dev->mfc_mutex);
	return ret;
}

/* Poll */
static unsigned int s5p_mfc_poll(struct file *file,
				 struct poll_table_struct *wait)
{
	struct s5p_mfc_ctx *ctx = fh_to_mfc_ctx(file->private_data);
	unsigned int ret = 0;
	enum s5p_mfc_node_type node_type;

	node_type = s5p_mfc_get_node_type(file);

	if (s5p_mfc_is_decoder_node(node_type))
		ret = vb2_poll(&ctx->vq_src, file, wait);
	else
		ret = vb2_poll(&ctx->vq_dst, file, wait);

	return ret;
}

/* Mmap */
static int s5p_mfc_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct s5p_mfc_ctx *ctx = fh_to_mfc_ctx(file->private_data);
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	int ret;

	mfc_debug_enter();

	if (offset < DST_QUEUE_OFF_BASE) {
		mfc_debug(2, "mmaping source.\n");
		ret = vb2_mmap(&ctx->vq_src, vma);
	} else {		/* capture */
		mfc_debug(2, "mmaping destination.\n");
		vma->vm_pgoff -= (DST_QUEUE_OFF_BASE >> PAGE_SHIFT);
		ret = vb2_mmap(&ctx->vq_dst, vma);
	}
	mfc_debug_leave();
	return ret;
}

/* v4l2 ops */
static const struct v4l2_file_operations s5p_mfc_fops = {
	.owner = THIS_MODULE,
	.open = s5p_mfc_open,
	.release = s5p_mfc_release,
	.poll = s5p_mfc_poll,
	.unlocked_ioctl = video_ioctl2,
	.mmap = s5p_mfc_mmap,
};

/* videodec structure */
static struct video_device s5p_mfc_dec_videodev = {
	.name = S5P_MFC_DEC_NAME,
	.fops = &s5p_mfc_fops,
	.minor = -1,
	.release = video_device_release,
};

static struct video_device s5p_mfc_enc_videodev = {
	.name = S5P_MFC_ENC_NAME,
	.fops = &s5p_mfc_fops,
	.minor = -1,
	.release = video_device_release,
};

static struct video_device s5p_mfc_dec_drm_videodev = {
	.name = S5P_MFC_DEC_DRM_NAME,
	.fops = &s5p_mfc_fops,
	.minor = -1,
	.release = video_device_release,
};

static struct video_device s5p_mfc_enc_drm_videodev = {
	.name = S5P_MFC_ENC_DRM_NAME,
	.fops = &s5p_mfc_fops,
	.minor = -1,
	.release = video_device_release,
};

#ifdef CONFIG_MFC_USE_BUS_DEVFREQ
static int mfc_parse_mfc_qos_platdata(struct device_node *np, char *node_name,
	struct s5p_mfc_qos *qosdata)
{
	int ret = 0;
	struct device_node *np_qos;

	np_qos = of_find_node_by_name(np, node_name);
	if (!np_qos) {
		pr_err("%s: could not find mfc_qos_platdata node\n",
			node_name);
		return -EINVAL;
	}

	of_property_read_u32(np_qos, "thrd_mb", &qosdata->threshold_mb);
	of_property_read_u32(np_qos, "freq_int", &qosdata->freq_int);
	of_property_read_u32(np_qos, "freq_mif", &qosdata->freq_mif);
	of_property_read_u32(np_qos, "freq_cpu", &qosdata->freq_cpu);
	of_property_read_u32(np_qos, "freq_kfc", &qosdata->freq_kfc);
	of_property_read_u32(np_qos, "mo_value", &qosdata->mo_value);
	of_property_read_u32(np_qos, "mo_10bit_value", &qosdata->mo_10bit_value);
	of_property_read_u32(np_qos, "time_fw", &qosdata->time_fw);

	return ret;
}
#endif

int s5p_mfc_sysmmu_fault_handler(struct iommu_domain *iodmn, struct device *device,
		unsigned long addr, int id, void *param)
{
	struct s5p_mfc_dev *dev;
	bool mapping;

	dev = platform_get_drvdata(to_platform_device(device));
	dev->logging_data->mmu_fi = (struct _sysmmu_fi *)param;

	mapping = iovmm_address_verifier(device, addr, dev->logging_data->mmu_fi);
	if (!mapping)
		dev->logging_data->cause |= (1 << MFC_CAUSE_NO_MAPPING_AREA);
	mfc_info_dev("There %s mapping\n", mapping ? "is" : "isn't");

	if (MFC_MMU0_READL(MFC_MMU_INTERRUPT_STATUS)) {
		if (MFC_MMU0_READL(MFC_MMU_FAULT_TRANS_INFO) & MFC_MMU_FAULT_TRANS_INFO_RW_MASK)
			dev->logging_data->cause |= (1 << MFC_CAUSE_0WRITE_PAGE_FAULT);
		else
			dev->logging_data->cause |= (1 << MFC_CAUSE_0READ_PAGE_FAULT);
		dev->logging_data->fault_status = MFC_MMU0_READL(MFC_MMU_INTERRUPT_STATUS);
		dev->logging_data->fault_trans_info = MFC_MMU0_READL(MFC_MMU_FAULT_TRANS_INFO);
	} else if (MFC_MMU1_READL(MFC_MMU_INTERRUPT_STATUS)) {
		if (MFC_MMU1_READL(MFC_MMU_FAULT_TRANS_INFO) & MFC_MMU_FAULT_TRANS_INFO_RW_MASK)
			dev->logging_data->cause |= (1 << MFC_CAUSE_1WRITE_PAGE_FAULT);
		else
			dev->logging_data->cause |= (1 << MFC_CAUSE_1READ_PAGE_FAULT);
		dev->logging_data->fault_status = MFC_MMU1_READL(MFC_MMU_INTERRUPT_STATUS);
		dev->logging_data->fault_trans_info = MFC_MMU1_READL(MFC_MMU_FAULT_TRANS_INFO);
	} else {
		mfc_err_dev("there isn't any fault interrupt of MFC\n");
	}
	dev->logging_data->fault_addr = (unsigned int)addr;

	s5p_mfc_dump_buffer_info(dev, addr);
	s5p_mfc_dump_info_and_stop_hw(dev);

	return 0;
}

static void mfc_parse_dt(struct device_node *np, struct s5p_mfc_dev *mfc)
{
	struct s5p_mfc_platdata	*pdata = mfc->pdata;
#ifdef CONFIG_MFC_USE_BUS_DEVFREQ
	char node_name[50];
	int i;
#endif

	if (!np)
		return;

	of_property_read_u32(np, "ip_ver", &pdata->ip_ver);
	of_property_read_u32(np, "clock_rate", &pdata->clock_rate);
	of_property_read_u32(np, "min_rate", &pdata->min_rate);
#ifdef CONFIG_MFC_USE_BUS_DEVFREQ
	of_property_read_u32(np, "num_qos_steps", &pdata->num_qos_steps);
	of_property_read_u32(np, "max_mb", &pdata->max_mb);

	pdata->qos_table = devm_kzalloc(mfc->device,
			sizeof(struct s5p_mfc_qos) * pdata->num_qos_steps, GFP_KERNEL);

	for (i = 0; i < pdata->num_qos_steps; i++) {
		snprintf(node_name, sizeof(node_name), "mfc_qos_variant_%d", i);
		mfc_parse_mfc_qos_platdata(np, node_name, &pdata->qos_table[i]);
	}
#endif
}

static void *mfc_get_drv_data(struct platform_device *pdev);

/* MFC probe function */
static int s5p_mfc_probe(struct platform_device *pdev)
{
	struct s5p_mfc_dev *dev;
	struct video_device *vfd;
	struct resource *res;
	int ret = -ENOENT;
#ifdef CONFIG_MFC_USE_BUS_DEVFREQ
	int i;
#endif

	dev_dbg(&pdev->dev, "%s()\n", __func__);
	dev = devm_kzalloc(&pdev->dev, sizeof(struct s5p_mfc_dev), GFP_KERNEL);
	if (!dev) {
		dev_err(&pdev->dev, "Not enough memory for MFC device.\n");
		return -ENOMEM;
	}

	dev->device = &pdev->dev;
	dev->pdata = pdev->dev.platform_data;

	dev->variant = mfc_get_drv_data(pdev);

	if (dev->device->of_node)
		dev->id = of_alias_get_id(pdev->dev.of_node, "mfc");

	dev_dbg(&pdev->dev, "of alias get id : mfc-%d \n", dev->id);

	if (dev->id < 0 || dev->id >= dev->variant->num_entities) {
		dev_err(&pdev->dev, "Invalid platform device id: %d\n", dev->id);
		ret = -EINVAL;
		goto err_pm;

	}

	dev->pdata = devm_kzalloc(&pdev->dev, sizeof(struct s5p_mfc_platdata), GFP_KERNEL);
	if (!dev->pdata) {
		dev_err(&pdev->dev, "no memory for state\n");
		ret = -ENOMEM;
		goto err_pm;
	}

	mfc_parse_dt(dev->device->of_node, dev);

	atomic_set(&dev->trace_ref, 0);
	atomic_set(&dev->trace_ref_longterm, 0);
	atomic_set(&dev->trace_ref_log, 0);
	dev->mfc_trace = g_mfc_trace;
	dev->mfc_trace_longterm = g_mfc_trace_longterm;
	dev->mfc_trace_logging = g_mfc_trace_logging;

	s5p_mfc_pm_init(dev);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (res == NULL) {
		dev_err(&pdev->dev, "failed to get memory region resource\n");
		ret = -ENOENT;
		goto err_res_mem;
	}
	dev->mfc_mem = request_mem_region(res->start, resource_size(res),
					pdev->name);
	if (dev->mfc_mem == NULL) {
		dev_err(&pdev->dev, "failed to get memory region\n");
		ret = -ENOENT;
		goto err_req_mem;
	}
	dev->regs_base = ioremap(dev->mfc_mem->start,
				resource_size(dev->mfc_mem));
	if (dev->regs_base == NULL) {
		dev_err(&pdev->dev, "failed to ioremap address region\n");
		ret = -ENOENT;
		goto err_ioremap;
	}
	dev->sysmmu0_base = ioremap(MFC_MMU0_BASE_ADDR, MFC_MMU_SIZE);
	if (dev->sysmmu0_base == NULL) {
		dev_err(&pdev->dev, "failed to ioremap sysmmu0 address region\n");
		ret = -ENOENT;
		goto err_ioremap_mmu0;
	}
	dev->sysmmu1_base = ioremap(MFC_MMU1_BASE_ADDR, MFC_MMU_SIZE);
	if (dev->sysmmu1_base == NULL) {
		dev_err(&pdev->dev, "failed to ioremap sysmmu1 address region\n");
		ret = -ENOENT;
		goto err_ioremap_mmu1;
	}

	res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (res == NULL) {
		dev_err(&pdev->dev, "failed to get irq resource\n");
		ret = -ENOENT;
		goto err_res_irq;
	}
	dev->irq = res->start;
	ret = request_threaded_irq(dev->irq, s5p_mfc_top_half_irq, s5p_mfc_irq,
				IRQF_ONESHOT, pdev->name, dev);
	if (ret != 0) {
		dev_err(&pdev->dev, "failed to install irq (%d)\n", ret);
		goto err_req_irq;
	}

	mutex_init(&dev->mfc_mutex);

	ret = v4l2_device_register(&pdev->dev, &dev->v4l2_dev);
	if (ret)
		goto err_v4l2_dev;

	init_waitqueue_head(&dev->cmd_wq);
	s5p_mfc_init_listable_wq_dev(dev);

	/* decoder */
	vfd = video_device_alloc();
	if (!vfd) {
		v4l2_err(&dev->v4l2_dev, "Failed to allocate video device\n");
		ret = -ENOMEM;
		goto alloc_vdev_dec;
	}
	*vfd = s5p_mfc_dec_videodev;

	vfd->ioctl_ops = s5p_mfc_get_dec_v4l2_ioctl_ops();

	vfd->lock = &dev->mfc_mutex;
	vfd->v4l2_dev = &dev->v4l2_dev;
	vfd->vfl_dir = VFL_DIR_M2M;

	snprintf(vfd->name, sizeof(vfd->name), "%s%d", s5p_mfc_dec_videodev.name, dev->id);

	ret = video_register_device(vfd, VFL_TYPE_GRABBER, EXYNOS_VIDEONODE_MFC_DEC + 60 * dev->id);
	if (ret) {
		v4l2_err(&dev->v4l2_dev, "Failed to register video device\n");
		video_device_release(vfd);
		goto reg_vdev_dec;
	}
	v4l2_info(&dev->v4l2_dev, "decoder registered as /dev/video%d\n",
								vfd->num);
	dev->vfd_dec = vfd;

	video_set_drvdata(vfd, dev);

	/* encoder */
	vfd = video_device_alloc();
	if (!vfd) {
		v4l2_err(&dev->v4l2_dev, "Failed to allocate video device\n");
		ret = -ENOMEM;
		goto alloc_vdev_enc;
	}
	*vfd = s5p_mfc_enc_videodev;

	vfd->ioctl_ops = s5p_mfc_get_enc_v4l2_ioctl_ops();

	vfd->lock = &dev->mfc_mutex;
	vfd->v4l2_dev = &dev->v4l2_dev;
	vfd->vfl_dir = VFL_DIR_M2M;
	snprintf(vfd->name, sizeof(vfd->name), "%s%d", s5p_mfc_enc_videodev.name, dev->id);

	ret = video_register_device(vfd, VFL_TYPE_GRABBER, EXYNOS_VIDEONODE_MFC_ENC + 60 * dev->id);
	if (ret) {
		v4l2_err(&dev->v4l2_dev, "Failed to register video device\n");
		video_device_release(vfd);
		goto reg_vdev_enc;
	}
	v4l2_info(&dev->v4l2_dev, "encoder registered as /dev/video%d\n",
								vfd->num);
	dev->vfd_enc = vfd;

	video_set_drvdata(vfd, dev);

	/* secure decoder */
	vfd = video_device_alloc();
	if (!vfd) {
		v4l2_err(&dev->v4l2_dev, "Failed to allocate video device\n");
		ret = -ENOMEM;
		goto alloc_vdev_dec_drm;
	}
	*vfd = s5p_mfc_dec_drm_videodev;

	vfd->ioctl_ops = s5p_mfc_get_dec_v4l2_ioctl_ops();

	vfd->lock = &dev->mfc_mutex;
	vfd->v4l2_dev = &dev->v4l2_dev;
	vfd->vfl_dir = VFL_DIR_M2M;

	snprintf(vfd->name, sizeof(vfd->name), "%s%d", s5p_mfc_dec_drm_videodev.name, dev->id);

	ret = video_register_device(vfd, VFL_TYPE_GRABBER, EXYNOS_VIDEONODE_MFC_DEC_DRM + 60 * dev->id);
	if (ret) {
		v4l2_err(&dev->v4l2_dev, "Failed to register video device\n");
		video_device_release(vfd);
		goto reg_vdev_dec_drm;
	}
	v4l2_info(&dev->v4l2_dev, "secure decoder registered as /dev/video%d\n",
								vfd->num);
	dev->vfd_dec_drm = vfd;

	video_set_drvdata(vfd, dev);

	/* secure encoder */
	vfd = video_device_alloc();
	if (!vfd) {
		v4l2_err(&dev->v4l2_dev, "Failed to allocate video device\n");
		ret = -ENOMEM;
		goto alloc_vdev_enc_drm;
	}
	*vfd = s5p_mfc_enc_drm_videodev;

	vfd->ioctl_ops = s5p_mfc_get_enc_v4l2_ioctl_ops();

	vfd->lock = &dev->mfc_mutex;
	vfd->v4l2_dev = &dev->v4l2_dev;
	vfd->vfl_dir = VFL_DIR_M2M;
	snprintf(vfd->name, sizeof(vfd->name), "%s%d", s5p_mfc_enc_drm_videodev.name, dev->id);

	ret = video_register_device(vfd, VFL_TYPE_GRABBER, EXYNOS_VIDEONODE_MFC_ENC_DRM + 60 * dev->id);
	if (ret) {
		v4l2_err(&dev->v4l2_dev, "Failed to register video device\n");
		video_device_release(vfd);
		goto reg_vdev_enc_drm;
	}
	v4l2_info(&dev->v4l2_dev, "secure encoder registered as /dev/video%d\n",
								vfd->num);
	dev->vfd_enc_drm = vfd;

	video_set_drvdata(vfd, dev);
	/* end of node setting*/

	platform_set_drvdata(pdev, dev);

	s5p_mfc_init_hwlock(dev);
	s5p_mfc_create_bits(&dev->work_bits);

	dev->watchdog_wq =
		create_singlethread_workqueue("s5p_mfc/watchdog");
	if (!dev->watchdog_wq) {
		dev_err(&pdev->dev, "failed to create workqueue for watchdog\n");
		goto err_wq_watchdog;
	}
	INIT_WORK(&dev->watchdog_work, s5p_mfc_watchdog_worker);
	atomic_set(&dev->watchdog_tick_running, 0);
	atomic_set(&dev->watchdog_tick_cnt, 0);
	atomic_set(&dev->watchdog_run, 0);
	init_timer(&dev->watchdog_timer);
	dev->watchdog_timer.data = (unsigned long)dev;
	dev->watchdog_timer.function = s5p_mfc_watchdog_tick;

#ifdef CONFIG_MFC_USE_BUS_DEVFREQ
	INIT_LIST_HEAD(&dev->qos_queue);
#endif

	/* default FW alloc is added */
	dev->alloc_ctx = (struct vb2_alloc_ctx *)
		vb2_ion_create_context(&pdev->dev, SZ_4K,
			VB2ION_CTX_VMCONTIG |
			VB2ION_CTX_IOMMU |
			VB2ION_CTX_UNCACHED);
	if (IS_ERR(dev->alloc_ctx)) {
		mfc_err_dev("Couldn't prepare allocator ctx.\n");
		ret = PTR_ERR(dev->alloc_ctx);
		goto alloc_ctx_fail;
	}

	dev->butler_wq = alloc_workqueue("s5p_mfc/butler", WQ_UNBOUND
					| WQ_MEM_RECLAIM | WQ_HIGHPRI, 1);
	if (dev->butler_wq == NULL) {
		dev_err(&pdev->dev, "failed to create workqueue for butler\n");
		goto err_butler_wq;
	}
	INIT_WORK(&dev->butler_work, s5p_mfc_butler_worker);

#ifdef CONFIG_ION_EXYNOS
	dev->mfc_ion_client = exynos_ion_client_create("mfc");
	if (IS_ERR(dev->mfc_ion_client)) {
		dev_err(&pdev->dev, "failed to ion_client_create\n");
		goto err_ion_client;
	}
#endif

	dev->alloc_ctx_fw = (struct vb2_alloc_ctx *)
		vb2_ion_create_context(&pdev->dev, SZ_4K,
			VB2ION_CTX_DRM_MFCNFW | VB2ION_CTX_IOMMU);
	if (IS_ERR(dev->alloc_ctx_fw)) {
		mfc_err_dev("failed to prepare F/W allocation context\n");
		ret = PTR_ERR(dev->alloc_ctx_fw);
		goto alloc_ctx_fw_fail;
	}

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	dev->alloc_ctx_drm_fw = (struct vb2_alloc_ctx *)
		vb2_ion_create_context(&pdev->dev, SZ_4K,
			VB2ION_CTX_DRM_MFCFW | VB2ION_CTX_IOMMU);
	if (IS_ERR(dev->alloc_ctx_drm_fw)) {
		mfc_err_dev("failed to prepare F/W allocation context\n");
		ret = PTR_ERR(dev->alloc_ctx_drm_fw);
		goto alloc_ctx_drm_fw_fail;
	}
	dev->alloc_ctx_drm = (struct vb2_alloc_ctx *)
		vb2_ion_create_context(&pdev->dev,
			SZ_4K,
			VB2ION_CTX_UNCACHED | VB2ION_CTX_DRM_VIDEO | VB2ION_CTX_IOMMU);
	if (IS_ERR(dev->alloc_ctx_drm)) {
		mfc_err_dev("failed to prepare DRM allocation context\n");
		ret = PTR_ERR(dev->alloc_ctx_drm);
		goto alloc_ctx_sh_fail;
	}
#endif

#ifdef CONFIG_MFC_USE_BUS_DEVFREQ
	atomic_set(&dev->qos_req_cur, 0);

	for (i = 0; i < dev->pdata->num_qos_steps; i++) {
		mfc_info_dev("QoS table[%d] int : %d, mif : %d\n",
				i,
				dev->pdata->qos_table[i].freq_int,
				dev->pdata->qos_table[i].freq_mif);
	}
#endif

	iovmm_set_fault_handler(dev->device, s5p_mfc_sysmmu_fault_handler, NULL);

	g_mfc_dev = dev;

	vb2_ion_attach_iommu(dev->alloc_ctx);

	dev->logging_data = devm_kzalloc(&pdev->dev, sizeof(struct s5p_mfc_debug), GFP_KERNEL);
	if (!dev->logging_data) {
		dev_err(&pdev->dev, "no memory for logging data\n");
		ret = -ENOMEM;
		goto err_alloc_debug;
	}

	pr_debug("%s--\n", __func__);
	return 0;

/* Deinit MFC if probe had failed */
err_alloc_debug:
	vb2_ion_detach_iommu(dev->alloc_ctx);
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
alloc_ctx_sh_fail:
	vb2_ion_destroy_context(dev->alloc_ctx_drm_fw);
alloc_ctx_drm_fw_fail:
#endif
	vb2_ion_destroy_context(dev->alloc_ctx_fw);
alloc_ctx_fw_fail:
#ifdef CONFIG_ION_EXYNOS
	ion_client_destroy(dev->mfc_ion_client);
err_ion_client:
#endif
	destroy_workqueue(dev->butler_wq);
err_butler_wq:
	vb2_ion_destroy_context(dev->alloc_ctx);
alloc_ctx_fail:
	destroy_workqueue(dev->watchdog_wq);
err_wq_watchdog:
	video_unregister_device(dev->vfd_enc_drm);
reg_vdev_enc_drm:
alloc_vdev_enc_drm:
	video_unregister_device(dev->vfd_dec_drm);
reg_vdev_dec_drm:
alloc_vdev_dec_drm:
	video_unregister_device(dev->vfd_enc);
reg_vdev_enc:
alloc_vdev_enc:
	video_unregister_device(dev->vfd_dec);
reg_vdev_dec:
alloc_vdev_dec:
	v4l2_device_unregister(&dev->v4l2_dev);
err_v4l2_dev:
	mutex_destroy(&dev->mfc_mutex);
	free_irq(dev->irq, dev);
err_req_irq:
err_res_irq:
	iounmap(dev->sysmmu1_base);
err_ioremap_mmu1:
	iounmap(dev->sysmmu0_base);
err_ioremap_mmu0:
	iounmap(dev->regs_base);
err_ioremap:
	release_mem_region(dev->mfc_mem->start, resource_size(dev->mfc_mem));
err_req_mem:
err_res_mem:
	s5p_mfc_pm_final(dev);
err_pm:
	return ret;
}

/* Remove the driver */
static int s5p_mfc_remove(struct platform_device *pdev)
{
	struct s5p_mfc_dev *dev = platform_get_drvdata(pdev);

	dev_dbg(&pdev->dev, "%s++\n", __func__);
	v4l2_info(&dev->v4l2_dev, "Removing %s\n", pdev->name);
	del_timer_sync(&dev->watchdog_timer);
	flush_workqueue(dev->watchdog_wq);
	destroy_workqueue(dev->watchdog_wq);
	flush_workqueue(dev->butler_wq);
	destroy_workqueue(dev->butler_wq);
	video_unregister_device(dev->vfd_enc);
	video_unregister_device(dev->vfd_dec);
	v4l2_device_unregister(&dev->v4l2_dev);
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	remove_proc_entry(MFC_PROC_FW_STATUS, mfc_proc_entry);
	remove_proc_entry(MFC_PROC_DRM_INSTANCE_NUMBER, mfc_proc_entry);
	remove_proc_entry(MFC_PROC_INSTANCE_NUMBER, mfc_proc_entry);
	remove_proc_entry(MFC_PROC_ROOT, NULL);
	vb2_ion_destroy_context(dev->alloc_ctx_drm);
	vb2_ion_destroy_context(dev->alloc_ctx_drm_fw);
#endif
	s5p_mfc_destroy_listable_wq_dev(dev);
	vb2_ion_destroy_context(dev->alloc_ctx_fw);
#ifdef CONFIG_ION_EXYNOS
	ion_client_destroy(dev->mfc_ion_client);
#endif
	mfc_debug(2, "Will now deinit HW\n");
	s5p_mfc_deinit_hw(dev);
	vb2_ion_destroy_context(dev->alloc_ctx);
	vb2_ion_detach_iommu(dev->alloc_ctx);
	free_irq(dev->irq, dev);
	iounmap(dev->sysmmu1_base);
	iounmap(dev->sysmmu0_base);
	iounmap(dev->regs_base);
	release_mem_region(dev->mfc_mem->start, resource_size(dev->mfc_mem));
	s5p_mfc_pm_final(dev);
	kfree(dev);
	dev_dbg(&pdev->dev, "%s--\n", __func__);
	return 0;
}

static void s5p_mfc_shutdown(struct platform_device *pdev)
{
	struct s5p_mfc_dev *dev = platform_get_drvdata(pdev);
	int ret;

	mfc_info_dev("MFC shutdown is called\n");

	if (!s5p_mfc_pm_get_pwr_ref_cnt(dev)) {
		dev->shutdown = 1;
		mfc_info_dev("MFC is not running\n");
		return;
	}

	ret = s5p_mfc_get_hwlock_dev(dev);
	if (ret < 0)
		mfc_err_dev("Failed to get hwlock.\n");

	if (!dev->shutdown) {
		s5p_mfc_risc_off(dev);
		dev->shutdown = 1;
		s5p_mfc_clear_all_bits(&dev->work_bits);
		vb2_ion_detach_iommu(dev->alloc_ctx);
	}
	s5p_mfc_release_hwlock_dev(dev);
	mfc_info_dev("MFC shutdown completed\n");
}

#ifdef CONFIG_PM_SLEEP
static int s5p_mfc_suspend(struct device *dev)
{
	struct s5p_mfc_dev *m_dev = platform_get_drvdata(to_platform_device(dev));
	int ret;

	if (!m_dev) {
		mfc_err_dev("no mfc device to run\n");
		return -EINVAL;
	}

	if (m_dev->num_inst == 0)
		return 0;

	ret = s5p_mfc_sleep(m_dev);

	return ret;
}

static int s5p_mfc_resume(struct device *dev)
{
	struct s5p_mfc_dev *m_dev = platform_get_drvdata(to_platform_device(dev));
	int ret;

	if (!m_dev) {
		mfc_err_dev("no mfc device to run\n");
		return -EINVAL;
	}

	if (m_dev->num_inst == 0)
		return 0;

	ret = s5p_mfc_wakeup(m_dev);

	return ret;
}
#endif

#ifdef CONFIG_PM
static int s5p_mfc_runtime_suspend(struct device *dev)
{
	mfc_debug(3, "mfc runtime suspend\n");

	return 0;
}

static int s5p_mfc_runtime_idle(struct device *dev)
{
	return 0;
}

static int s5p_mfc_runtime_resume(struct device *dev)
{
	mfc_debug(3, "mfc runtime resume\n");

	return 0;
}
#endif

/* Power management */
static const struct dev_pm_ops s5p_mfc_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(s5p_mfc_suspend, s5p_mfc_resume)
	SET_RUNTIME_PM_OPS(
			s5p_mfc_runtime_suspend,
			s5p_mfc_runtime_resume,
			s5p_mfc_runtime_idle
	)
};

struct s5p_mfc_buf_size_v6 mfc_buf_size_v6 = {
	.dev_ctx	= PAGE_ALIGN(0x7800),	/*  30KB */
	.h264_dec_ctx	= PAGE_ALIGN(0x200000),	/* 1.6MB */
	.other_dec_ctx	= PAGE_ALIGN(0x7800),	/*  30KB */
	.h264_enc_ctx	= PAGE_ALIGN(0x19000),	/* 100KB */
	.hevc_enc_ctx	= PAGE_ALIGN(0xA000),	/*  40KB */
	.other_enc_ctx	= PAGE_ALIGN(0x6400),	/*  25KB */
	.shared_buf	= PAGE_ALIGN(0x2000),	/*   8KB */
	.dbg_info_buf	= PAGE_ALIGN(0x1000),	/* 4KB for DEBUG INFO */
};

struct s5p_mfc_buf_size buf_size_v6 = {
	.firmware_code	= PAGE_ALIGN(0x100000),	/* 1MB */
	.cpb_buf	= PAGE_ALIGN(0x300000),	/* 3MB */
	.buf		= &mfc_buf_size_v6,
};

struct s5p_mfc_buf_align mfc_buf_align_v6 = {
	.mfc_base_align = 0,
};


static struct s5p_mfc_variant mfc_drvdata_v6 = {
	.buf_size = &buf_size_v6,
	.buf_align = &mfc_buf_align_v6,
	.num_entities = 2,
};

static const struct of_device_id exynos_mfc_match[] = {
	{
		.compatible = "samsung,mfc-v6",
		.data = &mfc_drvdata_v6,
	},
	{},
};
MODULE_DEVICE_TABLE(of, exynos_mfc_match);

static void *mfc_get_drv_data(struct platform_device *pdev)
{
	struct s5p_mfc_variant *driver_data = NULL;

	if (pdev->dev.of_node) {
		const struct of_device_id *match;
		match = of_match_node(of_match_ptr(exynos_mfc_match),
				pdev->dev.of_node);
		if (match)
			driver_data = (struct s5p_mfc_variant *)match->data;
	} else {
		driver_data = (struct s5p_mfc_variant *)
			platform_get_device_id(pdev)->driver_data;
	}
	return driver_data;
}

static struct platform_driver s5p_mfc_driver = {
	.probe		= s5p_mfc_probe,
	.remove		= s5p_mfc_remove,
	.shutdown	= s5p_mfc_shutdown,
	.driver	= {
		.name	= S5P_MFC_NAME,
		.owner	= THIS_MODULE,
		.pm	= &s5p_mfc_pm_ops,
		.of_match_table = exynos_mfc_match,
		.suppress_bind_attrs = true,
	},
};

module_platform_driver(s5p_mfc_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kamil Debski <k.debski@samsung.com>");
