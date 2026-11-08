/*
 * drivers/media/platform/exynos/mfc/s5p_mfc_buf.c
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/smc.h>
#include <linux/firmware.h>
#include <trace/events/mfc.h>

#include "s5p_mfc_buf.h"

#include "s5p_mfc_mem.h"

static int mfc_alloc_common_context(struct s5p_mfc_dev *dev,
					enum mfc_buf_usage_type buf_type)
{
	struct s5p_mfc_special_buf *ctx_buf;
	int firmware_size;
	unsigned long fw_daddr;

	mfc_debug_enter();
	if (!dev) {
		mfc_err_dev("no mfc device to run\n");
		return -EINVAL;
	}

	ctx_buf = &dev->common_ctx_buf;
	fw_daddr = dev->fw_buf.daddr;

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	if (buf_type == MFCBUF_DRM) {
		ctx_buf = &dev->drm_common_ctx_buf;
		fw_daddr = dev->drm_fw_buf.daddr;
	}
#endif

	firmware_size = dev->variant->buf_size->firmware_code;

	ctx_buf->alloc = NULL;
	ctx_buf->vaddr = NULL;
	ctx_buf->daddr = fw_daddr + firmware_size;

	mfc_debug_leave();

	return 0;
}

/* Wrapper : allocate context buffers for SYS_INIT */
int s5p_mfc_alloc_common_context(struct s5p_mfc_dev *dev)
{
	int ret = 0;

	ret = mfc_alloc_common_context(dev, MFCBUF_NORMAL);
	if (ret)
		return ret;
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	if (dev->fw.drm_status) {
		ret = mfc_alloc_common_context(dev, MFCBUF_DRM);
		if (ret)
			return ret;
	}
#endif

	return ret;
}

/* Release context buffers for SYS_INIT */
static void mfc_release_common_context(struct s5p_mfc_dev *dev,
					enum mfc_buf_usage_type buf_type)
{
	struct s5p_mfc_special_buf *ctx_buf;

	if (!dev) {
		mfc_err_dev("no mfc device to run\n");
		return;
	}

	ctx_buf = &dev->common_ctx_buf;
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	if (buf_type == MFCBUF_DRM)
		ctx_buf = &dev->drm_common_ctx_buf;
#endif

	if (ctx_buf->vaddr) {
		s5p_mfc_mem_free(ctx_buf->alloc);
		ctx_buf->alloc = NULL;
		ctx_buf->daddr = 0;
		ctx_buf->vaddr = NULL;
	} else {
		/* In case of using FW region for common context buffer */
		if (ctx_buf->daddr)
			ctx_buf->daddr = 0;
	}
}

/* Release context buffers for SYS_INIT */
void s5p_mfc_release_common_context(struct s5p_mfc_dev *dev)
{
	mfc_release_common_context(dev, MFCBUF_NORMAL);

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	mfc_release_common_context(dev, MFCBUF_DRM);
#endif
}

/* Allocate memory for instance data buffer */
int s5p_mfc_alloc_instance_context(struct s5p_mfc_ctx *ctx)
{
	struct s5p_mfc_dev *dev;
	struct s5p_mfc_buf_size_v6 *buf_size;
	void *alloc_ctx;

	mfc_debug_enter();
	if (!ctx) {
		mfc_err_dev("no mfc context to run\n");
		return -EINVAL;
	}
	dev = ctx->dev;
	if (!dev) {
		mfc_err_dev("no mfc device to run\n");
		return -EINVAL;
	}
	buf_size = dev->variant->buf_size->buf;
	alloc_ctx = dev->alloc_ctx;

	switch (ctx->codec_mode) {
	case S5P_FIMV_CODEC_H264_DEC:
	case S5P_FIMV_CODEC_H264_MVC_DEC:
	case S5P_FIMV_CODEC_HEVC_DEC:
		ctx->instance_ctx_buf.size = buf_size->h264_dec_ctx;
		break;
	case S5P_FIMV_CODEC_MPEG4_DEC:
	case S5P_FIMV_CODEC_H263_DEC:
	case S5P_FIMV_CODEC_VC1_RCV_DEC:
	case S5P_FIMV_CODEC_VC1_DEC:
	case S5P_FIMV_CODEC_MPEG2_DEC:
	case S5P_FIMV_CODEC_VP8_DEC:
	case S5P_FIMV_CODEC_VP9_DEC:
	case S5P_FIMV_CODEC_FIMV1_DEC:
	case S5P_FIMV_CODEC_FIMV2_DEC:
	case S5P_FIMV_CODEC_FIMV3_DEC:
	case S5P_FIMV_CODEC_FIMV4_DEC:
		ctx->instance_ctx_buf.size = buf_size->other_dec_ctx;
		break;
	case S5P_FIMV_CODEC_H264_ENC:
		ctx->instance_ctx_buf.size = buf_size->h264_enc_ctx;
		break;
	case S5P_FIMV_CODEC_HEVC_ENC:
		ctx->instance_ctx_buf.size = buf_size->hevc_enc_ctx;
		break;
	case S5P_FIMV_CODEC_MPEG4_ENC:
	case S5P_FIMV_CODEC_H263_ENC:
	case S5P_FIMV_CODEC_VP8_ENC:
	case S5P_FIMV_CODEC_VP9_ENC:
		ctx->instance_ctx_buf.size = buf_size->other_enc_ctx;
		break;
	default:
		ctx->instance_ctx_buf.size = 0;
		mfc_err_ctx("Codec type(%d) should be checked!\n", ctx->codec_mode);
		break;
	}

	if (ctx->is_drm)
		alloc_ctx = dev->alloc_ctx_drm;

	ctx->instance_ctx_buf.alloc = s5p_mfc_mem_alloc(alloc_ctx, ctx->instance_ctx_buf.size);
	if (IS_ERR_OR_NULL(ctx->instance_ctx_buf.alloc)) {
		ctx->instance_ctx_buf.alloc = NULL;
		mfc_err_ctx("Allocating context buffer failed.\n");
		return -ENOMEM;
	}

	ctx->instance_ctx_buf.daddr = s5p_mfc_mem_get_daddr(ctx->instance_ctx_buf.alloc);
	ctx->instance_ctx_buf.vaddr = s5p_mfc_mem_get_vaddr(ctx->instance_ctx_buf.alloc);
	mfc_debug(2, "Instance buf alloc, ctx: %d, size: %ld, addr: 0x%08llx\n",
			ctx->num, ctx->instance_ctx_buf.size, ctx->instance_ctx_buf.daddr);
	if (!ctx->instance_ctx_buf.vaddr) {
		s5p_mfc_mem_free(ctx->instance_ctx_buf.alloc);
		ctx->instance_ctx_buf.alloc = NULL;
		ctx->instance_ctx_buf.daddr = 0;
		ctx->instance_ctx_buf.vaddr = NULL;

		mfc_err_ctx("Remapping context buffer failed.\n");
		return -ENOMEM;
	}

	mfc_debug_leave();

	return 0;
}

/* Release instance buffer */
void s5p_mfc_release_instance_context(struct s5p_mfc_ctx *ctx)
{
	struct s5p_mfc_dev *dev;

	mfc_debug_enter();
	if (!ctx) {
		mfc_err_dev("no mfc context to run\n");
		return;
	}

	dev = ctx->dev;
	if (!dev) {
		mfc_err_dev("no mfc device to run\n");
		return;
	}

	if (ctx->instance_ctx_buf.vaddr) {
		s5p_mfc_mem_free(ctx->instance_ctx_buf.alloc);
		ctx->instance_ctx_buf.alloc = NULL;
		ctx->instance_ctx_buf.daddr = 0;
		ctx->instance_ctx_buf.vaddr = NULL;
	}

	mfc_debug_leave();
}

/* Allocate codec buffers */
int s5p_mfc_alloc_codec_buffers(struct s5p_mfc_ctx *ctx)
{
	struct s5p_mfc_dev *dev;
	struct s5p_mfc_dec *dec;
	struct s5p_mfc_enc *enc;
	unsigned int mb_width, mb_height;
	unsigned int lcu_width = 0, lcu_height = 0;
	void *alloc_ctx;
	int i;

	mfc_debug_enter();
	if (!ctx) {
		mfc_err_dev("no mfc context to run\n");
		return -EINVAL;
	}
	dev = ctx->dev;
	if (!dev) {
		mfc_err_dev("no mfc device to run\n");
		return -EINVAL;
	}
	dec = ctx->dec_priv;
	enc = ctx->enc_priv;
	alloc_ctx = dev->alloc_ctx;

	mb_width = WIDTH_MB(ctx->img_width);
	mb_height = HEIGHT_MB(ctx->img_height);

	if (ctx->type == MFCINST_DECODER) {
		lcu_width = DEC_LCU_WIDTH(ctx->img_width);
		lcu_height = DEC_LCU_HEIGHT(ctx->img_height);
		for (i = 0; i < ctx->raw_buf.num_planes; i++)
			mfc_debug(2, "Plane[%d] size:%d\n",
					i, ctx->raw_buf.plane_size[i]);
		mfc_debug(2, "MV size: %ld, Totals bufs: %d\n",
				ctx->mv_size, dec->total_dpb_count);
	} else if (ctx->type == MFCINST_ENCODER) {
		enc->tmv_buffer_size = 0;

		lcu_width = ENC_LCU_WIDTH(ctx->img_width);
		lcu_height = ENC_LCU_HEIGHT(ctx->img_height);
		if (ctx->codec_mode != S5P_FIMV_CODEC_HEVC_ENC &&
				ctx->codec_mode != S5P_FIMV_CODEC_VP9_ENC) {
			enc->luma_dpb_size =
				ALIGN((((mb_width * 16) + 63) / 64) * 64
						* (((mb_height * 16) + 31) / 32)
						* 32 + 64, 64);
			enc->chroma_dpb_size =
				ALIGN((((mb_width * 16) + 63) / 64)
						* 64 * (mb_height * 8) + 64, 64);
		} else {
			enc->luma_dpb_size =
				ALIGN((((lcu_width * 32 ) + 63 ) / 64) * 64
						* (((lcu_height * 32) + 31) / 32)
						* 32 + 64, 64);
			enc->chroma_dpb_size =
				ALIGN((((lcu_width * 32) + 63) / 64)
						* 64 * (lcu_height * 16) + 64, 64);
		}
		mfc_debug(2, "recon luma size: %zu chroma size: %zu\n",
			  enc->luma_dpb_size, enc->chroma_dpb_size);
	} else {
		return -EINVAL;
	}

	/* Codecs have different memory requirements */
	switch (ctx->codec_mode) {
	case S5P_FIMV_CODEC_H264_DEC:
	case S5P_FIMV_CODEC_H264_MVC_DEC:
		ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
		ctx->codec_buf.size =
			ctx->scratch_buf_size +
			(dec->mv_count * ctx->mv_size);
		break;
	case S5P_FIMV_CODEC_MPEG4_DEC:
	case S5P_FIMV_CODEC_FIMV1_DEC:
	case S5P_FIMV_CODEC_FIMV2_DEC:
	case S5P_FIMV_CODEC_FIMV3_DEC:
	case S5P_FIMV_CODEC_FIMV4_DEC:
		ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
		ctx->codec_buf.size = ctx->scratch_buf_size;
		break;
	case S5P_FIMV_CODEC_VC1_RCV_DEC:
	case S5P_FIMV_CODEC_VC1_DEC:
		ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
		ctx->codec_buf.size = ctx->scratch_buf_size;
		break;
	case S5P_FIMV_CODEC_MPEG2_DEC:
		ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
		ctx->codec_buf.size = ctx->scratch_buf_size;
		break;
	case S5P_FIMV_CODEC_H263_DEC:
		ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
		ctx->codec_buf.size = ctx->scratch_buf_size;
		break;
	case S5P_FIMV_CODEC_VP8_DEC:
		ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
		ctx->codec_buf.size = ctx->scratch_buf_size;
		break;
	case S5P_FIMV_CODEC_VP9_DEC:
		ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
		ctx->codec_buf.size =
			ctx->scratch_buf_size +
			DEC_STATIC_BUFFER_SIZE;
		break;
	case S5P_FIMV_CODEC_HEVC_DEC:
		ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
		ctx->codec_buf.size =
			ctx->scratch_buf_size +
			(dec->mv_count * ctx->mv_size);
		break;
	case S5P_FIMV_CODEC_H264_ENC:
		enc->me_buffer_size =
			ALIGN(ENC_V100_H264_ME_SIZE(mb_width, mb_height), 16);

		ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
		ctx->codec_buf.size =
			ctx->scratch_buf_size + enc->tmv_buffer_size +
			(ctx->dpb_count * (enc->luma_dpb_size +
			enc->chroma_dpb_size + enc->me_buffer_size));

		ctx->scratch_buf_size = max(ctx->scratch_buf_size, ctx->min_scratch_buf_size);
		ctx->min_scratch_buf_size = 0;
		break;
	case S5P_FIMV_CODEC_MPEG4_ENC:
	case S5P_FIMV_CODEC_H263_ENC:
		enc->me_buffer_size =
			ALIGN(ENC_V100_MPEG4_ME_SIZE(mb_width, mb_height), 16);

		ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
		ctx->codec_buf.size =
			ctx->scratch_buf_size + enc->tmv_buffer_size +
			(ctx->dpb_count * (enc->luma_dpb_size +
			enc->chroma_dpb_size + enc->me_buffer_size));
		break;
	case S5P_FIMV_CODEC_VP8_ENC:
		enc->me_buffer_size =
			ALIGN(ENC_V100_VP8_ME_SIZE(mb_width, mb_height), 16);

		ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
		ctx->codec_buf.size =
			ctx->scratch_buf_size + enc->tmv_buffer_size +
			(ctx->dpb_count * (enc->luma_dpb_size +
			enc->chroma_dpb_size + enc->me_buffer_size));
		break;
	case S5P_FIMV_CODEC_VP9_ENC:
			enc->me_buffer_size =
				ALIGN(ENC_V100_VP9_ME_SIZE(lcu_width, lcu_height), 16);

			ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
			ctx->codec_buf.size =
				ctx->scratch_buf_size + enc->tmv_buffer_size +
				(ctx->dpb_count * (enc->luma_dpb_size +
				enc->chroma_dpb_size + enc->me_buffer_size));
		break;
	case S5P_FIMV_CODEC_HEVC_ENC:
			enc->me_buffer_size =
				ALIGN(ENC_V100_HEVC_ME_SIZE(lcu_width, lcu_height), 16);

			ctx->scratch_buf_size = ALIGN(ctx->scratch_buf_size, 256);
			ctx->codec_buf.size =
				ctx->scratch_buf_size + enc->tmv_buffer_size +
				(ctx->dpb_count * (enc->luma_dpb_size +
				enc->chroma_dpb_size + enc->me_buffer_size));
		break;
	default:
		break;
	}

	if (ctx->is_drm)
		alloc_ctx = dev->alloc_ctx_drm;

	/* Allocate only if memory from bank 1 is necessary */
	if (ctx->codec_buf.size > 0) {
		ctx->codec_buf.alloc = s5p_mfc_mem_alloc(
				alloc_ctx, ctx->codec_buf.size);
		if (IS_ERR_OR_NULL(ctx->codec_buf.alloc)) {
			ctx->codec_buf.alloc = NULL;
			mfc_err_ctx("Allocating codec buffer failed.\n");
			return -ENOMEM;
		}
		ctx->codec_buf.daddr = s5p_mfc_mem_get_daddr(ctx->codec_buf.alloc);
		ctx->codec_buf.vaddr = s5p_mfc_mem_get_vaddr(ctx->codec_buf.alloc);
		mfc_debug(2, "Codec buf alloc, ctx: %d, size: %ld, addr: 0x%08llx\n",
			ctx->num, ctx->codec_buf.size, ctx->codec_buf.daddr);
		if (!ctx->codec_buf.vaddr) {
			s5p_mfc_mem_free(ctx->codec_buf.alloc);
			ctx->codec_buf.alloc = NULL;
			ctx->codec_buf.daddr = 0;

			mfc_err_ctx("Get vaddr for codec buffer failed.\n");
			return -ENOMEM;
		}
		ctx->codec_buffer_allocated = 1;
	} else if (ctx->codec_mode == S5P_FIMV_CODEC_MPEG2_DEC) {
		ctx->codec_buffer_allocated = 1;
	}

	mfc_debug_leave();

	return 0;
}

/* Release buffers allocated for codec */
void s5p_mfc_release_codec_buffers(struct s5p_mfc_ctx *ctx)
{
	struct s5p_mfc_dev *dev;

	if (!ctx) {
		mfc_err_dev("no mfc context to run\n");
		return;
	}

	dev = ctx->dev;
	if (!dev) {
		mfc_err_dev("no mfc device to run\n");
		return;
	}

	if (ctx->codec_buf.alloc) {
		ctx->codec_buffer_allocated = 0;
		s5p_mfc_mem_free(ctx->codec_buf.alloc);
		ctx->codec_buf.alloc = NULL;
		ctx->codec_buf.daddr = 0;
		ctx->codec_buf.vaddr = NULL;
	}
}

/* Allocation buffer of debug infor memory for FW debugging */
int s5p_mfc_alloc_dbg_info_buffer(struct s5p_mfc_dev *dev)
{
	struct s5p_mfc_buf_size_v6 *buf_size = dev->variant->buf_size->buf;
	void *alloc_ctx;

	mfc_debug(2, "Allocate a debug-info buffer.\n");

	alloc_ctx = dev->alloc_ctx;
	dev->dbg_info_buf.alloc = s5p_mfc_mem_alloc(alloc_ctx,
			buf_size->dbg_info_buf);
	if (IS_ERR_OR_NULL(dev->dbg_info_buf.alloc)) {
		mfc_err_dev("failed to allocate debug info memory\n");
		return -ENOMEM;
	}

	dev->dbg_info_buf.daddr = s5p_mfc_mem_get_daddr(dev->dbg_info_buf.alloc);
	dev->dbg_info_buf.vaddr = s5p_mfc_mem_get_vaddr(dev->dbg_info_buf.alloc);
	if (!dev->dbg_info_buf.vaddr) {
		s5p_mfc_mem_free(dev->dbg_info_buf.alloc);
		dev->dbg_info_buf.daddr = 0;
		dev->dbg_info_buf.alloc = NULL;

		mfc_err_dev("failed to get virtual address of debug info memory\n");
		return -ENOMEM;
	}
	mfc_debug(2, "dev->dbg_info_buf.daddr = 0x%08llx\n", dev->dbg_info_buf.daddr);
	mfc_debug(2, "dev->dbg_info_buf.vaddr = 0x%lx\n", (unsigned long int)dev->dbg_info_buf.vaddr);

	return 0;
}

/* Release buffer of debug infor memory for FW debugging */
int s5p_mfc_release_dbg_info_buffer(struct s5p_mfc_dev *dev)
{
	if (!dev) {
		mfc_err_dev("no mfc device to run\n");
		return -EINVAL;
	}

	if (!dev->dbg_info_buf.alloc) {
		mfc_debug(2, "debug info buffer is already freed\n");
		return 0;
	}

	mfc_debug(2, "Release the debug-info buffer.\n");

	s5p_mfc_mem_free(dev->dbg_info_buf.alloc);

	dev->dbg_info_buf.vaddr = NULL;
	dev->dbg_info_buf.daddr = 0;
	dev->dbg_info_buf.alloc = NULL;

	return 0;
}

/* Allocation buffer of ROI macroblock information */
static int mfc_alloc_enc_roi_buffer(struct s5p_mfc_ctx *ctx, struct s5p_mfc_special_buf *roi_buf)
{
	struct s5p_mfc_dev *dev = ctx->dev;
	struct s5p_mfc_buf_size_v6 *buf_size = dev->variant->buf_size->buf;
	void *alloc_ctx;

	alloc_ctx = dev->alloc_ctx;
	roi_buf->alloc = s5p_mfc_mem_alloc(alloc_ctx,
			buf_size->shared_buf);
	if (IS_ERR_OR_NULL(roi_buf->alloc)) {
		mfc_err_dev("failed to allocate shared memory\n");
		return -ENOMEM;
	}

	roi_buf->daddr = s5p_mfc_mem_get_daddr(roi_buf->alloc);
	roi_buf->vaddr = s5p_mfc_mem_get_vaddr(roi_buf->alloc);
	if (!roi_buf->vaddr) {
		s5p_mfc_mem_free(roi_buf->alloc);
		roi_buf->daddr = 0;
		roi_buf->alloc = NULL;

		mfc_err_dev("failed to get virtual address of shared memory\n");
		return -ENOMEM;
	}

	memset((void *)roi_buf->vaddr, 0, buf_size->shared_buf);
	s5p_mfc_mem_clean(roi_buf->alloc, roi_buf->vaddr, 0,
			buf_size->shared_buf);

	return 0;
}

/* Wrapper : allocation ROI buffers */
int s5p_mfc_alloc_enc_roi_buffer(struct s5p_mfc_ctx *ctx)
{
	struct s5p_mfc_enc *enc = ctx->enc_priv;
	int i;

	for (i = 0; i < MFC_MAX_EXTRA_BUF; i++) {
		if (mfc_alloc_enc_roi_buffer(ctx, &enc->roi_buf[i]) < 0) {
			mfc_err_dev("Remapping shared mem buffer failed.\n");
			return -ENOMEM;
		}
	}

	return 0;
}

/* Release buffer of ROI macroblock information */
void s5p_mfc_release_enc_roi_buffer(struct s5p_mfc_ctx *ctx)
{
	struct s5p_mfc_enc *enc = ctx->enc_priv;
	int i;

	for (i = 0; i < MFC_MAX_EXTRA_BUF; i++) {
		if (enc->roi_buf[i].alloc) {
			s5p_mfc_mem_free(enc->roi_buf[i].alloc);
			enc->roi_buf[i].alloc = NULL;
			enc->roi_buf[i].daddr = 0;
			enc->roi_buf[i].vaddr = NULL;
		}
	}
}

/* Allocate firmware */
int s5p_mfc_alloc_firmware(struct s5p_mfc_dev *dev)
{
	unsigned int base_align;
	size_t firmware_size;
	void *alloc_ctx;
	struct s5p_mfc_buf_size_v6 *buf_size;
	int ret = -EIO;

	mfc_debug_enter();

	if (!dev) {
		mfc_err_dev("no mfc device to run\n");
		return -EINVAL;
	}

	buf_size = dev->variant->buf_size->buf;
	base_align = dev->variant->buf_align->mfc_base_align;
	firmware_size = dev->variant->buf_size->firmware_code;
	dev->fw.size = firmware_size + buf_size->dev_ctx;

	if (dev->fw_buf.alloc)
		return 0;

	mfc_debug(2, "Allocating memory for firmware.\n");
	trace_mfc_loadfw_start(dev->fw.size, firmware_size);

	alloc_ctx = dev->alloc_ctx_fw;
	dev->fw_buf.alloc = s5p_mfc_mem_alloc(alloc_ctx, dev->fw.size);
	if (IS_ERR_OR_NULL(dev->fw_buf.alloc)) {
		dev->fw_buf.alloc = NULL;
		mfc_err_dev("Allocating bitprocessor buffer failed\n");
		return -ENOMEM;
	}

	dev->fw_buf.daddr = s5p_mfc_mem_get_daddr(dev->fw_buf.alloc);
	if (dev->fw_buf.daddr & ((1 << base_align) - 1)) {
		mfc_err_dev("The base memory is not aligned to %dBytes.\n",
				(1 << base_align));
		goto err_free_fw;
	}

	dev->fw_buf.vaddr =
		s5p_mfc_mem_get_vaddr(dev->fw_buf.alloc);
	mfc_debug(2, "Virtual address for FW: %08lx\n",
			(long unsigned int)dev->fw_buf.vaddr);
	if (!dev->fw_buf.vaddr) {
		mfc_err_dev("Bitprocessor memory remap failed\n");
		goto err_free_fw;
	}

	mfc_debug(2, "FW: 0x%08llx size: %08zu\n",
			dev->fw_buf.daddr, firmware_size);

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	alloc_ctx = dev->alloc_ctx_drm_fw;

	dev->drm_fw_buf.alloc = s5p_mfc_mem_alloc(alloc_ctx, dev->fw.size);
	if (IS_ERR_OR_NULL(dev->drm_fw_buf.alloc)) {
		dev->drm_fw_buf.alloc = NULL;
		dev->drm_fw_buf.daddr = 0;
		dev->drm_fw_buf.vaddr = NULL;
		mfc_err_dev("Allocating bitprocessor buffer failed\n");
		ret = -ENOMEM;
		goto err_free_fw;
	}

	dev->drm_fw_buf.daddr = s5p_mfc_mem_get_daddr(dev->drm_fw_buf.alloc);
	if (dev->drm_fw_buf.daddr & ((1 << base_align) - 1)) {
		mfc_err_dev("The base memory is not aligned to %dBytes.\n",
				(1 << base_align));
		goto err_free_drm_fw;
	}

	dev->drm_fw_buf.vaddr =
		s5p_mfc_mem_get_vaddr(dev->drm_fw_buf.alloc);
	mfc_info_dev("Virtual address for DRM FW: %08lx\n",
			(long unsigned int)dev->drm_fw_buf.vaddr);
	if (!dev->drm_fw_buf.vaddr) {
		mfc_err_dev("Bitprocessor memory remap failed\n");
		goto err_free_drm_fw;
	}

	mfc_info_dev("Port for DRM F/W : 0x%08llx\n", dev->drm_fw_buf.daddr);
#endif

	mfc_debug_leave();

	return 0;

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
err_free_drm_fw:
	s5p_mfc_mem_free(dev->drm_fw_buf.alloc);
	dev->drm_fw_buf.alloc = NULL;
	dev->drm_fw_buf.daddr = 0;
	dev->drm_fw_buf.vaddr = NULL;
#endif
err_free_fw:
	s5p_mfc_mem_free(dev->fw_buf.alloc);
	dev->fw_buf.alloc = NULL;
	dev->fw_buf.daddr = 0;
	dev->fw_buf.vaddr = NULL;
	return ret;
}

/* Load firmware to MFC */
int s5p_mfc_load_firmware(struct s5p_mfc_dev *dev)
{
	struct firmware *fw_blob;
	size_t firmware_size;
	int err;

	if (!dev) {
		mfc_err_dev("no mfc device to run\n");
		return -EINVAL;
	}

	firmware_size = dev->variant->buf_size->firmware_code;

	/* Firmare has to be present as a separate file or compiled
	 * into kernel. */
	mfc_debug_enter();
	mfc_debug(2, "Requesting fw\n");
	err = request_firmware((const struct firmware **)&fw_blob,
					MFC_FW_NAME, dev->v4l2_dev.dev);

	if (err != 0) {
		mfc_err_dev("Firmware is not present in the /lib/firmware directory nor compiled in kernel.\n");
		return -EINVAL;
	}

	mfc_debug(2, "Ret of request_firmware: %d Size: %zu\n", err, fw_blob->size);

	if (fw_blob->size > firmware_size) {
		mfc_err_dev("MFC firmware is too big to be loaded.\n");
		release_firmware(fw_blob);
		return -ENOMEM;
	}

	if (dev->fw_buf.alloc == NULL || dev->fw_buf.daddr == 0) {
		mfc_err_dev("MFC firmware is not allocated or was not mapped correctly.\n");
		release_firmware(fw_blob);
		return -EINVAL;
	}

	memcpy(dev->fw_buf.vaddr, fw_blob->data, fw_blob->size);
	s5p_mfc_mem_clean(dev->fw_buf.alloc, dev->fw_buf.vaddr, 0,
			fw_blob->size);
	s5p_mfc_mem_invalidate(dev->fw_buf.alloc, dev->fw_buf.vaddr, 0,
			fw_blob->size);
	if (dev->drm_fw_buf.vaddr) {
		memcpy(dev->drm_fw_buf.vaddr, fw_blob->data, fw_blob->size);
		mfc_debug(2, "copy firmware to secure region\n");
		s5p_mfc_mem_clean(dev->drm_fw_buf.alloc,
				dev->drm_fw_buf.vaddr, 0, fw_blob->size);
		s5p_mfc_mem_invalidate(dev->drm_fw_buf.alloc,
				dev->drm_fw_buf.vaddr, 0, fw_blob->size);
	}
	release_firmware(fw_blob);
	trace_mfc_loadfw_end(dev->fw.size, firmware_size);
	mfc_debug_leave();
	return 0;
}

/* Release firmware memory */
int s5p_mfc_release_firmware(struct s5p_mfc_dev *dev)
{
	/* Before calling this function one has to make sure
	 * that MFC is no longer processing */
	if (!dev) {
		mfc_err_dev("no mfc device to run\n");
		return -EINVAL;
	}

	if (!dev->fw_buf.alloc) {
		mfc_err_dev("firmware memory is already freed\n");
		return -EINVAL;
	}

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	if (dev->drm_fw_buf.alloc) {
		s5p_mfc_mem_free(dev->drm_fw_buf.alloc);
		dev->drm_fw_buf.vaddr = NULL;
		dev->drm_fw_buf.alloc = NULL;
		dev->drm_fw_buf.daddr = 0;
	}
#endif
	s5p_mfc_mem_free(dev->fw_buf.alloc);

	dev->fw_buf.vaddr =  NULL;
	dev->fw_buf.daddr = 0;
	dev->fw_buf.alloc = NULL;

	return 0;
}
