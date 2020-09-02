/*
 * drivers/media/platform/exynos/mfc/s5p_mfc_inst.c
 *
 * Copyright (c) 2010 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "s5p_mfc_inst.h"

#include "s5p_mfc_cmd.h"
#include "s5p_mfc_intr.h"

int s5p_mfc_open_inst(struct s5p_mfc_ctx *ctx)
{
	int ret;

	/* Preparing decoding - getting instance number */
	mfc_debug(2, "Getting instance number\n");
	s5p_mfc_clean_ctx_int_flags(ctx);
	ret = s5p_mfc_open_inst_cmd(ctx);
	if (ret) {
		mfc_err_ctx("Failed to create a new instance.\n");
		s5p_mfc_change_state(ctx, MFCINST_ERROR);
	}
	return ret;
}

int s5p_mfc_close_inst(struct s5p_mfc_ctx *ctx)
{
	int ret = -EINVAL;

	/* Closing decoding instance  */
	mfc_debug(2, "Returning instance number\n");
	s5p_mfc_clean_ctx_int_flags(ctx);
	if (ctx->state != MFCINST_FREE)
		ret = s5p_mfc_close_inst_cmd(ctx);

	if (ret) {
		mfc_err_ctx("Failed to return an instance.\n");
		s5p_mfc_change_state(ctx, MFCINST_ERROR);
		return ret;
	}
	return ret;
}

