/*
 * drivers/video/decon/panels/s6e36w0x10_lcd_ctrl.c
 *
 * Samsung SoC MIPI LCD CONTROL functions
 *
 * Copyright (c) 2016 Samsung Electronics
 *
 * Jiun Yu, <minwoo7945.kim@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <video/mipi_display.h>
#include "../dsim.h"
#include "s6e36w0x10_param.h"
#include "dsim_panel.h"


static int s6e36w0x10_read_info(struct dsim_device *dsim, unsigned char* mtp, unsigned char* hbm)
{
	int i;
	int ret;
	struct panel_private *panel = &dsim->priv;
	unsigned char tmtp[S6E36W0X10_MTP_DATE_SIZE] = {0, };
	unsigned char bufForCoordi[S6E36W0X10_COORDINATE_LEN] = {0,};

	dsim_info("%s:id-%d:was called\n", __func__, dsim->id);

	ret = dsim_read_hl_data(dsim, S6E36W0X10_ID_REG, S6E36W0X10_ID_LEN, dsim->priv.id);
	if (ret != S6E36W0X10_ID_LEN) {
		dsim_err("%s : can't find connected panel. check panel connection\n",__func__);
		panel->lcdConnected = PANEL_DISCONNECTED;
		goto read_exit;
	}

	dsim_info("READ ID : ");
	for (i = 0; i < S6E36W0X10_ID_LEN; i++)
		dsim_info("%02x, ", dsim->priv.id[i]);
	dsim_info("\n");

	ret = dsim_read_hl_data(dsim, S6E36W0X10_MTP_ADDR, S6E36W0X10_MTP_DATE_SIZE, tmtp);
	if (ret != S6E36W0X10_MTP_DATE_SIZE) {
		dsim_err("ERR:%s:failed to read mtp value : %d\n", __func__, ret);
		goto read_fail;
	}

	memcpy(mtp, tmtp, S6E36W0X10_MTP_SIZE);
	memcpy(dsim->priv.date, &tmtp[40], ARRAY_SIZE(dsim->priv.date));
	dsim_info("READ MTP SIZE : %d\n", S6E36W0X10_MTP_SIZE);
	dsim_info("=========== MTP INFO =========== \n");
	for (i = 0; i < S6E36W0X10_MTP_SIZE; i++)
		dsim_info("MTP[%2d] : %2d : %2x\n", i, mtp[i], mtp[i]);
	ret = dsim_read_hl_data(dsim, S6E36W0X10_COORDINATE_REG, S6E36W0X10_COORDINATE_LEN, bufForCoordi);
	if (ret != S6E36W0X10_COORDINATE_LEN) {
		dsim_err("fail to read coordinate on command.\n");
		goto read_fail;
	}
	dsim->priv.coordinate[0] = bufForCoordi[0] << 8 | bufForCoordi[1];	/* X */
	dsim->priv.coordinate[1] = bufForCoordi[2] << 8 | bufForCoordi[3];	/* Y */
	dsim_info("READ coordi : ");
	for(i = 0; i < 2; i++)
		dsim_info("%d, ", dsim->priv.coordinate[i]);
	dsim_info("\n");

read_exit:
	return 0;

read_fail:
	return -ENODEV;


}


static int s6e36w0x10_read_init_info(struct dsim_device *dsim, unsigned char* mtp, unsigned char* hbm)
{
	int ret = 0;

	ret = dsim_write_hl_data(dsim, SEQ_TEST_KEY_ON_F0, ARRAY_SIZE(SEQ_TEST_KEY_ON_F0));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_TEST_KEY_ON_F0\n", __func__, dsim->id);
		goto err_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_TEST_KEY_ON_F1, ARRAY_SIZE(SEQ_TEST_KEY_ON_F1));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_TEST_KEY_ON_F0\n", __func__, dsim->id);
		goto err_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_SLEEP_OUT, ARRAY_SIZE(SEQ_SLEEP_OUT));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_SLEEP_OUT\n", __func__, dsim->id);
		goto err_init;
	}
	msleep(20);

	ret = s6e36w0x10_read_info(dsim, mtp, hbm);
	if (ret) {
		dsim_err("ERR:%s:failed to read info \n", __func__);
		goto err_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_ALC_SETTING, ARRAY_SIZE(SEQ_ALC_SETTING));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_SINGLE_DSI_1\n", __func__, dsim->id);
		goto err_init;
	}
	ret = dsim_write_hl_data(dsim, SEQ_TEMP_OFFSET_1, ARRAY_SIZE(SEQ_TEMP_OFFSET_1));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_SINGLE_DSI_2\n", __func__, dsim->id);
		goto err_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_TEMP_OFFSET_2, ARRAY_SIZE(SEQ_TEMP_OFFSET_2));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_TE_ON\n", __func__, dsim->id);
		goto err_init;
	}

#ifndef CONFIG_PANEL_AID_DIMMING
	/* Brightness Setting */
	ret = dsim_write_hl_data(dsim, SEQ_GAMMA_CONDITION_SET, ARRAY_SIZE(SEQ_GAMMA_CONDITION_SET));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_GAMMA_CONDITION_SET\n", __func__, dsim->id);
		goto err_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_AID_SETTING, ARRAY_SIZE(SEQ_AID_SETTING));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_AID_SETTING\n", __func__, dsim->id);
		goto err_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_ELVSS_SET, ARRAY_SIZE(SEQ_ELVSS_SET));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_ELVSS_SET\n", __func__, dsim->id);
		goto err_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_GAMMA_UPDATE, ARRAY_SIZE(SEQ_GAMMA_UPDATE));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_GAMMA_UPDATE\n", __func__, dsim->id);
		goto err_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_ACL_OFF, ARRAY_SIZE(SEQ_ACL_OFF));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_ACL_OFF\n", __func__, dsim->id);
		goto err_init;
	}
#endif

	msleep(120);

	ret = dsim_write_hl_data(dsim, SEQ_TEST_KEY_OFF_F1, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F1));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_TEST_KEY_OFF_F0\n", __func__, dsim->id);
		goto err_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_TEST_KEY_OFF_F0, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_TEST_KEY_OFF_F0\n", __func__, dsim->id);
		goto err_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_TE_ON, ARRAY_SIZE(SEQ_TE_ON));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_ACL_OFF\n", __func__, dsim->id);
		goto err_init;
	}

	return ret;

err_init :
	dsim_err("ERR:PANEL:%s:id-%d:failed to full init\n", __func__, dsim->id);
	return ret;

}

static int s6e36w0x10_dump(struct dsim_device *dsim)
{
	int ret = 0;

	dsim_info("MDD : %s was called\n", __func__);

	return ret;
}

#ifdef CONFIG_PANEL_AID_DIMMING
extern int init_smart_dimming(struct panel_info *panel, char *refgamma, char *mtp);
#endif

static int s6e36w0x10_probe(struct dsim_device *dsim)
{
	int ret = 0;
	struct panel_private *panel = &dsim->priv;
	unsigned char mtp[S6E36W0X10_MTP_SIZE] = {0, };
	unsigned char hbm[S6E36W0X10_HBMGAMMA_LEN] = {0, };
#ifdef CONFIG_PANEL_AID_DIMMING
	unsigned char refgamma[S6E36W0X10_MTP_SIZE] = {
		0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
		0x80, 0x80, 0x80,
		0x80, 0x80, 0x80,
		0x80, 0x80, 0x80,
		0x80, 0x80, 0x80,
		0x80, 0x80, 0x80,
		0x80, 0x80, 0x80,
		0x80, 0x80, 0x80,
		0x80, 0x80, 0x80,
		0x00, 0x00, 0x00,
		0x00, 0x00
	};
#endif
	dsim_info("DSIM Panel : %d : %s was called\n", dsim->id, __func__);

	ret = s6e36w0x10_read_init_info(dsim, mtp, hbm);
	if (panel->lcdConnected == PANEL_DISCONNECTED) {
		dsim_err("dsim : %s lcd was not connected\n", __func__);
		goto probe_exit;
	}
#ifdef CONFIG_PANEL_AID_DIMMING
	init_smart_dimming(&panel->command, refgamma, mtp);
#endif

#ifdef CONFIG_EXYNOS_DECON_MDNIE_LITE
	panel->mdnie_support = 1;
#endif

probe_exit:
	return ret;

}


static int s6e36w0x10_displayon(struct dsim_device *dsim)
{
	int ret = 0;

	dsim_info("DSIM Panel : %d : %s was called\n", dsim->id, __func__);

	ret = dsim_write_hl_data(dsim, SEQ_DISPLAY_ON, ARRAY_SIZE(SEQ_DISPLAY_ON));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_DISPLAY_ON\n", __func__, dsim->id);
 		goto displayon_err;
	}

displayon_err:
	return ret;
}


static int s6e36w0x10_exit(struct dsim_device *dsim)
{
	int ret = 0;

	dsim_info("DSIM Panel : %d : %s was called\n", dsim->id, __func__);

	ret = dsim_write_hl_data(dsim, SEQ_DISPLAY_OFF, ARRAY_SIZE(SEQ_DISPLAY_OFF));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_DISPLAY_OFF\n", __func__, dsim->id);
		goto exit_err;
	}

	ret = dsim_write_hl_data(dsim, SEQ_SLEEP_IN, ARRAY_SIZE(SEQ_SLEEP_IN));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_SLEEP_IN\n", __func__, dsim->id);
		goto exit_err;
	}

	msleep(120);

exit_err:

	return ret;
}


static int s6e36w0x10_full_init(struct dsim_device *dsim)
{
	int ret = 0;

	ret = dsim_write_hl_data(dsim, SEQ_TEST_KEY_ON_F0, ARRAY_SIZE(SEQ_TEST_KEY_ON_F0));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_TEST_KEY_ON_F0\n", __func__, dsim->id);
		goto err_full_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_TEST_KEY_ON_F1, ARRAY_SIZE(SEQ_TEST_KEY_ON_F1));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_TEST_KEY_ON_F0\n", __func__, dsim->id);
		goto err_full_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_SLEEP_OUT, ARRAY_SIZE(SEQ_SLEEP_OUT));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_SLEEP_OUT\n", __func__, dsim->id);
		goto err_full_init;
	}
	msleep(20);

	ret = dsim_write_hl_data(dsim, SEQ_ALC_SETTING, ARRAY_SIZE(SEQ_ALC_SETTING));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_SINGLE_DSI_1\n", __func__, dsim->id);
		goto err_full_init;
	}
	ret = dsim_write_hl_data(dsim, SEQ_TEMP_OFFSET_1, ARRAY_SIZE(SEQ_TEMP_OFFSET_1));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_SINGLE_DSI_2\n", __func__, dsim->id);
		goto err_full_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_TEMP_OFFSET_2, ARRAY_SIZE(SEQ_TEMP_OFFSET_2));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_TE_ON\n", __func__, dsim->id);
		goto err_full_init;
	}

#if 0 
#ifndef CONFIG_PANEL_AID_DIMMING
	/* Brightness Setting */
	ret = dsim_write_hl_data(dsim, SEQ_GAMMA_CONDITION_SET, ARRAY_SIZE(SEQ_GAMMA_CONDITION_SET));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_GAMMA_CONDITION_SET\n", __func__, dsim->id);
		goto err_full_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_AID_SETTING, ARRAY_SIZE(SEQ_AID_SETTING));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_AID_SETTING\n", __func__, dsim->id);
		goto err_full_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_ELVSS_SET, ARRAY_SIZE(SEQ_ELVSS_SET));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_ELVSS_SET\n", __func__, dsim->id);
		goto err_full_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_GAMMA_UPDATE, ARRAY_SIZE(SEQ_GAMMA_UPDATE));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_GAMMA_UPDATE\n", __func__, dsim->id);
		goto err_full_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_ACL_OFF, ARRAY_SIZE(SEQ_ACL_OFF));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_ACL_OFF\n", __func__, dsim->id);
		goto err_full_init;
	}
#endif
#endif
	msleep(120);


	ret = dsim_write_hl_data(dsim, SEQ_TEST_KEY_OFF_F1, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F1));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_TEST_KEY_OFF_F0\n", __func__, dsim->id);
		goto err_full_init;
	}

	ret = dsim_write_hl_data(dsim, SEQ_TEST_KEY_OFF_F0, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_TEST_KEY_OFF_F0\n", __func__, dsim->id);
		goto err_full_init;
	}


	ret = dsim_write_hl_data(dsim, SEQ_TE_ON, ARRAY_SIZE(SEQ_TE_ON));
	if (ret != 0) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to write SEQ_ACL_OFF\n", __func__, dsim->id);
		goto err_full_init;
	}

	return ret;

err_full_init :
	dsim_err("ERR:PANEL:%s:id-%d:failed to full init\n", __func__, dsim->id);
	return ret;

}


static int s6e36w0x10_init(struct dsim_device *dsim)
{
	int ret = 0;

	dsim_info("DSIM Panel:id-%d:%s was called\n", dsim->id, __func__);

	ret = s6e36w0x10_full_init(dsim);
	if (ret) {
		dsim_err("ERR:PANEL:%s:id-%d:fail to full init\n", __func__, dsim->id);
		goto err_init;
	}

	return ret;

err_init:
	dsim_err("%s : failed to init\n", __func__);
	return ret;
}


struct dsim_panel_ops s6e36w0x10_panel_ops = {
	.name = "s6e36w0x10",
	.early_probe = NULL,
	.probe		= s6e36w0x10_probe,
	.displayon	= s6e36w0x10_displayon,
	.exit		= s6e36w0x10_exit,
	.init		= s6e36w0x10_init,
	.dump 		= s6e36w0x10_dump,
};

static int __init s6e36w0x10_register_panel(void)
{
	int ret = 0; 

	ret = dsim_register_panel(&s6e36w0x10_panel_ops);
	if (ret) {
		dsim_err("ERR:%s:failed to register panel\n", __func__);
	}
	return 0;
}
arch_initcall(s6e36w0x10_register_panel);

static int __init s6e36w0x10_get_lcd_type(char *arg)
{
	unsigned int lcdtype;

	get_option(&arg, &lcdtype);

	dsim_info("--- Parse LCD TYPE ---\n");
	dsim_info("LCDTYPE : %x\n", lcdtype);

	return 0;
}
early_param("lcdtype", s6e36w0x10_get_lcd_type);

