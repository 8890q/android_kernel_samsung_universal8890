/*
 * UFS Host Controller driver for Exynos specific extensions
 *
 * Copyright (C) 2013-2014 Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/clk.h>
#include <linux/smc.h>
#include <soc/samsung/exynos-pm.h>
#include <soc/samsung/exynos-powermode.h>
#include "ufshcd.h"
#include "unipro.h"
#include "mphy.h"
#include "ufshcd-pltfrm.h"
#include "ufs-exynos.h"
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>
#include <linux/soc/samsung/exynos-soc.h>

/*
 * Unipro attribute value
 */
#define TXTRAILINGCLOCKS	0x10
#define TACTIVATE_10_USEC	400	/* unit: 10us */

/* Device ID */
#define DEV_ID	0x00
#define PEER_DEV_ID	0x01
#define PEER_CPORT_ID	0x00
#define TRAFFIC_CLASS	0x00

/*
 * Default M-PHY parameter
 */
#define TX_DIF_P_NSEC		3000000	/* unit: ns */
#define TX_DIF_N_NSEC		1000000	/* unit: ns */
#define RX_DIF_P_NSEC		1000000	/* unit: ns */
#define RX_HIBERN8_WAIT_NSEC	4000000	/* unit: ns */
#define HIBERN8_TIME		40	/* unit: 100us */
#define RX_BASE_UNIT_NSEC	100000	/* unit: ns */
#define RX_GRAN_UNIT_NSEC	4000	/* unit: ns */
#define RX_SLEEP_CNT		1280	/* unit: ns */
#define RX_STALL_CNT		320	/* unit: ns */

#define TX_HIGH_Z_CNT_NSEC	20000	/* unit: ns */
#define TX_BASE_UNIT_NSEC	100000	/* unit: ns */
#define TX_GRAN_UNIT_NSEC	4000	/* unit: ns */
#define TX_SLEEP_CNT		1000	/* unit: ns */
#define IATOVAL_NSEC		20000	/* unit: ns */

#define UNIPRO_PCLK_PERIOD(ufs) (NSEC_PER_SEC / ufs->pclk_rate)
#define UNIPRO_MCLK_PERIOD(ufs) (NSEC_PER_SEC / ufs->mclk_rate)

#define for_each_ufs_lane(ufs, i) \
	for (i = 0; i < (ufs)->num_rx_lanes; i++)
#define for_each_phy_cfg(cfg) \
	for (; (cfg)->flg != PHY_CFG_NONE; (cfg)++)

/*
 * UIC configuration tables, used when a table in device node doesn't exist
 */
static struct ufs_phy_cfg init_cfg[] = {
	{PA_DBG_OPTION_SUITE, 0x30103, PMD_ALL, UNIPRO_DBG_MIB},
	{PA_DBG_AUTOMODE_THLD, 0x222E, PMD_ALL, UNIPRO_DBG_MIB},
	{0x00f, 0xfa, PMD_ALL, PHY_PMA_COMN},
	{0x010, 0x82, PMD_ALL, PHY_PMA_COMN},
	{0x011, 0x1e, PMD_ALL, PHY_PMA_COMN},
	{0x017, 0x84, PMD_ALL, PHY_PMA_COMN},
	{0x035, 0x58, PMD_ALL, PHY_PMA_TRSV},
	{0x036, 0x32, PMD_ALL, PHY_PMA_TRSV},
	{0x037, 0x40, PMD_ALL, PHY_PMA_TRSV},
	{0x03b, 0x83, PMD_ALL, PHY_PMA_TRSV},
	{0x042, 0x88, PMD_ALL, PHY_PMA_TRSV},
	{0x043, 0xa6, PMD_ALL, PHY_PMA_TRSV},
	{0x048, 0x74, PMD_ALL, PHY_PMA_TRSV},
	{0x04c, 0x5b, PMD_ALL, PHY_PMA_TRSV},
	{0x04d, 0x83, PMD_ALL, PHY_PMA_TRSV},
	{0x05c, 0x14, PMD_ALL, PHY_PMA_TRSV},
	{PA_DBG_OV_TM, true, PMD_ALL, PHY_PCS_COMN},
	{0x297, 0x17, PMD_ALL, PHY_PCS_RXTX},
	{PA_DBG_OV_TM, false, PMD_ALL, PHY_PCS_COMN},
	{},
};


static struct ufs_phy_cfg post_init_cfg[] = {
	{PA_DBG_OV_TM, true, PMD_ALL, PHY_PCS_COMN},
	{0x28b, 0x83, PMD_ALL, PHY_PCS_RXTX},
	{0x29a, 0x7, PMD_ALL, PHY_PCS_RXTX},
	{0x277, (200000 / 10) >> 10, PMD_ALL, PHY_PCS_RXTX},
	{PA_DBG_OV_TM, false, PMD_ALL, PHY_PCS_COMN},
	{},
};

/* Calibration for PWM mode */
static struct ufs_phy_cfg calib_of_pwm[] = {
	{PA_DBG_OV_TM, true, PMD_ALL, PHY_PCS_COMN},
	{0x376, 0x00, PMD_PWM, PHY_PCS_RXTX},
	{PA_DBG_OV_TM, false, PMD_ALL, PHY_PCS_COMN},
	{0x04d, 0x03, PMD_PWM, PHY_PMA_COMN},
	{PA_DBG_MODE, 0x1, PMD_ALL, UNIPRO_DBG_MIB},
	{PA_SAVECONFIGTIME, 0xbb8, PMD_ALL, UNIPRO_STD_MIB},
	{PA_DBG_MODE, 0x0, PMD_ALL, UNIPRO_DBG_MIB},
	{UNIP_DBG_FORCE_DME_CTRL_STATE, 0x22, PMD_ALL, UNIPRO_DBG_APB},
	{},
};

/* Calibration for HS mode series A */
static struct ufs_phy_cfg calib_of_hs_rate_a[] = {
	{PA_DBG_OV_TM, true, PMD_ALL, PHY_PCS_COMN},
	{0x362, 0xff, PMD_HS, PHY_PCS_RXTX},
	{0x363, 0x00, PMD_HS, PHY_PCS_RXTX},
	{PA_DBG_OV_TM, false, PMD_ALL, PHY_PCS_COMN},
	{0x00f, 0xfa, PMD_HS, PHY_PMA_COMN},
	{0x010, 0x82, PMD_HS, PHY_PMA_COMN},
	{0x011, 0x1e, PMD_HS, PHY_PMA_COMN},
	/* Setting order: 1st(0x16), 2nd(0x15) */
	{0x016, 0xff, PMD_HS, PHY_PMA_COMN},
	{0x015, 0x80, PMD_HS, PHY_PMA_COMN},
	{0x017, 0x94, PMD_HS, PHY_PMA_COMN},
	{0x036, 0x32, PMD_HS, PHY_PMA_TRSV},
	{0x037, 0x43, PMD_HS, PHY_PMA_TRSV},
	{0x038, 0x3f, PMD_HS, PHY_PMA_TRSV},
	{0x042, 0x88, PMD_HS, PHY_PMA_TRSV},
	{0x043, 0xa6, PMD_HS, PHY_PMA_TRSV},
	{0x048, 0x74, PMD_HS, PHY_PMA_TRSV},
	{0x034, 0x35, PMD_HS_G2_L1 | PMD_HS_G2_L2, PHY_PMA_TRSV},
	{0x035, 0x5b, PMD_HS_G2_L1 | PMD_HS_G2_L2, PHY_PMA_TRSV},
	{PA_DBG_MODE, 0x1, PMD_ALL, UNIPRO_DBG_MIB},
	{PA_SAVECONFIGTIME, 0xbb8, PMD_ALL, UNIPRO_STD_MIB},
	{PA_DBG_MODE, 0x0, PMD_ALL, UNIPRO_DBG_MIB},
	{UNIP_DBG_FORCE_DME_CTRL_STATE, 0x22, PMD_ALL, UNIPRO_DBG_APB},
	{},
};

/* Calibration for HS mode series B */
static struct ufs_phy_cfg calib_of_hs_rate_b[] = {
	{PA_DBG_OV_TM, true, PMD_ALL, PHY_PCS_COMN},
	{0x362, 0xff, PMD_HS, PHY_PCS_RXTX},
	{0x363, 0x00, PMD_HS, PHY_PCS_RXTX},
	{PA_DBG_OV_TM, false, PMD_ALL, PHY_PCS_COMN},
	{0x00f, 0xfa, PMD_HS, PHY_PMA_COMN},
	{0x010, 0x82, PMD_HS, PHY_PMA_COMN},
	{0x011, 0x1e, PMD_HS, PHY_PMA_COMN},
	/* Setting order: 1st(0x16), 2nd(0x15) */
	{0x016, 0xff, PMD_HS, PHY_PMA_COMN},
	{0x015, 0x80, PMD_HS, PHY_PMA_COMN},
	{0x017, 0x94, PMD_HS, PHY_PMA_COMN},
	{0x036, 0x32, PMD_HS, PHY_PMA_TRSV},
	{0x037, 0x43, PMD_HS, PHY_PMA_TRSV},
	{0x038, 0x3f, PMD_HS, PHY_PMA_TRSV},
	{0x042, 0xbb, PMD_HS_G2_L1 | PMD_HS_G2_L2, PHY_PMA_TRSV},
	{0x043, 0xa6, PMD_HS, PHY_PMA_TRSV},
	{0x048, 0x74, PMD_HS, PHY_PMA_TRSV},
	{0x034, 0x36, PMD_HS_G2_L1 | PMD_HS_G2_L2, PHY_PMA_TRSV},
	{0x035, 0x5c, PMD_HS_G2_L1 | PMD_HS_G2_L2, PHY_PMA_TRSV},
	{PA_DBG_MODE, 0x1, PMD_ALL, UNIPRO_DBG_MIB},
	{PA_SAVECONFIGTIME, 0xbb8, PMD_ALL, UNIPRO_STD_MIB},
	{PA_DBG_MODE, 0x0, PMD_ALL, UNIPRO_DBG_MIB},
	{UNIP_DBG_FORCE_DME_CTRL_STATE, 0x22, PMD_ALL, UNIPRO_DBG_APB},
	{},
};

/* Calibration for PWM mode atfer PMC */
static struct ufs_phy_cfg post_calib_of_pwm[] = {
	{PA_DBG_RXPHY_CFGUPDT, 0x1, PMD_ALL, UNIPRO_DBG_MIB},
	{PA_DBG_OV_TM, true, PMD_ALL, PHY_PCS_COMN},
	{0x363, 0x00, PMD_PWM, PHY_PCS_RXTX},
	{PA_DBG_OV_TM, false, PMD_ALL, PHY_PCS_COMN},
	{},
};

/* Calibration for HS mode series A atfer PMC */
static struct ufs_phy_cfg post_calib_of_hs_rate_a[] = {
	{PA_DBG_RXPHY_CFGUPDT, 0x1, PMD_ALL, UNIPRO_DBG_MIB},
	{0x015, 0x00, PMD_HS, PHY_PMA_COMN},
	{0x04d, 0x83, PMD_HS, PHY_PMA_TRSV},
	{0x41a, 0x00, PMD_HS_G3_L1 | PMD_HS_G3_L2, PHY_PCS_COMN},
	{PA_DBG_OV_TM, true, PMD_ALL, PHY_PCS_COMN},
	{0x363, 0x00, PMD_HS, PHY_PCS_RXTX},
	{PA_DBG_OV_TM, false, PMD_ALL, PHY_PCS_COMN},
	{PA_DBG_MODE, 0x1, PMD_ALL, UNIPRO_DBG_MIB},
	{PA_CONNECTEDTXDATALANES, 1, PMD_HS_G1_L1 | PMD_HS_G2_L1 | PMD_HS_G3_L1, UNIPRO_STD_MIB},
	{PA_DBG_MODE, 0x0, PMD_ALL, UNIPRO_DBG_MIB},
	{0x01E, BIT(5), PMD_HS, PHY_PLL_WAIT},
	{0x05E, BIT(4), PMD_HS, PHY_CDR_WAIT},
	{},
};

/* Calibration for HS mode series B after PMC*/
static struct ufs_phy_cfg post_calib_of_hs_rate_b[] = {
	{PA_DBG_RXPHY_CFGUPDT, 0x1, PMD_ALL, UNIPRO_DBG_MIB},
	{0x015, 0x00, PMD_HS, PHY_PMA_COMN},
	{0x04d, 0x83, PMD_HS, PHY_PMA_TRSV},
	{0x41a, 0x00, PMD_HS_G3_L1 | PMD_HS_G3_L2, PHY_PCS_COMN},
	{PA_DBG_OV_TM, true, PMD_ALL, PHY_PCS_COMN},
	{0x363, 0x00, PMD_HS, PHY_PCS_RXTX},
	{PA_DBG_OV_TM, false, PMD_ALL, PHY_PCS_COMN},
	{PA_DBG_MODE, 0x1, PMD_ALL, UNIPRO_DBG_MIB},
	{PA_CONNECTEDTXDATALANES, 1, PMD_HS_G1_L1 | PMD_HS_G2_L1 | PMD_HS_G3_L1, UNIPRO_STD_MIB},
	{PA_DBG_MODE, 0x0, PMD_ALL, UNIPRO_DBG_MIB},
	{0x01E, BIT(5), PMD_HS, PHY_PLL_WAIT},
	{0x05E, BIT(4), PMD_HS, PHY_CDR_WAIT},

	{},
};

static struct ufs_phy_cfg lpa_restore[] = {
	{},
};

static struct ufs_phy_cfg pre_clk_off[] = {
	{},
};

static struct ufs_phy_cfg post_clk_on[] = {
	{},
};

static struct ufs_phy_cfg lane1_sq_off[] = {
	{},
};

static struct exynos_ufs_soc exynos_ufs_soc_data = {
	.tbl_phy_init			= init_cfg,
	.tbl_post_phy_init		= post_init_cfg,
	.tbl_calib_of_pwm		= calib_of_pwm,
	.tbl_calib_of_hs_rate_a		= calib_of_hs_rate_a,
	.tbl_calib_of_hs_rate_b		= calib_of_hs_rate_b,
	.tbl_post_calib_of_pwm		= post_calib_of_pwm,
	.tbl_post_calib_of_hs_rate_a	= post_calib_of_hs_rate_a,
	.tbl_post_calib_of_hs_rate_b	= post_calib_of_hs_rate_b,
	.tbl_lpa_restore		= lpa_restore,
	.tbl_pre_clk_off		= pre_clk_off,
	.tbl_post_clk_on		= post_clk_on,
	.tbl_lane1_sq_off		= lane1_sq_off,
};

/*
 * Debugging information, SFR/attributes/misc
 */
static struct exynos_ufs *ufs_host_backup[1];
static int ufs_host_index = 0;

static struct exynos_ufs_sfr_log ufs_log_std_sfr[] = {
	{"CAPABILITIES"			,	REG_CONTROLLER_CAPABILITIES,	0},
	{"UFS VERSION"			,	REG_UFS_VERSION,		0},
	{"PRODUCT ID"			,	REG_CONTROLLER_DEV_ID,		0},
	{"MANUFACTURE ID"		,	REG_CONTROLLER_PROD_ID,		0},
	{"INTERRUPT STATUS"		,	REG_INTERRUPT_STATUS,		0},
	{"INTERRUPT ENABLE"		,	REG_INTERRUPT_ENABLE,		0},
	{"CONTROLLER STATUS"		,	REG_CONTROLLER_STATUS,		0},
	{"CONTROLLER ENABLE"		,	REG_CONTROLLER_ENABLE,		0},
	{"UIC ERR PHY ADAPTER LAYER"	,	REG_UIC_ERROR_CODE_PHY_ADAPTER_LAYER,		0},
	{"UIC ERR DATA LINK LAYER"	,	REG_UIC_ERROR_CODE_DATA_LINK_LAYER,		0},
	{"UIC ERR NETWORK LATER"	,	REG_UIC_ERROR_CODE_NETWORK_LAYER,		0},
	{"UIC ERR TRANSPORT LAYER"	,	REG_UIC_ERROR_CODE_TRANSPORT_LAYER,		0},
	{"UIC ERR DME"			,	REG_UIC_ERROR_CODE_DME,		0},
	{"UTP TRANSF REQ INT AGG CNTRL"	,	REG_UTP_TRANSFER_REQ_INT_AGG_CONTROL,		0},
	{"UTP TRANSF REQ LIST BASE L"	,	REG_UTP_TRANSFER_REQ_LIST_BASE_L,		0},
	{"UTP TRANSF REQ LIST BASE H"	,	REG_UTP_TRANSFER_REQ_LIST_BASE_H,		0},
	{"UTP TRANSF REQ DOOR BELL"	,	REG_UTP_TRANSFER_REQ_DOOR_BELL,		0},
	{"UTP TRANSF REQ LIST CLEAR"	,	REG_UTP_TRANSFER_REQ_LIST_CLEAR,		0},
	{"UTP TRANSF REQ LIST RUN STOP"	,	REG_UTP_TRANSFER_REQ_LIST_RUN_STOP,		0},
	{"UTP TASK REQ LIST BASE L"	,	REG_UTP_TASK_REQ_LIST_BASE_L,		0},
	{"UTP TASK REQ LIST BASE H"	,	REG_UTP_TASK_REQ_LIST_BASE_H,		0},
	{"UTP TASK REQ DOOR BELL"	,	REG_UTP_TASK_REQ_DOOR_BELL,		0},
	{"UTP TASK REQ LIST CLEAR"	,	REG_UTP_TASK_REQ_LIST_CLEAR,		0},
	{"UTP TASK REQ LIST RUN STOP"	,	REG_UTP_TASK_REQ_LIST_RUN_STOP,		0},
	{"UIC COMMAND"			,	REG_UIC_COMMAND,		0},
	{"UIC COMMAND ARG1"		,	REG_UIC_COMMAND_ARG_1,		0},
	{"UIC COMMAND ARG2"		,	REG_UIC_COMMAND_ARG_2,		0},
	{"UIC COMMAND ARG3"		,	REG_UIC_COMMAND_ARG_3,		0},

	{},
};

static inline const struct exynos_ufs_soc *to_phy_soc(struct exynos_ufs *ufs)
{
	return ufs->phy.soc;
}

static inline void exynos_ufs_ctrl_phy_pwr(struct exynos_ufs *ufs, bool en)
{
	/* TODO: offset, mask */
	writel(!!en, ufs->phy.reg_pmu);
}

#ifndef __EXYNOS_UFS_VS_DEBUG__
static void exynos_ufs_dump_std_sfr(struct ufs_hba *hba)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	struct exynos_ufs_sfr_log* cfg = ufs->debug.std_sfr;

	dev_err(hba->dev, ": --------------------------------------------------- \n");
	dev_err(hba->dev, ": \t\tREGISTER DUMP\n");
	dev_err(hba->dev, ": --------------------------------------------------- \n");

	while(cfg) {
		if (!cfg->name)
			break;
		cfg->val = ufshcd_readl(hba, cfg->offset);

		/* Dump */
		dev_err(hba->dev, ": %s(0x%04x):\t\t\t\t0x%08x\n",
				cfg->name, cfg->offset, cfg->val);

		/* Next SFR */
		cfg++;
	}
}
#endif

/*
 * Exynos debugging main function
 */
static void exynos_ufs_dump_debug_info(struct ufs_hba *hba)
{
#ifdef __EXYNOS_UFS_VS_DEBUG__
	exynos_ufs_get_uic_info(hba);
#else
	exynos_ufs_dump_std_sfr(hba);
#endif
}

#define NUM_OF_PHY_CONFIGS	12
static int exynos_ufs_populate_dt_phy_cfg(struct device *dev,
		struct exynos_ufs_soc **org_soc)
{
	int ret = 1;
	int i, j;
	u32* val;
	int num_of_configs[NUM_OF_PHY_CONFIGS];
	struct exynos_ufs_soc *soc;
	struct ufs_phy_cfg *phy_cfg;
	const char *const configs[NUM_OF_PHY_CONFIGS] = {
		"phy-init",
		"post-phy-init",
		"calib-of-pwm",
		"calib-of-hs-rate-a",
		"calib-of-hs-rate-b",
		"post-calib-of-pwm",
		"post-calib-of-hs-rate-a",
		"post-calib-of-hs-rate-b",
		"lpa-restore",
		"pre-clk-off",
		"post-clk-on",
		"lane1-sq-off",
	};

	soc = devm_kzalloc(dev, sizeof(*soc), GFP_KERNEL);
	if (!soc) {
		dev_err(dev, "cannot allocate mem for phy configs\n");
		return -ENOMEM;
	}
	phy_cfg = soc->tbl_phy_init;

	dev_dbg(dev, "=== PHY config allocation complete ===\n");
	for (i=0 ; i<NUM_OF_PHY_CONFIGS ; i++) {
		/* Check if each config table exits */
		if (!of_get_property(dev->of_node, configs[i], &num_of_configs[i])) {
			/* Older boards provide only the tables their PHY needs. */
			if (i == 0)
				goto out;
			continue;
		}
		num_of_configs[i] /= sizeof(int);
		dev_dbg(dev, "%s: %d\n", configs[i], num_of_configs[i]);

		/* Buffer allocation for each table */
		phy_cfg = devm_kzalloc(dev,
			(num_of_configs[i] * sizeof(*phy_cfg)/sizeof(int)), GFP_KERNEL);
		if (!phy_cfg) {
			dev_err(dev, "cannot allocate mem for a phy table\n");
			return -ENOMEM;
		}

		/* Fetch config data from DT */
		if(of_property_read_u32_array(dev->of_node, configs[i], (u32*)phy_cfg,
					num_of_configs[i])) {
			devm_kfree(dev, phy_cfg);
			goto out;
		}
		val = (u32*)phy_cfg;
		for (j=0 ; j<num_of_configs[i]; j+=sizeof(int))
			dev_dbg(dev, "%08X %08X %08X %08X\n",
					val[j],val[j+1],val[j+2],val[j+3]);

		/* Move a pointer to indicate each table */
		*(&soc->tbl_phy_init+i) = phy_cfg;
	}
	ret = 0;
out:
	*org_soc = soc;
	return ret;
}

static void exynos_ufs_select_refclk(struct exynos_ufs *ufs, bool en)
{
#if !defined(CONFIG_SOC_EXYNOS7420) && !defined(CONFIG_SOC_EXYNOS8890)
	u32 reg;

	if (ufs->hw_rev != UFS_VER_0004)
		return;

	/*
	 * true : alternative clock path, false : active clock path
	 */
	reg = hci_readl(ufs, HCI_MPHY_REFCLK_SEL);
	if (en)
		hci_writel(ufs, reg | MPHY_REFCLK_SEL, HCI_MPHY_REFCLK_SEL);
	else
		hci_writel(ufs, reg & ~MPHY_REFCLK_SEL, HCI_MPHY_REFCLK_SEL);
#endif
}

inline void exynos_ufs_set_hwacg_control(struct exynos_ufs *ufs, bool en)
{
#if !defined(CONFIG_SOC_EXYNOS7420) && !defined(CONFIG_SOC_EXYNOS8890)
	u32 reg;

	if (ufs->hw_rev < UFS_VER_0004)
		return;

	/*
	 * default value 1->0 at KC. so,
	 * need to set "1(disable HWACG)" during UFS init
	 */
	reg = hci_readl(ufs, HCI_UFS_ACG_DISABLE);
	if (en)
		hci_writel(ufs, reg & (~HCI_UFS_ACG_DISABLE_EN), HCI_UFS_ACG_DISABLE);
	else
		hci_writel(ufs, reg | HCI_UFS_ACG_DISABLE_EN, HCI_UFS_ACG_DISABLE);

#endif
}

inline void exynos_ufs_ctrl_auto_hci_clk(struct exynos_ufs *ufs, bool en)
{
	u32 reg = hci_readl(ufs, HCI_FORCE_HCS);

	if (en)
		hci_writel(ufs, reg | HCI_CORECLK_STOP_EN, HCI_FORCE_HCS);
	else
		hci_writel(ufs, reg & ~HCI_CORECLK_STOP_EN, HCI_FORCE_HCS);
}

static inline void exynos_ufs_ctrl_clk(struct exynos_ufs *ufs, bool en)
{
	u32 reg = hci_readl(ufs, HCI_FORCE_HCS);

	if (en)
		hci_writel(ufs, reg | CLK_STOP_CTRL_EN_ALL, HCI_FORCE_HCS);
	else
		hci_writel(ufs, reg & ~CLK_STOP_CTRL_EN_ALL, HCI_FORCE_HCS);
}

static inline void exynos_ufs_gate_clk(struct exynos_ufs *ufs, bool en)
{

	u32 reg = hci_readl(ufs, HCI_CLKSTOP_CTRL);

	if (en)
		hci_writel(ufs, reg | CLK_STOP_ALL, HCI_CLKSTOP_CTRL);
	else
		hci_writel(ufs, reg & ~CLK_STOP_ALL, HCI_CLKSTOP_CTRL);
}

static void exynos_ufs_set_pclk_period(struct exynos_ufs *ufs, u8 div)
{
	u32 pclk_ctrl;

	pclk_ctrl = hci_readl(ufs, HCI_UNIPRO_APB_CLK_CTRL);
	pclk_ctrl = (pclk_ctrl & ~0xf) | (div & 0xf);
	hci_writel(ufs, pclk_ctrl, HCI_UNIPRO_APB_CLK_CTRL);
}

static u8 exynos_ufs_set_unipro_pclk(struct exynos_ufs *ufs)
{
	u32 pclk_rate;
	u32 f_min, f_max;
	u8 div = 0;

	pclk_rate = clk_get_rate(ufs->pclk);

	if (ufs->hw_rev == UFS_VER_0004){
		ufs->pclk_rate = pclk_rate;
		return div;
	}

	f_min = ufs->pclk_avail_min;
	f_max = ufs->pclk_avail_max;

	do {
		pclk_rate /= (div + 1);

		if (pclk_rate <= f_max)
			break;
		else
			div++;
	} while (pclk_rate >= f_min);

	WARN(pclk_rate < f_min, "not available pclk range %d\n", pclk_rate);

	if (ufs->hw_rev == UFS_VER_0003 &&
	    !(ufs->opts & EXYNOS_UFS_OPTS_USE_SEPERATED_PCLK))
		exynos_ufs_set_pclk_period(ufs, div);

	ufs->pclk_rate = pclk_rate;

	return div;
}

static void exynos_ufs_set_unipro_mclk(struct exynos_ufs *ufs)
{
	ufs->mclk_rate = clk_get_rate(ufs->clk_unipro);
}

static u32 exynos_ufs_calc_time_cntr(struct exynos_ufs *ufs, long period)
{
	const u32 precise = 10;
	u32 pclk_rate = ufs->pclk_rate;
	u32 clk_period, fraction;

	clk_period = UNIPRO_PCLK_PERIOD(ufs);
	fraction = ((NSEC_PER_SEC % pclk_rate) * precise) / pclk_rate;

	return (period * precise) / ((clk_period * precise) + fraction);
}

static void exynos_ufs_fit_aggr_timeout(struct exynos_ufs *ufs)
{
	u32 cnt_val;
	u32 nVal;
	const u8 cnt_div_val = 40;

	if (ufs->hw_rev >= UFS_VER_0004) {
		/* IA_TICK_SEL : 1(1us_TO_CNT_VAL) */
		nVal = hci_readl(ufs, HCI_UFSHCI_V2P1_CTRL);
		nVal |= IA_TICK_SEL;
		hci_writel(ufs, nVal, HCI_UFSHCI_V2P1_CTRL);

		cnt_val = ufs->mclk_rate / 1000000 ;
		hci_writel(ufs, cnt_val & CNT_VAL_1US_MASK, HCI_1US_TO_CNT_VAL);
	}
	else {
		cnt_val = exynos_ufs_calc_time_cntr(ufs, IATOVAL_NSEC / cnt_div_val);
		hci_writel(ufs, cnt_val & CNT_VAL_1US_MASK, HCI_1US_TO_CNT_VAL);
	}
}

static void exynos_ufs_set_pwm_clk_div(struct exynos_ufs *ufs)
{
	struct ufs_hba *hba = ufs->hba;
	const int div = 30, mult = 20;
	const unsigned long pwm_min = 3 * 1000 * 1000;
	const unsigned long pwm_max = 9 * 1000 * 1000;
	long clk_period;
	const int divs[] = {32, 16, 8, 4};
	unsigned long _clk, clk = 0;
	int i = 0, clk_idx = -1;

	if (ufs->hw_rev >= UFS_VER_0004)
		return;

	clk_period = UNIPRO_PCLK_PERIOD(ufs);

	for (i = 0; i < ARRAY_SIZE(divs); i++) {
		_clk = NSEC_PER_SEC * mult / (clk_period * divs[i] * div);
		if (_clk >= pwm_min && _clk <= pwm_max) {
			if (_clk > clk) {
				clk_idx = i;
				clk = _clk;
			}
		}
	}
	ufs->pwm_freq = clk;

	if (clk_idx >= 0)
		ufshcd_dme_set(hba, UIC_ARG_MIB(CMN_PWM_CMN_CTRL),
				clk_idx & PWM_CMN_CTRL_MASK);
	else
		dev_err(ufs->dev, "not dicided pwm clock divider\n");
}

static int exynos_ufs_calc_line_init_pre_len(struct exynos_ufs *ufs, int tx_ls_prep_len)
{
	u32 pwm_g1_ns;
	u32 val = 1;
	u32 result;
	u32 pwm_gear = 1;
	long pwm_g1_freq;
	int i;
	int pow_val;

	pwm_g1_freq = ufs->pwm_freq;

	pwm_g1_ns = (1000 *1000 *1000 / pwm_g1_freq); //ns

	pow_val = (tx_ls_prep_len + pwm_gear - 7);
	if (pow_val <= 0)
		val = 1;
	else {
		for(i = 0; i < pow_val; i++)
			val *= 2;
	}

	result = pwm_g1_ns * 10 * val;

	return (result/1000);
}

static void exynos_ufs_set_line_init_prep_len(struct exynos_ufs *ufs)
{
	struct uic_pwr_mode *act_pmd = &ufs->act_pmd_parm;
	struct ufs_hba *hba = ufs->hba;
	u32 tx_ls_prepare_length;
	u32 result;
	u32 result_div;
	u32 rate = act_pmd->hs_series;
	int i;

	if (!(ufs->opts & EXYNOS_UFS_OPTS_SET_LINE_INIT_PREP_LEN))
		return;

	for (i = 0; i <= 15; i++) {  /* gear1 prepare length 1~15 */
		tx_ls_prepare_length = i;

		result = exynos_ufs_calc_line_init_pre_len(ufs, tx_ls_prepare_length);

		if (result > 200)
			break;
	}

	if (rate == 1)
		result_div = ((result * 10000) / 160);
	else
		result_div = ((result * 10000) / 136);

	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_DBG_OV_TM), TRUE);
	for_each_ufs_lane(ufs, i) {
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(0x29E, i), (result_div >> 8) & 0xFF);
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(0x29F, i), result_div & 0xFF);
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(0x29D, i), 0x10);
	}
	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_DBG_OV_TM), FALSE);
}

static void exynos_ufs_compute_phy_time_v(struct exynos_ufs *ufs,
					struct phy_tm_parm *tm_parm)
{
	tm_parm->tx_linereset_p =
		exynos_ufs_calc_time_cntr(ufs, TX_DIF_P_NSEC);
	tm_parm->tx_linereset_n =
		exynos_ufs_calc_time_cntr(ufs, TX_DIF_N_NSEC);
	tm_parm->tx_high_z_cnt =
		exynos_ufs_calc_time_cntr(ufs, TX_HIGH_Z_CNT_NSEC);
	tm_parm->tx_base_n_val =
		exynos_ufs_calc_time_cntr(ufs, TX_BASE_UNIT_NSEC);
	tm_parm->tx_gran_n_val =
		exynos_ufs_calc_time_cntr(ufs, TX_GRAN_UNIT_NSEC);
	tm_parm->tx_sleep_cnt =
		exynos_ufs_calc_time_cntr(ufs, TX_SLEEP_CNT);

	tm_parm->rx_linereset =
		exynos_ufs_calc_time_cntr(ufs, RX_DIF_P_NSEC);
	tm_parm->rx_hibern8_wait =
		exynos_ufs_calc_time_cntr(ufs, RX_HIBERN8_WAIT_NSEC);
	tm_parm->rx_base_n_val =
		exynos_ufs_calc_time_cntr(ufs, RX_BASE_UNIT_NSEC);
	tm_parm->rx_gran_n_val =
		exynos_ufs_calc_time_cntr(ufs, RX_GRAN_UNIT_NSEC);
	tm_parm->rx_sleep_cnt =
		exynos_ufs_calc_time_cntr(ufs, RX_SLEEP_CNT);
	tm_parm->rx_stall_cnt =
		exynos_ufs_calc_time_cntr(ufs, RX_STALL_CNT);
}

static void exynos_ufs_config_phy_time_v(struct exynos_ufs *ufs)
{
	struct ufs_hba *hba = ufs->hba;
	struct phy_tm_parm tm_parm;
	int i;

	if (ufs->hw_rev >= UFS_VER_0004)
		return;

	exynos_ufs_compute_phy_time_v(ufs, &tm_parm);

	exynos_ufs_set_pwm_clk_div(ufs);

	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_DBG_OV_TM), TRUE);

	for_each_ufs_lane(ufs, i) {
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_FILLER_ENABLE, i),
				0x2);
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_LINERESET_VAL, i),
				RX_LINERESET(tm_parm.rx_linereset));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_BASE_NVAL_07_00, i),
				RX_BASE_NVAL_L(tm_parm.rx_base_n_val));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_BASE_NVAL_15_08, i),
				RX_BASE_NVAL_H(tm_parm.rx_base_n_val));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_GRAN_NVAL_07_00, i),
				RX_GRAN_NVAL_L(tm_parm.rx_gran_n_val));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_GRAN_NVAL_10_08, i),
				RX_GRAN_NVAL_H(tm_parm.rx_gran_n_val));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_OV_SLEEP_CNT_TIMER, i),
				RX_OV_SLEEP_CNT(tm_parm.rx_sleep_cnt));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_OV_STALL_CNT_TIMER, i),
				RX_OV_STALL_CNT(tm_parm.rx_stall_cnt));
	}

	for_each_ufs_lane(ufs, i) {
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(TX_LINERESET_P_VAL, i),
				TX_LINERESET_P(tm_parm.tx_linereset_p));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(TX_HIGH_Z_CNT_07_00, i),
				TX_HIGH_Z_CNT_L(tm_parm.tx_high_z_cnt));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(TX_HIGH_Z_CNT_11_08, i),
				TX_HIGH_Z_CNT_H(tm_parm.tx_high_z_cnt));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(TX_BASE_NVAL_07_00, i),
				TX_BASE_NVAL_L(tm_parm.tx_base_n_val));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(TX_BASE_NVAL_15_08, i),
				TX_BASE_NVAL_H(tm_parm.tx_base_n_val));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(TX_GRAN_NVAL_07_00, i),
				TX_GRAN_NVAL_L(tm_parm.tx_gran_n_val));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(TX_GRAN_NVAL_10_08, i),
				TX_GRAN_NVAL_H(tm_parm.tx_gran_n_val));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(TX_OV_SLEEP_CNT_TIMER, i),
				TX_OV_H8_ENTER_EN |
				TX_OV_SLEEP_CNT(tm_parm.tx_sleep_cnt));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(TX_MIN_ACTIVATE_TIME, i),
				0xA);
	}

	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_DBG_OV_TM), FALSE);
}

static void exynos_ufs_config_phy_cap_attr(struct exynos_ufs *ufs)
{
	struct ufs_hba *hba = ufs->hba;
	int i;

	if (ufs->hw_rev >= UFS_VER_0004)
		return;

	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_DBG_OV_TM), TRUE);

	for_each_ufs_lane(ufs, i) {
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_HS_G1_SYNC_LENGTH_CAP, i),
				SYNC_RANGE_COARSE | SYNC_LEN(0xf));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_HS_G2_SYNC_LENGTH_CAP, i),
				SYNC_RANGE_COARSE | SYNC_LEN(0xf));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_HS_G3_SYNC_LENGTH_CAP, i),
				SYNC_RANGE_COARSE | SYNC_LEN(0xf));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_HS_G1_PREP_LENGTH_CAP, i),
				PREP_LEN(0xf));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_HS_G2_PREP_LENGTH_CAP, i),
				PREP_LEN(0xf));
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(RX_HS_G3_PREP_LENGTH_CAP, i),
				PREP_LEN(0xf));
	}

	if (ufs->rx_adv_fine_gran_sup_en == 0) {
		for_each_ufs_lane(ufs, i) {
			ufshcd_dme_set(hba,
				UIC_ARG_MIB_SEL(RX_ADV_GRANULARITY_CAP, i), 0);

			ufshcd_dme_set(hba,
				UIC_ARG_MIB_SEL(TX_ADV_GRANULARITY_CAP, i), 0);

			if (ufs->rx_min_actv_time_cap)
				ufshcd_dme_set(hba,
					UIC_ARG_MIB_SEL(RX_MIN_ACTIVATETIME_CAP, i),
					ufs->rx_min_actv_time_cap);

			if (ufs->rx_hibern8_time_cap)
				ufshcd_dme_set(hba,
					UIC_ARG_MIB_SEL(RX_HIBERN8TIME_CAP, i),
					ufs->rx_hibern8_time_cap);

			if (ufs->tx_hibern8_time_cap)
				ufshcd_dme_set(hba,
					UIC_ARG_MIB_SEL(TX_HIBERN8TIME_CAP, i),
					ufs->tx_hibern8_time_cap);
		}
	} else if (ufs->rx_adv_fine_gran_sup_en == 1) {
		for_each_ufs_lane(ufs, i) {
			if (ufs->rx_adv_fine_gran_step)
				ufshcd_dme_set(hba,
					UIC_ARG_MIB_SEL(RX_ADV_GRANULARITY_CAP, i),
					RX_ADV_FINE_GRAN_STEP(ufs->rx_adv_fine_gran_step));

			if (ufs->rx_adv_min_actv_time_cap)
				ufshcd_dme_set(hba,
					UIC_ARG_MIB_SEL(RX_ADV_MIN_ACTIVATETIME_CAP, i),
					ufs->rx_adv_min_actv_time_cap);

			if (ufs->rx_adv_hibern8_time_cap)
				ufshcd_dme_set(hba,
					UIC_ARG_MIB_SEL(RX_ADV_HIBERN8TIME_CAP, i),
					ufs->rx_adv_hibern8_time_cap);
		}
	}

	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_DBG_OV_TM), FALSE);
}

static void exynos_ufs_establish_connt(struct exynos_ufs *ufs)
{
	struct ufs_hba *hba = ufs->hba;

	if (ufs->hw_rev >= UFS_VER_0004)
		return;

	/* allow cport attributes to be set */
	ufshcd_dme_set(hba, UIC_ARG_MIB(T_CONNECTIONSTATE), CPORT_IDLE);

	/* local */
	ufshcd_dme_set(hba, UIC_ARG_MIB(N_DEVICEID), DEV_ID);
	ufshcd_dme_set(hba, UIC_ARG_MIB(N_DEVICEID_VALID), TRUE);
	ufshcd_dme_set(hba, UIC_ARG_MIB(T_PEERDEVICEID), PEER_DEV_ID);
	ufshcd_dme_set(hba, UIC_ARG_MIB(T_PEERCPORTID), PEER_CPORT_ID);
	ufshcd_dme_set(hba, UIC_ARG_MIB(T_CPORTFLAGS), CPORT_DEF_FLAGS);
	ufshcd_dme_set(hba, UIC_ARG_MIB(T_TRAFFICCLASS), TRAFFIC_CLASS);
	ufshcd_dme_set(hba, UIC_ARG_MIB(T_CONNECTIONSTATE), CPORT_CONNECTED);
}

static void exynos_ufs_calib_hibern8_values(struct ufs_hba *hba)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	u32 peer_rx_min_actv_time_cap;
	u32 max_rx_hibern8_time_cap;

	/*
	 * if granularity is not configured,
	 * we assume relying on capability exchange
	 */
	if (ufs->pa_granularity) {
		ufshcd_dme_set(hba, UIC_ARG_MIB(PA_DBG_MODE), TRUE);
		ufshcd_dme_set(hba,
				UIC_ARG_MIB(PA_GRANULARITY), ufs->pa_granularity);
		ufshcd_dme_set(hba, UIC_ARG_MIB(PA_DBG_MODE), FALSE);

		if (ufs->pa_tactivate)
			ufshcd_dme_set(hba,
					UIC_ARG_MIB(PA_TACTIVATE), ufs->pa_tactivate);

		if (ufs->pa_hibern8time)
			ufshcd_dme_set(hba,
					UIC_ARG_MIB(PA_HIBERN8TIME), ufs->pa_hibern8time);
	} else {
		ufshcd_dme_get(hba, UIC_ARG_MIB(PA_TACTIVATE), &peer_rx_min_actv_time_cap);
		ufshcd_dme_get(hba, UIC_ARG_MIB(PA_HIBERN8TIME), &max_rx_hibern8_time_cap);
		if (ufs->rx_min_actv_time_cap <= peer_rx_min_actv_time_cap)
			ufshcd_dme_peer_set(hba, UIC_ARG_MIB(PA_TACTIVATE),
					peer_rx_min_actv_time_cap + 1);
		ufshcd_dme_set(hba, UIC_ARG_MIB(PA_HIBERN8TIME), max_rx_hibern8_time_cap + 1);
	}


	return;
}

static void exynos_ufs_config_smu(struct exynos_ufs *ufs)
{
	int ret;

#ifdef CONFIG_SOC_EXYNOS8890
#if defined(CONFIG_FMP_UFS)
	const u32 enabled = FMP_DESC_ON;
#else
	const u32 enabled = FMP_DESC_OFF;
#endif

	ret = exynos_smc(SMC_CMD_FMP, FMP_SECURITY, UFS_FMP, enabled);
	if (ret)
		dev_err(ufs->dev, "Fail to smc call for FMP SECURITY: %d\n", ret);
	ret = exynos_smc(SMC_CMD_SMU, FMP_SMU_INIT,
			enabled ? FMP_SMU_ON : FMP_SMU_OFF, 0);
#else
#if defined(CONFIG_FMP_UFS)
	ret = exynos_smc(SMC_CMD_FMP_SECURITY, 0, ID_FMP_UFS_MMC, FMP_DESCTYPE_3);
#else
	ret = exynos_smc(SMC_CMD_FMP_SECURITY, 0, ID_FMP_UFS_MMC, FMP_DESCTYPE_0);
#endif
	if (ret)
		dev_err(ufs->dev, "Fail to smc call for FMP SECURITY\n");

	ret = exynos_smc(SMC_CMD_SMU, FMP_SMU_INIT, ID_FMP_UFS_MMC, 0);
#endif
	if (ret)
		dev_err(ufs->dev, "Fail to smc call for FMP SMU Initialization: %d\n", ret);
}

static bool exynos_ufs_wait_pll_lock(struct exynos_ufs *ufs, u32 addr, u32 mask)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(100);
	u32 reg;

	do {
		reg = phy_pma_readl(ufs, PHY_PMA_COMN_ADDR(addr));
		if (mask == (reg & mask))
			return true;
		usleep_range(1, 1);
	} while (time_before(jiffies, timeout));

	dev_err(ufs->dev, "timeout pll lock\n");

	exynos_ufs_dump_uic_info(ufs->hba);

	return false;

}

static bool exynos_ufs_wait_cdr_lock(struct exynos_ufs *ufs, u32 addr,
					u32 mask, int lane)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(100);
	u32 reg;

	do {
		reg = phy_pma_readl(ufs, PHY_PMA_TRSV_ADDR(addr, lane));
		if (mask == (reg & mask))
			return true;
		usleep_range(1, 1);
	} while (time_before(jiffies, timeout));

	dev_err(ufs->dev, "timeout cdr lock\n");

	exynos_ufs_dump_uic_info(ufs->hba);

	return false;

}

static inline bool __match_mode_by_cfg(struct uic_pwr_mode *pmd, int mode)
{
	bool match = false;
	u8 _m, _l, _g;

	_m = pmd->mode;
	_g = pmd->gear;
	_l = pmd->lane;

	if (mode == PMD_ALL)
		match = true;
	else if (IS_PWR_MODE_HS(_m) && mode == PMD_HS)
		match = true;
	else if (IS_PWR_MODE_PWM(_m) && mode == PMD_PWM)
		match = true;
	else if (IS_PWR_MODE_HS(_m) && _g == 1 && _l == 1
			&& mode & PMD_HS_G1_L1)
			match = true;
	else if (IS_PWR_MODE_HS(_m) && _g == 1 && _l == 2
			&& mode & PMD_HS_G1_L2)
			match = true;
	else if (IS_PWR_MODE_HS(_m) && _g == 2 && _l == 1
			&& mode & PMD_HS_G2_L1)
			match = true;
	else if (IS_PWR_MODE_HS(_m) && _g == 2 && _l == 2
			&& mode & PMD_HS_G2_L2)
			match = true;
	else if (IS_PWR_MODE_HS(_m) && _g == 3 && _l == 1
			&& mode & PMD_HS_G3_L1)
			match = true;
	else if (IS_PWR_MODE_HS(_m) && _g == 3 && _l == 2
			&& mode & PMD_HS_G3_L2)
			match = true;
	else if (IS_PWR_MODE_PWM(_m) && _g == 1 && _l == 1
			&& mode & PMD_PWM_G1_L1)
			match = true;
	else if (IS_PWR_MODE_PWM(_m) && _g == 1 && _l == 2
			&& mode & PMD_PWM_G1_L2)
			match = true;
	else if (IS_PWR_MODE_PWM(_m) && _g == 2 && _l == 1
			&& mode & PMD_PWM_G2_L1)
			match = true;
	else if (IS_PWR_MODE_PWM(_m) && _g == 2 && _l == 2
			&& mode & PMD_PWM_G2_L2)
			match = true;
	else if (IS_PWR_MODE_PWM(_m) && _g == 3 && _l == 1
			&& mode & PMD_PWM_G3_L1)
			match = true;
	else if (IS_PWR_MODE_PWM(_m) && _g == 3 && _l == 2
			&& mode & PMD_PWM_G3_L2)
			match = true;
	else if (IS_PWR_MODE_PWM(_m) && _g == 4 && _l == 1
			&& mode & PMD_PWM_G4_L1)
			match = true;
	else if (IS_PWR_MODE_PWM(_m) && _g == 4 && _l == 2
			&& mode & PMD_PWM_G4_L2)
			match = true;
	else if (IS_PWR_MODE_PWM(_m) && _g == 5 && _l == 1
			&& mode & PMD_PWM_G5_L1)
			match = true;
	else if (IS_PWR_MODE_PWM(_m) && _g == 5 && _l == 2
			&& mode & PMD_PWM_G5_L2)
			match = true;

	return match;
}

static int exynos_ufs_config_uic(struct exynos_ufs *ufs,
				  const struct ufs_phy_cfg *cfg,
				  struct uic_pwr_mode *pmd)
{
	struct ufs_hba *hba = ufs->hba;
	int i;
	u32 pclk_period;

	if (!cfg)
		return 0;

	for_each_phy_cfg(cfg) {
		for_each_ufs_lane(ufs, i) {
			if (pmd && !__match_mode_by_cfg(pmd, cfg->flg))
				continue;

			switch (cfg->lyr) {
			case PHY_PCS_COMN:
			case UNIPRO_STD_MIB:
			case UNIPRO_DBG_MIB:
				if (i == 0)
					ufshcd_dme_set(hba, UIC_ARG_MIB(cfg->addr), cfg->val);
				break;
			case PHY_PCS_RXTX:
				ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(cfg->addr, i), cfg->val);
				break;
			case UNIPRO_DBG_PRD:
				if (i == 0) {
					u32 mclk_period;

					mclk_period = UNIPRO_MCLK_PERIOD(ufs);
					ufshcd_dme_set(hba, UIC_ARG_MIB(cfg->addr),mclk_period);
				}
				break;
			case PHY_PCS_RX:
				ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(cfg->addr, RX_LANE_0+i), cfg->val);
				break;
			case PHY_PCS_TX:
				ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(cfg->addr, TX_LANE_0+i), cfg->val);
				break;
			case PHY_PCS_RX_PRD:
				pclk_period = UNIPRO_PCLK_PERIOD(ufs);;
				ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(cfg->addr, RX_LANE_0+i), pclk_period);
				break;

			case PHY_PCS_TX_PRD:
				pclk_period = UNIPRO_PCLK_PERIOD(ufs);;
				ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(cfg->addr, TX_LANE_0+i), pclk_period);
				break;
			case PHY_PMA_COMN:
				if (i == 0)
					phy_pma_writel(ufs, cfg->val, PHY_PMA_COMN_ADDR(cfg->addr));
				break;
			case PHY_PMA_TRSV:
				phy_pma_writel(ufs, cfg->val, PHY_PMA_TRSV_ADDR(cfg->addr, i));
				break;
			case PHY_PMA_TRSV_LANE1_SQ_OFF:
				if (i == 1)
					phy_pma_writel(ufs, cfg->val, PHY_PMA_TRSV_ADDR(cfg->addr, i));
				break;
			case UNIPRO_DBG_APB:
				unipro_writel(ufs, cfg->val, cfg->addr);
				break;
			case PHY_PLL_WAIT:
				if (i == 0) {
					if (!exynos_ufs_wait_pll_lock(ufs, cfg->addr, cfg->val))
						return -EPERM;
				}
				break;
			case PHY_CDR_WAIT:
				if (i == 0) {
					if (!exynos_ufs_wait_cdr_lock(ufs, cfg->addr, cfg->val, i))
						return -EPERM;
				}
				break;
			case COMMON_WAIT:
				if (i == 0)
					udelay(cfg->val);
				break;
			default:
				break;
			}
		}
	}

	return 0;
}

static void exynos_ufs_config_sync_pattern_mask(struct exynos_ufs *ufs,
					struct uic_pwr_mode *pmd)
{
	struct ufs_hba *hba = ufs->hba;
	u8 g = pmd->gear;
	u32 mask, sync_len;
	int i;
#define SYNC_LEN_G1	(80 * 1000) /* 80 us */
#define SYNC_LEN_G2	(40 * 1000) /* 40 us */
#define SYNC_LEN_G3	(20 * 1000) /* 20 us */

	if (ufs->hw_rev < UFS_VER_0004)
		return;

	if (g == 1)
		sync_len = SYNC_LEN_G1;
	else if (g == 2)
		sync_len = SYNC_LEN_G2;
	else if (g == 3)
		sync_len = SYNC_LEN_G3;
	else
		return;

	mask = exynos_ufs_calc_time_cntr(ufs, sync_len);
	mask = (mask >> 8) & 0xff;

	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_DBG_OV_TM), TRUE);

	for_each_ufs_lane(ufs, i)
		ufshcd_dme_set(hba,
			UIC_ARG_MIB_SEL(RX_SYNC_MASK_LENGTH, i), mask);

	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_DBG_OV_TM), FALSE);
}

static void exynos_ufs_init_pmc_req(struct ufs_hba *hba,
		struct ufs_pa_layer_attr *pwr_max,
		struct ufs_pa_layer_attr *pwr_req)
{

	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	struct uic_pwr_mode *req_pmd = &ufs->req_pmd_parm;
	struct uic_pwr_mode *act_pmd = &ufs->act_pmd_parm;
	
	/* update lane variable after link */
	ufs->num_rx_lanes = pwr_max->lane_rx;
	ufs->num_tx_lanes = pwr_max->lane_tx;

	pwr_req->gear_rx
		= act_pmd->gear= min_t(u8, pwr_max->gear_rx, req_pmd->gear);
	pwr_req->gear_tx
		= act_pmd->gear = min_t(u8, pwr_max->gear_tx, req_pmd->gear);
	pwr_req->lane_rx
		= act_pmd->lane = min_t(u8, pwr_max->lane_rx, req_pmd->lane);
	pwr_req->lane_tx
		= act_pmd->lane = min_t(u8, pwr_max->lane_tx, req_pmd->lane);
	pwr_req->pwr_rx = act_pmd->mode = req_pmd->mode;
	pwr_req->pwr_tx = act_pmd->mode = req_pmd->mode;
	pwr_req->hs_rate = act_pmd->hs_series = req_pmd->hs_series;
	act_pmd->local_l2_timer[0] = req_pmd->local_l2_timer[0];
	act_pmd->local_l2_timer[1] = req_pmd->local_l2_timer[1];
	act_pmd->local_l2_timer[2] = req_pmd->local_l2_timer[2];

	act_pmd->remote_l2_timer[0] = req_pmd->remote_l2_timer[0];
	act_pmd->remote_l2_timer[1] = req_pmd->remote_l2_timer[1];
	act_pmd->remote_l2_timer[2] = req_pmd->remote_l2_timer[2];
}

static void exynos_ufs_set_l2_timer(struct ufs_hba *hba,
		struct uic_pwr_mode *act_pmd)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);

	if (ufs->hw_rev < UFS_VER_0004)
		return;

	ufshcd_dme_set(hba,
		UIC_ARG_MIB(DL_FC0PROTTIMEOUTVAL), act_pmd->local_l2_timer[0]);
	ufshcd_dme_set(hba,
		UIC_ARG_MIB(DL_TC0REPLAYTIMEOUTVAL), act_pmd->local_l2_timer[1]);
	ufshcd_dme_set(hba,
		UIC_ARG_MIB(DL_AFC0REQTIMEOUTVAL), act_pmd->local_l2_timer[2]);
	ufshcd_dme_set(hba,
		UIC_ARG_MIB(PA_PWRMODEUSERDATA0), act_pmd->remote_l2_timer[0]);
	ufshcd_dme_set(hba,
		UIC_ARG_MIB(PA_PWRMODEUSERDATA1), act_pmd->remote_l2_timer[1]);
	ufshcd_dme_set(hba,
		UIC_ARG_MIB(PA_PWRMODEUSERDATA2), act_pmd->remote_l2_timer[2]);

	unipro_writel(ufs, act_pmd->local_l2_timer[0], UNIP_DME_PWR_REQ_LOCALL2TIMER0);
	unipro_writel(ufs, act_pmd->local_l2_timer[1], UNIP_DME_PWR_REQ_LOCALL2TIMER1);
	unipro_writel(ufs, act_pmd->local_l2_timer[2], UNIP_DME_PWR_REQ_LOCALL2TIMER2);
	unipro_writel(ufs, act_pmd->remote_l2_timer[0], UNIP_DME_PWR_REQ_REMOTEL2TIMER0);
	unipro_writel(ufs, act_pmd->remote_l2_timer[1], UNIP_DME_PWR_REQ_REMOTEL2TIMER1);
	unipro_writel(ufs, act_pmd->remote_l2_timer[2], UNIP_DME_PWR_REQ_REMOTEL2TIMER2);
}

static void exynos_ufs_set_pmc_req(struct exynos_ufs *ufs,
		struct uic_pwr_mode *act_pmd,
		enum ufs_notify_change_status status)
{
	const struct exynos_ufs_soc *soc = to_phy_soc(ufs);
	struct ufs_phy_cfg *tbl = NULL;
	bool need_cfg_sync_pattern_mask = false;

	if (!soc)
		return;

	if (IS_PWR_MODE_HS(act_pmd->mode)) {
		switch (act_pmd->hs_series) {
		case PA_HS_MODE_A:
			tbl = (status == PRE_CHANGE) ?
				soc->tbl_calib_of_hs_rate_a :
				soc->tbl_post_calib_of_hs_rate_a;
			need_cfg_sync_pattern_mask = true;
			break;
		case PA_HS_MODE_B:
			tbl = (status == PRE_CHANGE) ?
				soc->tbl_calib_of_hs_rate_b :
				soc->tbl_post_calib_of_hs_rate_b;
			break;
		default:
			break;
		}
	} else if (IS_PWR_MODE_PWM(act_pmd->mode)) {
		tbl = (status == PRE_CHANGE) ? soc->tbl_calib_of_pwm :
						soc->tbl_post_calib_of_pwm;
	}


	/*
	 * actual configurations
	 */
	if (need_cfg_sync_pattern_mask)
		exynos_ufs_config_sync_pattern_mask(ufs, act_pmd);

	exynos_ufs_config_uic(ufs, tbl, act_pmd);

	return;
}

static void exynos_ufs_phy_init(struct exynos_ufs *ufs)
{
	struct ufs_hba *hba = ufs->hba;
	const struct exynos_ufs_soc *soc = to_phy_soc(ufs);

	if (ufs->num_rx_lanes == 0 || ufs->num_tx_lanes == 0) {
		ufshcd_dme_get(hba, UIC_ARG_MIB(PA_AVAILRXDATALANES),
			&ufs->num_rx_lanes);
		ufshcd_dme_get(hba, UIC_ARG_MIB(PA_AVAILTXDATALANES),
			&ufs->num_tx_lanes);
		WARN(ufs->num_rx_lanes != ufs->num_tx_lanes,
			"available data lane is not equal(rx:%d, tx:%d)\n",
			ufs->num_rx_lanes, ufs->num_tx_lanes);
	}

	if (!soc)
		return;

	exynos_ufs_config_uic(ufs, soc->tbl_phy_init, NULL);
}

static int exynos_ufs_phy_lane1_sqoff(struct ufs_hba *hba)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	const struct exynos_ufs_soc *soc = to_phy_soc(ufs);

	if (soc) {
		ufs->lane1_poweroff = true;
		exynos_ufs_config_uic(ufs, soc->tbl_lane1_sq_off, NULL);
	}
	return 0;
}

static void exynos_ufs_config_unipro(struct exynos_ufs *ufs)
{
	struct ufs_hba *hba = ufs->hba;

	if (ufs->hw_rev >= UFS_VER_0004)
		return;

	unipro_writel(ufs, 0x1, UNIP_DME_PACP_CNFBIT);

	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_DBG_CLK_PERIOD),
		DIV_ROUND_UP(NSEC_PER_SEC, ufs->mclk_rate));
	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_TXTRAILINGCLOCKS), TXTRAILINGCLOCKS);
}

static void exynos_ufs_config_intr(struct exynos_ufs *ufs, u32 errs, u8 index)
{
	switch(index) {
	case UNIP_PA_LYR:
		hci_writel(ufs, DFES_ERR_EN | errs, HCI_ERROR_EN_PA_LAYER);
		break;
	case UNIP_DL_LYR:
		hci_writel(ufs, DFES_ERR_EN | errs, HCI_ERROR_EN_DL_LAYER);
		break;
	case UNIP_N_LYR:
		hci_writel(ufs, DFES_ERR_EN | errs, HCI_ERROR_EN_N_LAYER);
		break;
	case UNIP_T_LYR:
		hci_writel(ufs, DFES_ERR_EN | errs, HCI_ERROR_EN_T_LAYER);
		break;
	case UNIP_DME_LYR:
		hci_writel(ufs, DFES_ERR_EN | errs, HCI_ERROR_EN_DME_LAYER);
		break;
	}
}

static int exynos_ufs_line_rest_ctrl(struct exynos_ufs *ufs)
{
	struct ufs_hba *hba = ufs->hba;
	u32 val;
	int i;

	if (ufs->hw_rev != UFS_VER_0003)
		return 0;

	ufshcd_dme_set(hba, UIC_ARG_MIB(0x9565), 0xf);
	ufshcd_dme_set(hba, UIC_ARG_MIB(0x9565), 0xf);
	for_each_ufs_lane(ufs, i)
		ufshcd_dme_set(hba, UIC_ARG_MIB_SEL(0x2b, i), 0x0);
	ufshcd_dme_set(hba, UIC_ARG_MIB(0x9518), 0x1);
	udelay(1);
	ufshcd_dme_get(hba, UIC_ARG_MIB(0x9564), &val);
	ufshcd_dme_set(hba, UIC_ARG_MIB(0x9564), val | (1 << 12));
	ufshcd_dme_set(hba, UIC_ARG_MIB(0x9539), 0x1);
	ufshcd_dme_set(hba, UIC_ARG_MIB(0x9541), 0x1);
	ufshcd_dme_set(hba, UIC_ARG_MIB(0x9543), 0x1);
	udelay(1600);
	ufshcd_dme_get(hba, UIC_ARG_MIB(0x9564), &val);
	ufshcd_dme_set(hba, UIC_ARG_MIB(0x9564), val & ~(1 << 12));

	return 0;
}

static void exynos_ufs_dev_hw_reset(struct ufs_hba *hba)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);

	/* bit[1] for resetn */
	hci_writel(ufs, 0 << 0, HCI_GPIO_OUT);
	udelay(5);
	hci_writel(ufs, 1 << 0, HCI_GPIO_OUT);
}

static void exynos_ufs_init_host(struct exynos_ufs *ufs)
{
	u32 reg;

	/* internal clock control */
	exynos_ufs_ctrl_auto_hci_clk(ufs, false);
	exynos_ufs_set_unipro_pclk(ufs);
	exynos_ufs_set_unipro_mclk(ufs);

	/* period for interrupt aggregation */
	exynos_ufs_fit_aggr_timeout(ufs);

	/* misc HCI configurations */
	hci_writel(ufs, 0xA, HCI_DATA_REORDER);
	hci_writel(ufs, PRDT_PREFECT_EN | PRDT_SET_SIZE(12),
			HCI_TXPRDT_ENTRY_SIZE);
	hci_writel(ufs, PRDT_SET_SIZE(12), HCI_RXPRDT_ENTRY_SIZE);
	hci_writel(ufs, 0xFFFFFFFF, HCI_UTRL_NEXUS_TYPE);
	hci_writel(ufs, 0xFFFFFFFF, HCI_UTMRL_NEXUS_TYPE);

	if (ufs->hw_rev >= UFS_VER_0004) {
		reg = hci_readl(ufs, HCI_AXIDMA_RWDATA_BURST_LEN) &
			~BURST_LEN(0);
		hci_writel(ufs, WLU_EN | BURST_LEN(3),
					HCI_AXIDMA_RWDATA_BURST_LEN);
	} else {
		hci_writel(ufs, AXIDMA_RWDATA_BURST_LEN,
					HCI_AXIDMA_RWDATA_BURST_LEN);
	}

#if !defined(CONFIG_SOC_EXYNOS7420) && !defined(CONFIG_SOC_EXYNOS8890)
	/*
	 * Enable HWAGC control by IOP
	 *
	 * default value 1->0 at KC.
	 * always "0"(controlled by UFS_ACG_DISABLE)
	 */
	reg = hci_readl(ufs, HCI_IOP_ACG_DISABLE);
	hci_writel(ufs, reg & (~HCI_IOP_ACG_DISABLE_EN), HCI_IOP_ACG_DISABLE);
#endif
}

static void exynos_ufs_pre_hibern8(struct ufs_hba *hba, u8 enter)
{
}

static void exynos_ufs_post_hibern8(struct ufs_hba *hba, u8 enter)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);

	if (!enter) {
		struct uic_pwr_mode *act_pmd = &ufs->act_pmd_parm;
		u32 mode = 0;

		ufshcd_dme_get(hba, UIC_ARG_MIB(PA_PWRMODE), &mode);
		if (mode != (act_pmd->mode << 4 | act_pmd->mode)) {
			dev_warn(hba->dev, "%s: power mode not matched, mode : 0x%x, act_mode : 0x%x\n",
					__func__, mode, act_pmd->mode);
			hba->pwr_info.pwr_rx = (mode >> 4) & 0xf;
			hba->pwr_info.pwr_tx = mode & 0xf;
			ufshcd_config_pwr_mode(hba, &hba->max_pwr_info.info);
		}

		if (!(ufs->opts & EXYNOS_UFS_OPTS_SKIP_CONNECTION_ESTAB))
			exynos_ufs_establish_connt(ufs);
	}
}

static void exynos_ufs_modify_sysreg(struct exynos_ufs *ufs, int index)
{
	struct exynos_ufs_sys *sys = &ufs->sys;
	void __iomem *reg_sys = sys->reg_sys[index];
	const char *const name[NUM_OF_SYSREG] = {
		"ufs-io-coherency",
		"ufs-tcxo-sel",
	};
	u32 reg;

	if (!of_get_child_by_name(ufs->dev->of_node, name[index]))
		return;

	reg = readl(reg_sys);
	writel((reg & ~(sys->mask[index])) | sys->bits[index], reg_sys);
}

static int exynos_ufs_init_system(struct exynos_ufs *ufs)
{
	struct device *dev = ufs->dev;
	struct clk *c, *p;
	int ret = 0;

#if !defined(CONFIG_SOC_EXYNOS7420) && !defined(CONFIG_SOC_EXYNOS8890)
	u32 val;

	/* Getting the soc revision*/
	val = exynos_soc_info.revision;

        /* From  EVT ver1.1 */
        if (val >= 0x11)
                regmap_update_bits(ufs->pmureg, 0x0620, 0x1, 1);
#endif

	/* The 8890 has a separate UniPro configuration clock. */
	if (ufs->hw_rev == UFS_VER_0003 &&
	    !(ufs->opts & EXYNOS_UFS_OPTS_USE_SEPERATED_PCLK)) {
		const char *const clks[] = {
			"mout_sclk_combo_phy_embedded", "top_sclk_phy_fsys1_26m",
		};

		c = devm_clk_get(dev, clks[0]);
		if (IS_ERR(c)) {
			dev_err(dev, "failed to get clock %s\n", clks[0]);
			return -EINVAL;
		}

		p = devm_clk_get(dev, clks[1]);
		if (IS_ERR(p)) {
			dev_err(dev, "failed to get clock %s\n", clks[1]);
			return -EINVAL;
		}

		ret = clk_set_parent(c, p);
	}

	/* PHY isolation bypass */
	exynos_ufs_ctrl_phy_pwr(ufs, true);

	/* IO cohernecy */
	if (!of_get_child_by_name(dev->of_node, "ufs-io-coherency")) {
		dev_err(dev, "Not configured to use IO coherency\n");
	} else {
		if (!of_find_property(dev->of_node, "dma-coherent", NULL))
			BUG();

		exynos_ufs_modify_sysreg(ufs, 0);
	}

	/* Ref clk selection, tcxo */
	exynos_ufs_modify_sysreg(ufs, 1);

	return ret;
}

static int exynos_ufs_get_clks(struct ufs_hba *hba)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	struct list_head *head = &hba->clk_list_head;
	struct ufs_clk_info *clki;

	ufs_host_backup[ufs_host_index++] = ufs;
	ufs->debug.std_sfr = ufs_log_std_sfr;

	if (!head || list_empty(head))
		goto out;

	list_for_each_entry(clki, head, list) {
		if (!IS_ERR_OR_NULL(clki->clk)) {
			if (!strcmp(clki->name, "GATE_UFS_EMBD"))
				ufs->clk_hci = clki->clk;
			if (!strcmp(clki->name, "UFS_EMBD")) {
				ufs->clk_unipro = clki->clk;
				ufs->pclk = clki->clk;
			}

			if (!strcmp(clki->name, "aclk_ufs"))
				ufs->clk_hci = clki->clk;
			if (!strcmp(clki->name, "sclk_ufsunipro"))
				ufs->clk_unipro = clki->clk;

			if (ufs->hw_rev == UFS_VER_0003 &&
			    !(ufs->opts & EXYNOS_UFS_OPTS_USE_SEPERATED_PCLK)) {
				if (!strcmp(clki->name, "aclk_ufs"))
					ufs->pclk = clki->clk;
			} else {
				if (!strcmp(clki->name, "sclk_ufsunipro20_cfg"))
					ufs->pclk = clki->clk;
			}
		}
	}
out:
	if (!ufs->clk_hci || !ufs->clk_unipro)
		return -EINVAL;

	return 0;
}

static void exynos_ufs_set_features(struct ufs_hba *hba, u32 hw_rev)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);

	/* caps */
	hba->caps = UFSHCD_CAP_CLK_GATING |
			UFSHCD_CAP_HIBERN8_WITH_CLK_GATING |
			UFSHCD_CAP_INTR_AGGR;

	/* quirks of common driver */
	hba->quirks = UFSHCD_QUIRK_BROKEN_DWORD_UTRD |
			UFSHCI_QUIRK_SKIP_INTR_AGGR |
			UFSHCD_QUIRK_BROKEN_REQ_LIST_CLR;

	if (hw_rev == UFS_VER_0003)
		hba->quirks |= UFSHCD_QUIRK_USE_OF_HCE;

	if (hw_rev == UFS_VER_0004)
		hba->quirks |= UFSHCD_QUIRK_GET_UPMCRS_DIRECT |
			UFSHCD_QUIRK_GET_GENERRCODE_DIRECT;

	/* quirks of exynos-specific driver */
	if (hw_rev < UFS_VER_0004)
		ufs->opts |= EXYNOS_UFS_OPTS_SKIP_CONNECTION_ESTAB;
}

/*
 * Exynos-specific callback functions
 *
 * init			| Pure SW init & system-related init
 * host_reset		| Host SW reset & init
 * pre_setup_clocks	| specific power down
 * setup_clocks		| specific power up
 * ...
 *
 * Initializations for software, host controller and system
 * should be contained only in ->host_reset() as possible.
 */

static int exynos_ufs_init(struct ufs_hba *hba)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	int ret;

	/* set features, such as caps or quirks */
	exynos_ufs_set_features(hba, ufs->hw_rev);

	/* get some clock sources and debug infomation structures */
	ret = exynos_ufs_get_clks(hba);
	if (ret)
		return ret;

	/* system init */
	ret = exynos_ufs_init_system(ufs);
	if (ret)
		return ret;

	/* SMU */
	exynos_ufs_config_smu(ufs);

	/* Enable log */
	ret =  exynos_ufs_init_dbg(hba);

	if (ret)
		return ret;

	ufs->misc_flags = EXYNOS_UFS_MISC_TOGGLE_LOG;

	return 0;
}

static void exynos_ufs_host_reset(struct ufs_hba *hba)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	unsigned long timeout = jiffies + msecs_to_jiffies(1);

	exynos_ufs_ctrl_auto_hci_clk(ufs, false);

	hci_writel(ufs, UFS_SW_RST_MASK, HCI_SW_RST);

	do {
		if (!(hci_readl(ufs, HCI_SW_RST) & UFS_SW_RST_MASK))
			goto success;
	} while (time_before(jiffies, timeout));

	dev_err(ufs->dev, "timeout host sw-reset\n");

	exynos_ufs_dump_uic_info(hba);

	goto out;

success:
	/* host init */
	exynos_ufs_init_host(ufs);

	/* device reset */
	exynos_ufs_dev_hw_reset(hba);

	/* secure log */
	exynos_smc(SMC_CMD_LOG, 0, 0, 2);
out:
	return;
}

static inline void exynos_ufs_dev_reset_ctrl(struct exynos_ufs *ufs, bool en)
{

	if (en)
		hci_writel(ufs, 1 << 0, HCI_GPIO_OUT);
	else
		hci_writel(ufs, 0 << 0, HCI_GPIO_OUT);
}

static int exynos_ufs_pre_setup_clocks(struct ufs_hba *hba, bool on)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	const struct exynos_ufs_soc *soc = to_phy_soc(ufs);

	if (on) {
#ifdef CONFIG_CPU_IDLE
		exynos_update_ip_idle_status(ufs->idle_ip_index, 0);
#endif
		/*
		 * Now all used blocks would not be turned off in a host.
		 */
		exynos_ufs_ctrl_auto_hci_clk(ufs, false);
		exynos_ufs_gate_clk(ufs, false);

		/* HWAGC disable */
		exynos_ufs_set_hwacg_control(ufs, false);
	} else {
		pm_qos_update_request(&ufs->pm_qos_int, 0);

		/*
		 * BG/SQ off
		 */
		exynos_ufs_config_uic(ufs, soc->tbl_pre_clk_off, NULL);
	}

	return 0;
}

static int exynos_ufs_setup_clocks(struct ufs_hba *hba, bool on)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	const struct exynos_ufs_soc *soc = to_phy_soc(ufs);

	if (on) {
		/*
		 * BG/SQ on
		 */
		exynos_ufs_config_uic(ufs, soc->tbl_post_clk_on, NULL);

		pm_qos_update_request(&ufs->pm_qos_int, ufs->pm_qos_int_value);

	} else {
		/*
		 * Now all used blocks would be turned off in a host.
		 */
		exynos_ufs_gate_clk(ufs, true);
		exynos_ufs_ctrl_auto_hci_clk(ufs, true);

		/* HWAGC enable */
		exynos_ufs_set_hwacg_control(ufs, true);

#ifdef CONFIG_CPU_IDLE
		exynos_update_ip_idle_status(ufs->idle_ip_index, 1);
#endif
	}

	return 0;
}

static int exynos_ufs_link_startup_notify(struct ufs_hba *hba,
					enum ufs_notify_change_status status)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	int ret = 0;
	const struct exynos_ufs_soc *soc = to_phy_soc(ufs);

	switch (status) {
	case PRE_CHANGE:
		/* refer to hba */
		ufs->hba = hba;

		/* hci */
		exynos_ufs_config_intr(ufs, DFES_DEF_DL_ERRS, UNIP_DL_LYR);
		exynos_ufs_config_intr(ufs, DFES_DEF_N_ERRS, UNIP_N_LYR);
		exynos_ufs_config_intr(ufs, DFES_DEF_T_ERRS, UNIP_T_LYR);

		exynos_ufs_ctrl_clk(ufs, true);
#if defined(CONFIG_SOC_EMULATOR8895)
		exynos_ufs_select_refclk(ufs, false);
#else
		exynos_ufs_select_refclk(ufs, true);
#endif
		exynos_ufs_gate_clk(ufs, false);
		exynos_ufs_set_hwacg_control(ufs, false);

		/* mphy */
		exynos_ufs_phy_init(ufs);

		/* unipro */
		exynos_ufs_config_unipro(ufs);

		/* mphy */
		exynos_ufs_config_phy_time_v(ufs);
		exynos_ufs_config_phy_cap_attr(ufs);

		/* line reset w/a */
		exynos_ufs_line_rest_ctrl(ufs);

		exynos_ufs_set_line_init_prep_len(ufs);
		break;
	case POST_CHANGE:
		exynos_ufs_establish_connt(ufs);

		if (ufs->opts & EXYNOS_UFS_OPTS_SKIP_CONNECTION_ESTAB)
			ufshcd_dme_set(hba,
					UIC_ARG_MIB(T_DBG_SKIP_INIT_HIBERN8_EXIT), TRUE);

		/*
		 * set h8 attrs as pre-defined values or
		 * exchanged values from remote
		 */
		exynos_ufs_calib_hibern8_values(hba);

		/* UIC configuration table after link startup */
		if (soc)
			exynos_ufs_config_uic(ufs, soc->tbl_post_phy_init, NULL);
		break;
	default:
		break;
	}

	return ret;
}

static int exynos_ufs_pwr_change_notify(struct ufs_hba *hba,
					enum ufs_notify_change_status status,
					struct ufs_pa_layer_attr *pwr_max,
					struct ufs_pa_layer_attr *pwr_req)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	struct uic_pwr_mode *act_pmd = &ufs->act_pmd_parm;
	int ret = 0;

	switch (status) {
	case PRE_CHANGE:
		if (ufs->hw_rev >= UFS_VER_0004) {
			if ((pwr_max->lane_rx == 1) && (pwr_max->peer_available_lane_tx == 1))
				exynos_ufs_phy_lane1_sqoff(hba);
		}
		/* Set PMC parameters to be requested */
		exynos_ufs_init_pmc_req(hba, pwr_max, pwr_req);

		/* Set L2 timer */
		exynos_ufs_set_l2_timer(hba, act_pmd);

		/* UIC configuration table before power mode change */
		exynos_ufs_set_pmc_req(ufs, act_pmd, status);

		break;
	case POST_CHANGE:
		/* UIC configuration table after power mode change */
		exynos_ufs_set_pmc_req(ufs, act_pmd, status);

		dev_info(ufs->dev,
				"Power mode change(%d): M(%d)G(%d)L(%d)HS-series(%d)\n",
				ret, act_pmd->mode, act_pmd->gear,
				act_pmd->lane, act_pmd->hs_series);
		break;
	default:
		break;
	}

	return ret;
}

static void exynos_ufs_set_nexus_t_xfer_req(struct ufs_hba *hba,
				int tag, struct scsi_cmnd *cmd)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	u32 type;

	type =  hci_readl(ufs, HCI_UTRL_NEXUS_TYPE);

	if (cmd)
		type |= (1 << tag);
	else
		type &= ~(1 << tag);

	hci_writel(ufs, type, HCI_UTRL_NEXUS_TYPE);
}

static void exynos_ufs_set_nexus_t_task_mgmt(struct ufs_hba *hba, int tag, u8 tm_func)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	u32 type;

	type =  hci_readl(ufs, HCI_UTMRL_NEXUS_TYPE);

	switch (tm_func) {
	case UFS_ABORT_TASK:
	case UFS_QUERY_TASK:
		type |= (1 << tag);
		break;
	case UFS_ABORT_TASK_SET:
	case UFS_CLEAR_TASK_SET:
	case UFS_LOGICAL_RESET:
	case UFS_QUERY_TASK_SET:
		type &= ~(1 << tag);
		break;
	}

	hci_writel(ufs, type, HCI_UTMRL_NEXUS_TYPE);
}

static void exynos_ufs_hibern8_notify(struct ufs_hba *hba,
				u8 enter, int notify)
{
	int noti = (int) notify;

	switch (noti) {
	case PRE_CHANGE:
		exynos_ufs_pre_hibern8(hba, enter);
		break;
	case POST_CHANGE:
		exynos_ufs_post_hibern8(hba, enter);
		break;
	default:
		break;
	}
}

static int __exynos_ufs_suspend(struct ufs_hba *hba, enum ufs_pm_op pm_op)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);

	pm_qos_update_request(&ufs->pm_qos_int, 0);

	exynos_ufs_dev_reset_ctrl(ufs, false);

	exynos_ufs_ctrl_phy_pwr(ufs, false);

	return 0;
}

static int __exynos_ufs_resume(struct ufs_hba *hba, enum ufs_pm_op pm_op)
{
	struct exynos_ufs *ufs = to_exynos_ufs(hba);
	int ret = 0;

	exynos_ufs_ctrl_phy_pwr(ufs, true);

	/* system init */
	ret = exynos_ufs_init_system(ufs);
	if (ret)
		return ret;

	if (ufshcd_is_clkgating_allowed(hba))
		clk_prepare_enable(ufs->clk_hci);
	exynos_ufs_ctrl_auto_hci_clk(ufs, false);
	exynos_ufs_config_smu(ufs);
#if defined(CONFIG_FMP_UFS)
#ifdef CONFIG_SOC_EXYNOS8890
	ret = exynos_smc(SMC_CMD_RESUME, 0, UFS_FMP, FMP_DESC_ON);
#else
	ret = exynos_smc(SMC_CMD_FMP_RESUME, 0, ID_FMP_UFS_MMC, 0);
#endif
	if (ret)
		dev_warn(ufs->dev, "failed to smc call for FMP: %x\n", ret);
#endif
#ifndef CONFIG_SOC_EXYNOS8890
	/* secure log */
	exynos_smc(SMC_CMD_LOG, 0, 0, 2);
#endif

	if (ufshcd_is_clkgating_allowed(hba))
		clk_disable_unprepare(ufs->clk_hci);

	return 0;
}

static u8 exynos_ufs_get_unipro_direct(struct ufs_hba *hba, int num)
{
	u32 offset[] = {
		UNIP_DME_LINKSTARTUP_CNF_RESULT,
		UNIP_DME_HIBERN8_ENTER_CNF_RESULT,
		UNIP_DME_HIBERN8_EXIT_CNF_RESULT,
		UNIP_DME_PWR_IND_RESULT,
		UNIP_DME_HIBERN8_ENTER_IND_RESULT,
		UNIP_DME_HIBERN8_EXIT_IND_RESULT
	};

	struct exynos_ufs *ufs = to_exynos_ufs(hba);

	return unipro_readl(ufs, offset[num]);
}

static struct ufs_hba_variant_ops exynos_ufs_ops = {
	.init = exynos_ufs_init,
	.host_reset = exynos_ufs_host_reset,
	.pre_setup_clocks = exynos_ufs_pre_setup_clocks,
	.setup_clocks = exynos_ufs_setup_clocks,
	.link_startup_notify = exynos_ufs_link_startup_notify,
	.pwr_change_notify = exynos_ufs_pwr_change_notify,
	.set_nexus_t_xfer_req = exynos_ufs_set_nexus_t_xfer_req,
	.set_nexus_t_task_mgmt = exynos_ufs_set_nexus_t_task_mgmt,
	.hibern8_notify = exynos_ufs_hibern8_notify,
	.dbg_register_dump = exynos_ufs_dump_debug_info,
	.suspend = __exynos_ufs_suspend,
	.resume = __exynos_ufs_resume,
	.get_unipro_result = exynos_ufs_get_unipro_direct,
};

static int exynos_ufs_populate_dt_sys_per_feature(struct device *dev,
				struct exynos_ufs *ufs,	int index)
{
	struct device_node *np;
	struct exynos_ufs_sys *sys = &ufs->sys;
	struct resource io_res;
	int ret;
	const char *const name[NUM_OF_SYSREG] = {
		"ufs-io-coherency",
		"ufs-tcxo-sel",
	};

	np = of_get_child_by_name(dev->of_node, name[index]);
	if (!np) {
		/* Per-feature system controls are optional. */
		return 0;
	}

	ret = of_address_to_resource(np, 0, &io_res);
	if (ret) {
		dev_err(dev, "failed to get i/o address %s\n", name[index]);
		if (ret == -EINVAL)
			ret = 0;
	} else {
		sys->reg_sys[index] = devm_ioremap_resource(dev, &io_res);
		if (IS_ERR(sys->reg_sys[index])) {
			dev_err(dev, "failed to ioremap sysreg\n");
			ret = -ENOMEM;
		} else {
			ret = of_property_read_u32(np, "mask",
						&sys->mask[index]);
			ret = of_property_read_u32(np, "bits",
						&sys->bits[index]);
			if (ret)
				ret = -EINVAL;
		}
	}

	of_node_put(np);

	return ret;
}

static int exynos_ufs_populate_dt_sys(struct device *dev, struct exynos_ufs *ufs)
{
	int i = 0;
	int ret;

	for (i = 0 ; i < NUM_OF_SYSREG ; i++) {
		ret = exynos_ufs_populate_dt_sys_per_feature(dev, ufs, i);
		if (ret && ret != -ENODEV)
			break;
	}

	return ret;
}

static int exynos_ufs_populate_dt_phy(struct device *dev, struct exynos_ufs *ufs)
{
	struct device_node *ufs_phy, *phy_sys;
	struct exynos_ufs_phy *phy = &ufs->phy;
	struct resource io_res;
	int ret;

	ufs_phy = of_get_child_by_name(dev->of_node, "ufs-phy");
	if (!ufs_phy) {
		dev_err(dev, "failed to get ufs-phy node\n");
		return -ENODEV;
	}

	ret = of_address_to_resource(ufs_phy, 0, &io_res);
	if (ret) {
		dev_err(dev, "failed to get i/o address phy pma\n");
		goto err_0;
	}

	phy->reg_pma = devm_ioremap_resource(dev, &io_res);
	if (!phy->reg_pma) {
		dev_err(dev, "failed to ioremap for phy pma\n");
		ret = -ENOMEM;
		goto err_0;
	}

	phy_sys = of_get_child_by_name(ufs_phy, "ufs-phy-sys");
	if (!phy_sys) {
		dev_err(dev, "failed to get ufs-phy-sys node\n");
		ret = -ENODEV;
		goto err_0;
	}

	ret = of_address_to_resource(phy_sys, 0, &io_res);
	if (ret) {
		dev_err(dev, "failed to get i/o address ufs-phy pmu\n");
		goto err_1;
	}

	phy->reg_pmu = devm_ioremap_resource(dev, &io_res);
	if (!phy->reg_pmu) {
		dev_err(dev, "failed to ioremap for ufs-phy pmu\n");
		ret = -ENOMEM;
	}

	if (exynos_ufs_populate_dt_phy_cfg(dev, &(phy->soc)))
		phy->soc = &exynos_ufs_soc_data;

err_1:
	of_node_put(phy_sys);
err_0:
	of_node_put(ufs_phy);

	return ret;
}

static int exynos_ufs_get_pwr_mode(struct device_node *np,
				struct exynos_ufs *ufs)
{
	struct uic_pwr_mode *pmd = &ufs->req_pmd_parm;
	const char *str = NULL;

	if (!of_property_read_string(np, "ufs,pmd-attr-mode", &str)) {
		if (!strncmp(str, "FAST", sizeof("FAST")))
			pmd->mode = FAST_MODE;
		else if (!strncmp(str, "SLOW", sizeof("SLOW")))
			pmd->mode = SLOW_MODE;
		else if (!strncmp(str, "FAST_auto", sizeof("FAST_auto")))
			pmd->mode = FASTAUTO_MODE;
		else if (!strncmp(str, "SLOW_auto", sizeof("SLOW_auto")))
			pmd->mode = SLOWAUTO_MODE;
		else
			pmd->mode = FAST_MODE;
	} else {
		pmd->mode = FAST_MODE;
	}

	if (of_property_read_u8(np, "ufs,pmd-attr-lane", &pmd->lane))
		pmd->lane = 1;

	if (of_property_read_u8(np, "ufs,pmd-attr-gear", &pmd->gear))
		pmd->gear = 1;

	if (IS_PWR_MODE_HS(pmd->mode)) {
		if (!of_property_read_string(np, "ufs,pmd-attr-hs-series", &str)) {
			if (!strncmp(str, "HS_rate_b", sizeof("HS_rate_b")))
				pmd->hs_series = PA_HS_MODE_B;
			else if (!strncmp(str, "HS_rate_a", sizeof("HS_rate_a")))
				pmd->hs_series = PA_HS_MODE_A;
			else
				pmd->hs_series = PA_HS_MODE_A;
		} else {
			pmd->hs_series = PA_HS_MODE_A;
		}
	}

	if (of_property_read_u32_array(
		np, "ufs,pmd-local-l2-timer", pmd->local_l2_timer, 3)) {
		pmd->local_l2_timer[0] = FC0PROTTIMEOUTVAL;
		pmd->local_l2_timer[1] = TC0REPLAYTIMEOUTVAL;
		pmd->local_l2_timer[2] = AFC0REQTIMEOUTVAL;
	}

	if (of_property_read_u32_array(
		np, "ufs,pmd-remote-l2-timer", pmd->remote_l2_timer, 3)) {
		pmd->remote_l2_timer[0] = FC0PROTTIMEOUTVAL;
		pmd->remote_l2_timer[1] = TC0REPLAYTIMEOUTVAL;
		pmd->remote_l2_timer[2] = AFC0REQTIMEOUTVAL;
	}

	return 0;
}

static int exynos_ufs_populate_dt(struct device *dev, struct exynos_ufs *ufs)
{
	struct device_node *np = dev->of_node;
	u32 freq[2];
	int ret;

	/* Get exynos-specific version for featuring */
	if (of_property_read_u32(np, "hw-rev", &ufs->hw_rev))
		ufs->hw_rev = UFS_VER_0003;

	ret = exynos_ufs_populate_dt_phy(dev, ufs);
	if (ret) {
		dev_err(dev, "failed to populate dt-phy\n");
		goto out;
	}

	ret = exynos_ufs_populate_dt_sys(dev, ufs);
	if (ret)
		dev_err(dev, "failed to populate ufs-sys\n");

	ret = of_property_read_u32_array(np,
			"pclk-freq-avail-range",freq, ARRAY_SIZE(freq));
	if (!ret) {
		ufs->pclk_avail_min = freq[0];
		ufs->pclk_avail_max = freq[1];
	} else {
		dev_err(dev, "faild to get available pclk range\n");
		goto out;
	}

	exynos_ufs_get_pwr_mode(np, ufs);

	if (of_find_property(np, "ufs-opts-skip-connection-estab", NULL))
		ufs->opts |= EXYNOS_UFS_OPTS_SKIP_CONNECTION_ESTAB;

	if (of_property_read_bool(np, "ufs-opts-use-seperated-pclk"))
		ufs->opts |= EXYNOS_UFS_OPTS_USE_SEPERATED_PCLK;

	if (of_find_property(np, "ufs-opts-set-line-init-prep-len", NULL))
		ufs->opts |= EXYNOS_UFS_OPTS_SET_LINE_INIT_PREP_LEN;

	if (!of_property_read_u32(np, "ufs-rx-adv-fine-gran-sup_en",
				&ufs->rx_adv_fine_gran_sup_en)) {
		if (ufs->rx_adv_fine_gran_sup_en == 0) {
			/* 100us step */
			if (of_property_read_u32(np,
					"ufs-rx-min-activate-time-cap",
					&ufs->rx_min_actv_time_cap))
				dev_warn(dev,
					"ufs-rx-min-activate-time-cap is empty\n");

			if (of_property_read_u32(np,
					"ufs-rx-hibern8-time-cap",
					&ufs->rx_hibern8_time_cap))
				dev_warn(dev,
					"ufs-rx-hibern8-time-cap is empty\n");

			if (of_property_read_u32(np,
					"ufs-tx-hibern8-time-cap",
					&ufs->tx_hibern8_time_cap))
				dev_warn(dev,
					"ufs-tx-hibern8-time-cap is empty\n");
		} else if (ufs->rx_adv_fine_gran_sup_en == 1) {
			/* fine granularity step */
			if (of_property_read_u32(np,
					"ufs-rx-adv-fine-gran-step",
					&ufs->rx_adv_fine_gran_step))
				dev_warn(dev,
					"ufs-rx-adv-fine-gran-step is empty\n");

			if (of_property_read_u32(np,
					"ufs-rx-adv-min-activate-time-cap",
					&ufs->rx_adv_min_actv_time_cap))
				dev_warn(dev,
					"ufs-rx-adv-min-activate-time-cap is empty\n");

			if (of_property_read_u32(np,
					"ufs-rx-adv-hibern8-time-cap",
					&ufs->rx_adv_hibern8_time_cap))
				dev_warn(dev,
					"ufs-rx-adv-hibern8-time-cap is empty\n");
		} else {
			dev_warn(dev,
				"not supported val for ufs-rx-adv-fine-gran-sup_en %d\n",
				ufs->rx_adv_fine_gran_sup_en);
		}
	} else {
		ufs->rx_adv_fine_gran_sup_en = 0xf;
	}

	if (!of_property_read_u32(np,
				"ufs-pa-granularity", &ufs->pa_granularity)) {
		if (of_property_read_u32(np,
				"ufs-pa-tacctivate", &ufs->pa_tactivate))
			dev_warn(dev, "ufs-pa-tacctivate is empty\n");

		if (of_property_read_u32(np,
				"ufs-pa-hibern8time", &ufs->pa_hibern8time))
			dev_warn(dev, "ufs-pa-hibern8time is empty\n");
	}

	if (of_property_read_u32(np, "ufs-pm-qos-int", &ufs->pm_qos_int_value))
		ufs->pm_qos_int_value = 0;

#if !defined(CONFIG_SOC_EXYNOS7420) && !defined(CONFIG_SOC_EXYNOS8890)
        ufs->pmureg = syscon_regmap_lookup_by_phandle(np,
                                        "samsung,pmu-phandle");
        if (IS_ERR(ufs->pmureg)) {
                dev_err(dev, "syscon regmap lookup failed.\n");
                return PTR_ERR(ufs->pmureg);
        }
#endif

out:
	return ret;
}

#ifdef CONFIG_CPU_IDLE
static int exynos_ufs_lp_event(struct notifier_block *nb, unsigned long event, void *data)
{
	struct exynos_ufs *ufs =
		container_of(nb, struct exynos_ufs, lpa_nb);
	const struct exynos_ufs_soc *soc = to_phy_soc(ufs);
	struct ufs_hba *hba = dev_get_drvdata(ufs->dev);
	int ret = NOTIFY_DONE;

	switch (event) {
	case LPA_ENTER:
		WARN_ON(!ufshcd_is_link_hibern8(hba));
		if (ufshcd_is_clkgating_allowed(hba))
			clk_prepare_enable(ufs->clk_hci);
		exynos_ufs_ctrl_auto_hci_clk(ufs, false);
		exynos_ufs_ctrl_phy_pwr(ufs, false);

		if (hba->monitor.flag & UFSHCD_MONITOR_LEVEL1)
			dev_info(hba->dev, "LPA+\n");
		break;
	case LPA_EXIT:
		exynos_ufs_ctrl_phy_pwr(ufs, true);
		exynos_ufs_ctrl_auto_hci_clk(ufs, true);
		if (ufshcd_is_clkgating_allowed(hba))
			clk_disable_unprepare(ufs->clk_hci);
		/*
		 * This condition means that PMA is reset.
		 * So, PMA SFRs should be restored as expected values
		 */
		if (ufshcd_is_clkgating_allowed(hba)) {
			clk_prepare_enable(ufs->clk_hci);
			clk_prepare_enable(ufs->pclk);
		}

		exynos_ufs_gate_clk(ufs, false);
		exynos_ufs_config_uic(ufs, soc->tbl_lpa_restore, NULL);
		if (ufshcd_is_clkgating_allowed(hba)) {
			clk_disable_unprepare(ufs->clk_hci);
			clk_disable_unprepare(ufs->pclk);
		}

		if (hba->monitor.flag & UFSHCD_MONITOR_LEVEL1)
			dev_info(hba->dev, "LPA-\n");

		break;
	}

	return ret;
}
#endif

static u64 exynos_ufs_dma_mask = DMA_BIT_MASK(32);

static int exynos_ufs_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct exynos_ufs *ufs;
	struct resource *res;
	int ret;

	ufs = devm_kzalloc(dev, sizeof(*ufs), GFP_KERNEL);
	if (!ufs) {
		dev_err(dev, "cannot allocate mem for exynos-ufs\n");
		return -ENOMEM;
	}

	/* exynos-specific hci */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	ufs->reg_hci = devm_ioremap_resource(dev, res);
	if (!ufs->reg_hci) {
		dev_err(dev, "cannot ioremap for hci vendor register\n");
		return -ENOMEM;
	}

	/* unipro */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	ufs->reg_unipro = devm_ioremap_resource(dev, res);
	if (!ufs->reg_unipro) {
		dev_err(dev, "cannot ioremap for unipro register\n");
		return -ENOMEM;
	}

	/* ufs protector */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 3);
	ufs->reg_ufsp = devm_ioremap_resource(dev, res);
	if (!ufs->reg_ufsp) {
		dev_err(dev, "cannot ioremap for ufs protector register\n");
		return -ENOMEM;
	}

	ret = exynos_ufs_populate_dt(dev, ufs);
	if (ret) {
		dev_err(dev, "failed to get dt info.\n");
		return ret;
	}

#ifdef CONFIG_CPU_IDLE
	ufs->lpa_nb.notifier_call = exynos_ufs_lp_event;
	ufs->lpa_nb.next = NULL;
	ufs->lpa_nb.priority = 0;

	ret = exynos_pm_register_notifier(&ufs->lpa_nb);
	if (ret) {
		dev_err(dev, "failed to register low power mode notifier\n");
		return ret;
	}
	ufs->idle_ip_index = exynos_get_idle_ip_index(dev_name(&pdev->dev));
	exynos_update_ip_idle_status(ufs->idle_ip_index, 0);
#endif

	ufs->dev = dev;
	dev->platform_data = ufs;
	dev->dma_mask = &exynos_ufs_dma_mask;

	pm_qos_add_request(&ufs->pm_qos_int, PM_QOS_DEVICE_THROUGHPUT, 0);

	ret = ufshcd_pltfrm_init(pdev, &exynos_ufs_ops);

	return ret;
}

static int exynos_ufs_remove(struct platform_device *pdev)
{
	struct exynos_ufs *ufs = dev_get_platdata(&pdev->dev);

	ufshcd_pltfrm_exit(pdev);

	pm_qos_remove_request(&ufs->pm_qos_int);

#ifdef CONFIG_CPU_IDLE
	exynos_pm_unregister_notifier(&ufs->lpa_nb);
#endif
	ufs->misc_flags = EXYNOS_UFS_MISC_TOGGLE_LOG;

	exynos_ufs_ctrl_phy_pwr(ufs, false);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int exynos_ufs_suspend(struct device *dev)
{
	struct ufs_hba *hba = dev_get_drvdata(dev);

	return ufshcd_system_suspend(hba);
}

static int exynos_ufs_resume(struct device *dev)
{
	struct ufs_hba *hba = dev_get_drvdata(dev);

	return ufshcd_system_resume(hba);
}
#else
#define exynos_ufs_suspend	NULL
#define exynos_ufs_resume	NULL
#endif /* CONFIG_PM_SLEEP */

#ifdef CONFIG_PM_RUNTIME
static int exynos_ufs_runtime_suspend(struct device *dev)
{
	return ufshcd_system_suspend(dev_get_drvdata(dev));
}

static int exynos_ufs_runtime_resume(struct device *dev)
{
	return ufshcd_system_resume(dev_get_drvdata(dev));
}

static int exynos_ufs_runtime_idle(struct device *dev)
{
	return ufshcd_runtime_idle(dev_get_drvdata(dev));
}

#else
#define exynos_ufs_runtime_suspend	NULL
#define exynos_ufs_runtime_resume	NULL
#define exynos_ufs_runtime_idle		NULL
#endif /* CONFIG_PM_RUNTIME */

static void exynos_ufs_shutdown(struct platform_device *pdev)
{
	ufshcd_shutdown((struct ufs_hba *)platform_get_drvdata(pdev));
}

static const struct dev_pm_ops exynos_ufs_dev_pm_ops = {
	.suspend		= exynos_ufs_suspend,
	.resume			= exynos_ufs_resume,
	.runtime_suspend	= exynos_ufs_runtime_suspend,
	.runtime_resume		= exynos_ufs_runtime_resume,
	.runtime_idle		= exynos_ufs_runtime_idle,
};

static const struct ufs_hba_variant exynos_ufs_drv_data = {
	.ops		= &exynos_ufs_ops,
	.vs_data	= &exynos_ufs_soc_data,
};

static const struct of_device_id exynos_ufs_match[] = {
	{ .compatible = "samsung,exynos-ufs", },
	{},
};
MODULE_DEVICE_TABLE(of, exynos_ufs_match);

static struct platform_driver exynos_ufs_driver = {
	.driver = {
		.name = "exynos-ufs",
		.owner = THIS_MODULE,
		.pm = &exynos_ufs_dev_pm_ops,
		.of_match_table = exynos_ufs_match,
		.suppress_bind_attrs = true,
	},
	.probe = exynos_ufs_probe,
	.remove = exynos_ufs_remove,
	.shutdown = exynos_ufs_shutdown,
};

module_platform_driver(exynos_ufs_driver);
MODULE_DESCRIPTION("Exynos Specific UFSHCI driver");
MODULE_AUTHOR("Seungwon Jeon <tgih.jun@samsung.com>");
MODULE_AUTHOR("Kiwoong Kim <kwmad.kim@samsung.com>");
MODULE_LICENSE("GPL");
