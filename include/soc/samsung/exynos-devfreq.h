#ifdef CONFIG_SOC_EXYNOS8890
#include <soc/samsung/exynos-devfreq8890.h>
#else
/* linux/arch/arm64/mach-exynos/include/mach/exynos-devfreq.h
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *              http://www.samsung.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __EXYNOS_DEVFREQ_H_
#define __EXYNOS_DEVFREQ_H_

#include <linux/devfreq.h>
#include <linux/pm_qos.h>
#include <linux/clk.h>
#include <soc/samsung/exynos-devfreq-dep.h>
#include <soc/samsung/exynos-dm.h>

#define EXYNOS_DEVFREQ_MODULE_NAME	"exynos-devfreq"
#define VOLT_STEP			25000
#define MAX_NR_CONSTRAINT		DM_TYPE_END
#define DATA_INIT			5
#define SET_CONST			1
#define RELEASE				2
enum exynos_devfreq_type {
	DEVFREQ_MIF = 0,
	DEVFREQ_INT,
	DEVFREQ_DISP,
	DEVFREQ_CAM,
	DEVFREQ_INTCAM,
	DEVFREQ_TYPE_END
};

enum exynos_devfreq_gov_type {
	SIMPLE_INTERACTIVE = 0,
	GOV_TYPE_END
};

/* "Utlization Monitor" type */
enum UM_TYPE {
	UM_MIF = 0,
	UM_INT,
	NONE_UM
};

enum volt_order_type {
	KEEP_SET_VOLT = 0,
	PRE_SET_VOLT,
	POST_SET_VOLT
};

enum exynos_devfreq_lv_index {
	DEV_LV0 = 0,
	DEV_LV1,
	DEV_LV2,
	DEV_LV3,
	DEV_LV4,
	DEV_LV5,
	DEV_LV6,
	DEV_LV7,
	DEV_LV8,
	DEV_LV9,
	DEV_LV10,
	DEV_LV11,
	DEV_LV12,
	DEV_LV13,
	DEV_LV14,
	DEV_LV15,
	DEV_LV16,
	DEV_LV17,
	DEV_LV18,
	DEV_LV19,
	DEV_LV20,
	DEV_LV_END,
};

struct exynos_devfreq_opp_table {
	u32 idx;
	u32 freq;
	u32 volt;
};

struct exynos_devfreq_data;
struct um_exynos;

struct exynos_devfreq_ops {
	/* ops.init(struct exynos_devfreq_data *data) */
	int (*init)(struct exynos_devfreq_data *);
	/* ops.exit(struct exynos_devfreq_data *data) */
	int (*exit)(struct exynos_devfreq_data *);
	/* ops.init_freq_table(struct exynos_devfreq_data *data) */
	int (*init_freq_table)(struct exynos_devfreq_data *);
	/* ops.get_volt_table(struct device *dev, u32 max_state, struct exynos_devfreq_opp_table *opp_list) */
	int (*get_volt_table)(struct device *, u32, struct exynos_devfreq_opp_table *);
	/* ops.ppmu_register(struct exynos_devfreq_data *data) */
	int (*um_register)(struct exynos_devfreq_data *);
	/* ops.ppmu_unregister(struct exynos_devfreq_data *data) */
	int (*um_unregister)(struct exynos_devfreq_data *);
	/* ops.suspend(struct exynos_devfreq_data *data) */
	int (*suspend)(struct exynos_devfreq_data *);
	/* ops.resume(struct exynos_devfreq_data *data */
	int (*resume)(struct exynos_devfreq_data *);
	/* ops.reboot(struct exynos_devfreq_data *data */
	int (*reboot)(struct exynos_devfreq_data *);
	/* ops.get_switch_voltage(struct device *dev, u32 cur_freq, u32 new_freq, u32 cur_volt, u32 new_volt, u32 *switch_volt) */
	int (*get_switch_voltage)(struct device *, u32, u32, u32, u32, u32 *);
	/* ops.set_voltage_prepare(struct exynos_devfreq_data *data) */
	void (*set_voltage_prepare)(struct exynos_devfreq_data *);
	/* ops.set_voltage_post(struct exynos_devfreq_data *data) */
	void (*set_voltage_post)(struct exynos_devfreq_data *);
	/* ops.get_switch_freq(struct device *dev, u32 cur_freq, u32 new_freq, u32 *switch_freq) */
	int (*get_switch_freq)(struct device *, u32, u32, u32 *);
	/* ops.get_freq(struct device *dev, u32 *cur_freq, struct clk *clk) */
	int (*get_freq)(struct device *, u32 *, struct clk *, struct exynos_devfreq_data *);
	/* ops.set_freq(struct device *dev, u32 new_freq, struct clk *clk) */
	int (*set_freq)(struct device *, u32, struct clk *, struct exynos_devfreq_data *);
	/* ops.set_freq_prepare(struct exynos_devfreq_data *data) */
	int (*set_freq_prepare)(struct exynos_devfreq_data *);
	/* ops.set_freq_post(struct exynos_devfreq_data) */
	int (*set_freq_post)(struct exynos_devfreq_data *);
	/* ops.change_to_switch_freq(struct device *dev, void *private_data, struct clk *sw_clk, u32 switch_freq, u32 cur_freq, u32 new_freq) */
	int (*change_to_switch_freq)(struct device *, void *, struct clk *, u32, u32, u32);
	/* ops.restore_from_switch_freq(struct device *dev, void *priave_data, struct clk *clk, u32 cur_freq, u32 new_freq) */
	int (*restore_from_switch_freq)(struct device *, void *, struct clk *, u32, u32);
	/* ops.get_dev_status(struct exynos_devfreq_data *data) */
	int (*get_dev_status)(struct exynos_devfreq_data *);
	/* ops.cl_dvfs_start(struct device *dev) */
	int (*cl_dvfs_start)(struct device *);
	/* ops.cl_dvfs_stop(struct device *dev, u32 target_idx) */
	int (*cl_dvfs_stop)(struct device *, u32);
	/* ops.cmu_dump(struct exynos_devfreq_data *data) */
	int (*cmu_dump)(struct exynos_devfreq_data *);
	/* ops.pm_suspend_prepare(struct exynos_devfreq_data *data) */
	int (*pm_suspend_prepare)(struct exynos_devfreq_data *);
	/* ops.pm_post_suspend(struct exynos_devfreq_data *data) */
	int (*pm_post_suspend)(struct exynos_devfreq_data *);
};

struct um_exynos {
	struct list_head node;
	void __iomem **va_base;
	u32 *pa_base;
	u32 *mask_v;
	u32 *mask_a;
	u32 *channel;
	unsigned int um_count;
	u64 val_ccnt;
	u64 val_pmcnt;
};

struct exynos_devfreq_data {
	struct device				*dev;
	struct devfreq				*devfreq;
	struct mutex				lock;
	struct clk				*clk;
	struct clk				*sw_clk;

	bool					devfreq_disabled;

	enum exynos_devfreq_type		devfreq_type;

	struct exynos_devfreq_opp_table		opp_list[DEV_LV_END];

	u32					default_qos;

	bool					use_get_dev;
	u32					max_state;
	struct devfreq_dev_profile		devfreq_profile;

	enum exynos_devfreq_gov_type		gov_type;
	const char				*governor_name;
	u32					cal_qos_max;
	void					*governor_data;
#if IS_ENABLED(CONFIG_DEVFREQ_GOV_SIMPLE_INTERACTIVE)
	struct devfreq_simple_interactive_data	simple_interactive_data;
#endif
	u32					dfs_id;
	s32					old_idx;
	s32					new_idx;
	u32					old_freq;
	u32					new_freq;
	u32					min_freq;
	u32					max_freq;
	u32					reboot_freq;
	u32					boot_freq;

	u32					old_volt;
	u32					new_volt;
	u32					volt_offset;
	u32					cold_volt_offset;
	u32					limit_cold_volt;
	u32					min_cold_volt;
	u32					reg_max_volt;
	bool					use_regulator;
	bool					use_pd_off;
	const char				*regulator_name;
	struct regulator			*vdd;
	struct mutex				regulator_lock;

	u32					pm_qos_class;
	u32					pm_qos_class_max;
	struct pm_qos_request			sys_pm_qos_min;
#ifdef CONFIG_ARM_EXYNOS_DEVFREQ_DEBUG
	struct pm_qos_request			debug_pm_qos_min;
	struct pm_qos_request			debug_pm_qos_max;
#endif
	struct pm_qos_request			default_pm_qos_min;
	struct pm_qos_request			default_pm_qos_max;
	struct pm_qos_request			boot_pm_qos;
	u32					boot_qos_timeout;

	struct devfreq_notifier_block		*um_nb;
	struct um_exynos			um_data;
	u64					last_monitor_period;
	u64					last_monitor_time;
	u32					last_um_usage_rate;

	bool					use_tmu;
	struct notifier_block			tmu_notifier;
	struct notifier_block			reboot_notifier;
	struct notifier_block			pm_notifier;

	u32					ess_flag;

	bool					use_cl_dvfs;

	s32					target_delay;
	s32					setfreq_delay;

	bool					use_switch_clk;
	u32					switch_freq;
	u32					switch_volt;

#ifdef CONFIG_EXYNOS_DVFS_MANAGER
	enum exynos_dm_type			dm_type;
	struct exynos_dm_constraint		*constraint[MAX_NR_CONSTRAINT];
#endif
	void					*private_data;
	struct exynos_devfreq_ops		ops;
	bool					use_acpm;
};

int register_exynos_devfreq_init_prepare(enum exynos_devfreq_type type,
				int (*func)(struct exynos_devfreq_data *));
s32 exynos_devfreq_get_opp_idx(struct exynos_devfreq_opp_table *table,
				unsigned int size, u32 freq);
#if defined(CONFIG_ARM_EXYNOS_DEVFREQ)
int exynos_devfreq_sync_voltage(enum exynos_devfreq_type type, bool turn_on);
#if defined(CONFIG_EXYNOS_DVFS_MANAGER)
enum exynos_dm_type exynos_devfreq_get_dm_type(enum exynos_devfreq_type devfreq_type);
enum exynos_devfreq_type exynos_devfreq_get_devfreq_type(enum exynos_dm_type dm_type);
struct device *find_exynos_devfreq_device(enum exynos_dm_type dm_type);
int find_exynos_devfreq_dm_type(struct device *dev, enum exynos_dm_type *dm_type);
#endif
#else
static inline
int exynos_devfreq_sync_voltage(enum exynos_devfreq_type type, bool turn_on)
{
	return 0;
}
#endif
#endif	/* __EXYNOS_DEVFREQ_H_ */

#endif
