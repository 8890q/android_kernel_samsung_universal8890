/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/spinlock.h>
#include <linux/suspend.h>
#include <linux/wakeup_reason.h>
#include <linux/gpio.h>
#include <linux/syscore_ops.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/slab.h>
#include <linux/psci.h>
#include <linux/debugfs.h>
#include <asm/cpuidle.h>
#include <asm/smp_plat.h>

#include <soc/samsung/exynos-pm.h>
#include <soc/samsung/exynos-pmu.h>
#include <soc/samsung/exynos-powermode.h>

#include <sound/samsung/vts.h>
#include <sound/samsung/abox.h>

//#include <sound/exynos-audmixer.h>

#ifdef CONFIG_SEC_PM
#include <linux/regulator/consumer.h>
#endif

#ifdef CONFIG_SEC_PM_DEBUG
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#endif

#define WAKEUP_STAT_EINT                (1 << 0)
#define WAKEUP_STAT_RTC_ALARM           (1 << 1)
#ifdef CONFIG_SEC_PM_DEBUG
#define WAKEUP_STAT_INT_MBOX            (1 << 24)
#endif
/*
 * PMU register offset
 */
#define EXYNOS_PMU_WAKEUP_STAT		0x0600
#define EXYNOS_PMU_EINT_WAKEUP_MASK	0x060C
#define BOOT_CPU			0

extern u32 exynos_eint_to_pin_num(int eint);
#define EXYNOS_EINT_PEND(b, x)      ((b) + 0xA00 + (((x) >> 3) * 4))

struct exynos_pm_info {
	void __iomem *eint_base;		/* GPIO_ALIVE base to check wkup reason */
	void __iomem *gic_base;			/* GICD_ISPENDRn base to check wkup reason */
	unsigned int num_eint;			/* Total number of EINT sources */
	unsigned int num_gic;			/* Total number of GIC sources */
	bool is_early_wakeup;
	bool is_cp_call;
	unsigned int suspend_mode_idx;		/* power mode to be used in suspend scenario */
	unsigned int suspend_psci_idx;		/* psci index to be used in suspend scenario */
	unsigned int cp_call_mode_idx;		/* power mode to be used in cp_call scenario */
	unsigned int cp_call_psci_idx;		/* psci index to be used in cp_call scenario */
	u8 num_extra_stat;			/* Total number of extra wakeup_stat */
	unsigned int *extra_wakeup_stat;	/* Extra wakeup stat SFRs offset */
};
static struct exynos_pm_info *pm_info;

struct exynos_pm_dbg {
	u32 test_early_wakeup;
	u32 test_cp_call;
};
static struct exynos_pm_dbg *pm_dbg;

static void exynos_show_wakeup_reason_eint(void)
{
	int bit;
	int i, size;
	long unsigned int ext_int_pend;
	u64 eint_wakeup_mask;
	bool found = 0;
	unsigned int val;

	exynos_pmu_read(EXYNOS_PMU_EINT_WAKEUP_MASK, &val);
	eint_wakeup_mask = val;

	for (i = 0, size = 8; i < pm_info->num_eint; i += size) {
		ext_int_pend =
			__raw_readl(EXYNOS_EINT_PEND(pm_info->eint_base, i));

		for_each_set_bit(bit, &ext_int_pend, size) {
			u32 gpio;
			int irq;

			if (eint_wakeup_mask & (1 << (i + bit)))
				continue;

			gpio = exynos_eint_to_pin_num(i + bit);
			irq = gpio_to_irq(gpio);

#ifdef CONFIG_SUSPEND
			log_wakeup_reason(irq);
		//	update_wakeup_reason_stats(irq, i + bit);
#endif
			found = 1;
		}
	}

	if (!found)
		pr_info("%s Resume caused by unknown EINT\n", EXYNOS_PM_PREFIX);
}

static void exynos_show_wakeup_registers(unsigned int wakeup_stat)
{
	int i, size;
	int extra_wakeup_stat;

	pr_info("WAKEUP_STAT:\n");
	pr_info("0x%08x\n", wakeup_stat);
	for (i = 0; i < pm_info->num_extra_stat; i++) {
		exynos_pmu_read(pm_info->extra_wakeup_stat[i], &extra_wakeup_stat);
		pr_info("0x%08x\n", extra_wakeup_stat);
	}

	pr_info("EINT_PEND: ");
	for (i = 0, size = 8; i < pm_info->num_eint; i += size)
		pr_info("0x%02x ", __raw_readl(EXYNOS_EINT_PEND(pm_info->eint_base, i)));
}

static void exynos_show_wakeup_reason(bool sleep_abort)
{
	unsigned int wakeup_stat;
	int i, size;

	if (sleep_abort) {
		pr_info("%s early wakeup! Dumping pending registers...\n", EXYNOS_PM_PREFIX);

		pr_info("EINT_PEND:\n");
		for (i = 0, size = 8; i < pm_info->num_eint; i += size)
			pr_info("0x%x\n", __raw_readl(EXYNOS_EINT_PEND(pm_info->eint_base, i)));

		pr_info("GIC_PEND:\n");
		for (i = 0; i < pm_info->num_gic; i++)
			pr_info("GICD_ISPENDR[%d] = 0x%x\n", i, __raw_readl(pm_info->gic_base + i*4));

		pr_info("%s done.\n", EXYNOS_PM_PREFIX);
		return ;
	}

	exynos_pmu_read(EXYNOS_PMU_WAKEUP_STAT, &wakeup_stat);
	exynos_show_wakeup_registers(wakeup_stat);

	if (wakeup_stat & WAKEUP_STAT_RTC_ALARM)
		pr_info("%s Resume caused by RTC alarm\n", EXYNOS_PM_PREFIX);
#ifdef CONFIG_SEC_PM_DEBUG
	else if (wakeup_stat & WAKEUP_STAT_INT_MBOX)
		log_mbox_wakeup();
#endif
	else if (wakeup_stat & WAKEUP_STAT_EINT)
		exynos_show_wakeup_reason_eint();
	else
		pr_info("%s Resume caused by wakeup_stat 0x%08x\n",
			EXYNOS_PM_PREFIX, wakeup_stat);
}

#ifdef CONFIG_CPU_IDLE
static DEFINE_RWLOCK(exynos_pm_notifier_lock);
static RAW_NOTIFIER_HEAD(exynos_pm_notifier_chain);

int exynos_pm_register_notifier(struct notifier_block *nb)
{
	unsigned long flags;
	int ret;

	write_lock_irqsave(&exynos_pm_notifier_lock, flags);
	ret = raw_notifier_chain_register(&exynos_pm_notifier_chain, nb);
	write_unlock_irqrestore(&exynos_pm_notifier_lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(exynos_pm_register_notifier);

int exynos_pm_unregister_notifier(struct notifier_block *nb)
{
	unsigned long flags;
	int ret;

	write_lock_irqsave(&exynos_pm_notifier_lock, flags);
	ret = raw_notifier_chain_unregister(&exynos_pm_notifier_chain, nb);
	write_unlock_irqrestore(&exynos_pm_notifier_lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(exynos_pm_unregister_notifier);

static int __exynos_pm_notify(enum exynos_pm_event event, int nr_to_call, int *nr_calls)
{
	int ret;

	ret = __raw_notifier_call_chain(&exynos_pm_notifier_chain, event, NULL,
		nr_to_call, nr_calls);

	return notifier_to_errno(ret);
}

int exynos_pm_notify(enum exynos_pm_event event)
{
	int nr_calls;
	int ret = 0;

	read_lock(&exynos_pm_notifier_lock);
	ret = __exynos_pm_notify(event, -1, &nr_calls);
	read_unlock(&exynos_pm_notifier_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(exynos_pm_notify);
#endif /* CONFIG_CPU_IDLE */

#if defined(CONFIG_SOC_EXYNOS8895)
#define SLEEP_VTS_ON   9
#define SLEEP_AUD_ON   10
#endif

static int exynos_pm_syscore_suspend(void)
{
	if (!exynos_check_cp_status()) {
		pr_info("%s %s: sleep canceled by CP reset \n",
					EXYNOS_PM_PREFIX, __func__);
		return -EINVAL;
	}

	pm_info->is_cp_call = abox_is_on();
	if (pm_info->is_cp_call || pm_dbg->test_cp_call) {
		exynos_prepare_sys_powerdown(pm_info->cp_call_mode_idx);
		pr_info("%s %s: Enter CP Call scenario. (mode_idx = %d)\n",
				EXYNOS_PM_PREFIX, __func__, pm_info->cp_call_mode_idx);
	} else {
#if defined(CONFIG_SOC_EXYNOS8895)
		if (vts_is_on())
			exynos_prepare_sys_powerdown(SLEEP_VTS_ON);
		else
#endif
			exynos_prepare_sys_powerdown(pm_info->suspend_mode_idx);

		pr_info("%s %s: Enter Suspend scenario. (mode_idx = %d)\n",
				EXYNOS_PM_PREFIX,__func__, pm_info->suspend_mode_idx);
	}

	return 0;
}

static void exynos_pm_syscore_resume(void)
{
	if (pm_info->is_cp_call || pm_dbg->test_cp_call)
		exynos_wakeup_sys_powerdown(pm_info->cp_call_mode_idx, pm_info->is_early_wakeup);
	else {
#if defined(CONFIG_SOC_EXYNOS8895)
		if (vts_is_on())
			exynos_wakeup_sys_powerdown(SLEEP_VTS_ON, pm_info->is_early_wakeup);
		else
#endif
			exynos_wakeup_sys_powerdown(pm_info->suspend_mode_idx, pm_info->is_early_wakeup);
	}

	exynos_show_wakeup_reason(pm_info->is_early_wakeup);

	if (!pm_info->is_early_wakeup)
		pr_debug("%s %s: post sleep, preparing to return\n",
						EXYNOS_PM_PREFIX, __func__);
}

static struct syscore_ops exynos_pm_syscore_ops = {
	.suspend	= exynos_pm_syscore_suspend,
	.resume		= exynos_pm_syscore_resume,
};

#ifdef CONFIG_SEC_GPIO_DVS
extern void gpio_dvs_check_sleepgpio(void);
#endif

#ifdef CONFIG_SEC_PM
static int exynos_pm_prepare(void)
{
	/* TODO */
	regulator_showall_enabled();

	return 0;
}

#endif

static int exynos_pm_enter(suspend_state_t state)
{
	unsigned int psci_index;

#ifdef CONFIG_SEC_GPIO_DVS
	/************************ Caution !!! ****************************/
	/* This function must be located in appropriate SLEEP position
	 * in accordance with the specification of each BB vendor.
	 */
	/************************ Caution !!! ****************************/
	gpio_dvs_check_sleepgpio();
#endif

	if (pm_info->is_cp_call || pm_dbg->test_cp_call)
		psci_index = pm_info->cp_call_psci_idx;
	else
		psci_index = pm_info->suspend_psci_idx;

	/* Send an IPI if test_early_wakeup flag is set */
	if (pm_dbg->test_early_wakeup)
		arch_send_call_function_single_ipi(0);

	/* This will also act as our return point when
	 * we resume as it saves its own register state and restores it
	 * during the resume. */
	pm_info->is_early_wakeup = (bool)arm_cpuidle_suspend(psci_index);
	if (pm_info->is_early_wakeup)
		pr_info("%s %s: return to originator\n",
				EXYNOS_PM_PREFIX, __func__);

	return pm_info->is_early_wakeup;
}

static const struct platform_suspend_ops exynos_pm_ops = {
	.enter		= exynos_pm_enter,
#ifdef CONFIG_SEC_PM
	.prepare	= exynos_pm_prepare,
#endif
	.valid		= suspend_valid_only_mem,
};

#if defined(CONFIG_SEC_PM_DEBUG)
enum dvfs_id {
	cal_asv_dvfs_big,
	cal_asv_dvfs_little,
	cal_asv_dvfs_g3d,
	cal_asv_dvfs_mif,
	cal_asv_dvfs_int,
	cal_asv_dvfs_cam,
	cal_asv_dvfs_disp,
	cal_asv_dvs_g3dm,
	num_of_dvfs,
};

enum asv_group {
	asv_max_lv,
	dvfs_freq,
	dvfs_voltage,
	dvfs_group,
	table_group,
	num_of_asc,
};

extern int asv_get_information(enum dvfs_id id,
	enum asv_group grp, unsigned int lv);

static int asv_group_show(struct seq_file *s, void *d)
{
	int i;

	for (i = 0; i < num_of_dvfs; i++) {
	int max_lv = asv_get_information(i, asv_max_lv, 0);
	char *name ="ASVGROUP";
	int lv;

	switch (i) {
		case cal_asv_dvfs_big:
			name ="MNGS";
			break;
		case cal_asv_dvfs_little:
			name = "APOLLO";
			break;
		case cal_asv_dvfs_g3d:
			name ="G3D";
			break;
		case cal_asv_dvfs_mif:
			name = "MIF";
			break;
		case cal_asv_dvfs_int:
			name = "INT";
			break;
		case cal_asv_dvfs_cam:
			name = "CAM";
			break;
		case cal_asv_dvfs_disp:
			name ="ISP";
			break;
		default:
			break;
	}

	seq_printf(s, "%s ASV group is %d max_lv is %d\n",
		name, asv_get_information(i, dvfs_group, 0), max_lv);

		for (lv = 0; lv < max_lv ; lv++) {
			seq_printf(s, "%s LV%d freq : %d volt : %d, "
			"group: %d\n",
			name, lv, asv_get_information(i, dvfs_freq, lv),
			asv_get_information(i, dvfs_voltage, lv),
			asv_get_information(i, dvfs_group, lv));
		}
	}

	return 0;
}

static int asv_group_open(struct inode *inode, struct file *file)
{
	return single_open(file, asv_group_show, inode->i_private);
}

const static struct file_operations asv_group_fops = {
	.open		= asv_group_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int asv_summary_show(struct seq_file *s, void *d)
{
	seq_printf(s, "big:%u, LITTLE:%u, INT:%u, MIF:%u, G3D:%u, ISP:%u\n",
		asv_get_information(cal_asv_dvfs_big, dvfs_group, 0),
		asv_get_information(cal_asv_dvfs_little, dvfs_group, 0),
		asv_get_information(cal_asv_dvfs_int, dvfs_group, 0),
		asv_get_information(cal_asv_dvfs_mif, dvfs_group, 0),
		asv_get_information(cal_asv_dvfs_g3d, dvfs_group, 0),
		asv_get_information(cal_asv_dvfs_disp, dvfs_group,0));

	return 0;
}

static int asv_summary_open(struct inode *inode, struct file *file)
{
	return single_open(file, asv_summary_show, inode->i_private);
}

const static struct file_operations asv_summary_fops = {
	.open		= asv_summary_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif /* CONFIG_SEC_PM_DEBUG */

bool is_test_cp_call_set(void)
{
	if (!pm_dbg)
		return false;

	return pm_dbg->test_cp_call;
}
EXPORT_SYMBOL_GPL(is_test_cp_call_set);

#ifdef CONFIG_DEBUG_FS
static void __init exynos_pm_debugfs_init(void)
{
	struct dentry *root, *d;

	root = debugfs_create_dir("exynos-pm", NULL);
	if (!root) {
		pr_err("%s %s: could't create debugfs dir\n", EXYNOS_PM_PREFIX, __func__);
		return;
	}

	d = debugfs_create_u32("test_early_wakeup", 0644, root, &pm_dbg->test_early_wakeup);
	if (!d) {
		pr_err("%s %s: could't create debugfs test_early_wakeup\n",
					EXYNOS_PM_PREFIX, __func__);
		return;
	}

	d = debugfs_create_u32("test_cp_call", 0644, root, &pm_dbg->test_cp_call);
	if (!d) {
		pr_err("%s %s: could't create debugfs test_cp_call\n",
					EXYNOS_PM_PREFIX, __func__);
		return;
	}
}
#endif

#if defined(CONFIG_SEC_FACTORY)
enum ids_info {
        tg,
        lg,
        bg,
        g3dg,
        mifg,
        bids,
        gids,
};

extern int asv_ids_information(enum ids_info id);

static ssize_t show_asv_info(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	int count = 0;

	/* Set asv group info to buf */
	count += sprintf(&buf[count], "%d ", asv_ids_information(tg));
	count += sprintf(&buf[count], "%03x ", asv_ids_information(bg));
	count += sprintf(&buf[count], "%03x ", asv_ids_information(g3dg));
	count += sprintf(&buf[count], "%u ", asv_ids_information(bids));
	count += sprintf(&buf[count], "%u ", asv_ids_information(gids));
	count += sprintf(&buf[count], "\n");

	return count;
}

static DEVICE_ATTR(asv_info, 0664, show_asv_info, NULL);
#endif /* CONFIG_SEC_FACTORY */

static __init int exynos_pm_drvinit(void)
{
	int ret;

	pm_info = kzalloc(sizeof(struct exynos_pm_info), GFP_KERNEL);
	if (pm_info == NULL) {
		pr_err("%s %s: failed to allocate memory for exynos_pm_info\n",
					EXYNOS_PM_PREFIX, __func__);
		BUG();
	}

	pm_dbg = kzalloc(sizeof(struct exynos_pm_dbg), GFP_KERNEL);
	if (pm_dbg == NULL) {
		pr_err("%s %s: failed to allocate memory for exynos_pm_dbg\n",
					EXYNOS_PM_PREFIX, __func__);
		BUG();
	}

	if (of_have_populated_dt()) {
		struct device_node *np;
		np = of_find_compatible_node(NULL, NULL, "samsung,exynos-pm");
		if (!np) {
			pr_err("%s %s: unabled to find compatible node (%s)\n",
					EXYNOS_PM_PREFIX, __func__, "samsung,exynos-pm");
			BUG();
		}

		pm_info->eint_base = of_iomap(np, 0);
		if (!pm_info->eint_base) {
			pr_err("%s %s: unabled to ioremap EINT base address\n",
					EXYNOS_PM_PREFIX, __func__);
			BUG();
		}

		pm_info->gic_base = of_iomap(np, 1);
		if (!pm_info->gic_base) {
			pr_err("%s %s: unbaled to ioremap GIC base address\n",
					EXYNOS_PM_PREFIX, __func__);
			BUG();
		}

		ret = of_property_read_u32(np, "num-eint", &pm_info->num_eint);
		if (ret) {
			pr_err("%s %s: unabled to get the number of eint from DT\n",
					EXYNOS_PM_PREFIX, __func__);
			BUG();
		}

		ret = of_property_read_u32(np, "num-gic", &pm_info->num_gic);
		if (ret) {
			pr_err("%s %s: unabled to get the number of gic from DT\n",
					EXYNOS_PM_PREFIX, __func__);
			BUG();
		}

		ret = of_property_read_u32(np, "suspend_mode_idx", &pm_info->suspend_mode_idx);
		if (ret) {
			pr_err("%s %s: unabled to get suspend_mode_idx from DT\n",
					EXYNOS_PM_PREFIX, __func__);
			BUG();
		}

		ret = of_property_read_u32(np, "suspend_psci_idx", &pm_info->suspend_psci_idx);
		if (ret) {
			pr_err("%s %s: unabled to get suspend_psci_idx from DT\n",
					EXYNOS_PM_PREFIX, __func__);
			BUG();
		}

		ret = of_property_read_u32(np, "cp_call_mode_idx", &pm_info->cp_call_mode_idx);
		if (ret) {
			pr_err("%s %s: unabled to get cp_call_mode_idx from DT\n",
					EXYNOS_PM_PREFIX, __func__);
			BUG();
		}

		ret = of_property_read_u32(np, "cp_call_psci_idx", &pm_info->cp_call_psci_idx);
		if (ret) {
			pr_err("%s %s: unabled to get cp_call_psci_idx from DT\n",
					EXYNOS_PM_PREFIX, __func__);
			BUG();
		}

		ret = of_property_count_u32_elems(np, "extra_wakeup_stat");
		if (!ret) {
			pr_err("%s %s: unabled to get wakeup_stat value from DT\n",
					EXYNOS_PM_PREFIX, __func__);
			BUG();
		} else {
			pm_info->num_extra_stat = ret;
			pm_info->extra_wakeup_stat = kzalloc(sizeof(unsigned int) * ret, GFP_KERNEL);
			of_property_read_u32_array(np, "extra_wakeup_stat", pm_info->extra_wakeup_stat, ret);
		}
	} else {
		pr_err("%s %s: failed to have populated device tree\n",
					EXYNOS_PM_PREFIX, __func__);
		BUG();
	}

	suspend_set_ops(&exynos_pm_ops);
	register_syscore_ops(&exynos_pm_syscore_ops);
#ifdef CONFIG_DEBUG_FS
	exynos_pm_debugfs_init();

#if defined(CONFIG_SEC_PM_DEBUG)
	debugfs_create_file("asv_summary", S_IRUSR, NULL, NULL, &asv_summary_fops);
#endif
#endif

#if defined(CONFIG_SEC_FACTORY)
	/* create sysfs group */
	ret = sysfs_create_file(power_kobj, &dev_attr_asv_info.attr);
	if (ret)
		pr_err("%s: failed to create exynos8890 asv attribute file\n", __func__);
#endif

	return 0;
}
arch_initcall(exynos_pm_drvinit);
