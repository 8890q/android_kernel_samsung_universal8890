/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * EXYNOS Power mode
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/tick.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/psci.h>
#include <linux/cpuidle_profiler.h>
#include <linux/exynos-ss.h>
#include <linux/cpufreq.h>
#include <linux/delay.h>

#include <asm/smp_plat.h>

#include <soc/samsung/exynos-pm.h>
#include <soc/samsung/exynos-pmu.h>
#include <soc/samsung/exynos-powermode.h>

extern void mngs_reset_control(int en);

#if defined(CONFIG_SEC_PM) && defined(CONFIG_MUIC_NOTIFIER)
#include <linux/device.h>
#include <linux/muic/muic.h>
#include <linux/muic/muic_notifier.h>
#ifdef CONFIG_CCIC_NOTIFIER
#include <linux/ccic/ccic_notifier.h>
#endif
#endif

struct exynos_powermode_info {
	unsigned int	cpd_residency;		/* target residency of cpd */
	unsigned int	sicd_residency;		/* target residency of sicd */

	struct cpumask	c2_mask;		/* per cpu c2 status */

	int		cpd_enabled;		/* CPD activation */
	int		cpd_blocking;		/* blocking CPD */

	int		sicd_enabled;		/* SICD activation */
	bool		sicd_entered;

	/*
	 * While system boot, wakeup_mask and idle_ip_mask is intialized with
	 * device tree. These are used by system power mode.
	 */
	unsigned int	num_wakeup_mask;
	unsigned int	*wakeup_mask_offset;
	unsigned int	*wakeup_mask[NUM_SYS_POWERDOWN];
	int		idle_ip_mask[NUM_SYS_POWERDOWN][NUM_IDLE_IP];
};

static struct exynos_powermode_info *pm_info;
static bool cpd_freq_blocked;

/******************************************************************************
 *                                CAL interfaces                              *
 ******************************************************************************/
#define linear_phycpu(mpidr)			\
	((MPIDR_AFFINITY_LEVEL(mpidr, 1) << 2)	\
	 | MPIDR_AFFINITY_LEVEL(mpidr, 0))

static void cpu_enable(unsigned int cpu)
{
#if defined(CONFIG_SOC_EXYNOS8890)
	exynos_cpu.power_up(cpu);
#else
	unsigned int mpidr = cpu_logical_map(cpu);
	unsigned int phycpu = linear_phycpu(mpidr);

	cal_cpu_enable(phycpu);
#endif
}

static void cpu_disable(unsigned int cpu)
{
#if defined(CONFIG_SOC_EXYNOS8890)
	exynos_cpu.power_down(cpu);
#else
	unsigned int mpidr = cpu_logical_map(cpu);
	unsigned int phycpu = linear_phycpu(mpidr);

	cal_cpu_disable(phycpu);
#endif
}

static void cluster_enable(unsigned int cpu)
{
#if defined(CONFIG_SOC_EXYNOS8890)
	exynos_cpu.cluster_up(cpu);
#else
	unsigned int mpidr = cpu_logical_map(cpu);
	unsigned int phycluster = MPIDR_AFFINITY_LEVEL(mpidr, 1);

	cal_cluster_enable(phycluster);
	mngs_reset_control(1);
#endif
}

static void cluster_disable(unsigned int cpu)
{
#if defined(CONFIG_SOC_EXYNOS8890)
	exynos_cpu.cluster_down(cpu);
#else
	unsigned int mpidr = cpu_logical_map(cpu);
	unsigned int phycluster = MPIDR_AFFINITY_LEVEL(mpidr, 1);

	mngs_reset_control(0);
	cal_cluster_disable(phycluster);
#endif
}

#ifdef CONFIG_ARM64_EXYNOS_CPUIDLE

/******************************************************************************
 *                                  IDLE_IP                                   *
 ******************************************************************************/
#define PMU_IDLE_IP_BASE		0x03E0
#define PMU_IDLE_IP_MASK_BASE		0x03F0
#define PMU_IDLE_IP(x)			(PMU_IDLE_IP_BASE + (x * 0x4))
#define PMU_IDLE_IP_MASK(x)		(PMU_IDLE_IP_MASK_BASE + (x * 0x4))

static int exynos_check_idle_ip_stat(int mode, int reg_index)
{
	unsigned int val, mask;
	int ret;

	exynos_pmu_read(PMU_IDLE_IP(reg_index), &val);
	mask = pm_info->idle_ip_mask[mode][reg_index];

	ret = (val & ~mask) == ~mask ? 0 : -EBUSY;

	if (ret) {
		/*
		 * Profile non-idle IP using idle_ip.
		 * A bit of idle-ip equals 0, it means non-idle. But then, if
		 * same bit of idle-ip-mask is 1, PMU does not see this bit.
		 * To know what IP blocks to enter system power mode, suppose
		 * below example: (express only 8 bits)
		 *
		 * idle-ip  : 1 0 1 1 0 0 1 0
		 * mask     : 1 1 0 0 1 0 0 1
		 *
		 * First, clear masked idle-ip bit.
		 *
		 * idle-ip  : 1 0 1 1 0 0 1 0
		 * ~mask    : 0 0 1 1 0 1 1 0
		 * -------------------------- (AND)
		 * idle-ip' : 0 0 1 1 0 0 1 0
		 *
		 * In upper case, only idle-ip[2] is not in idle. Calculates
		 * as follows, then we can get the non-idle IP easily.
		 *
		 * idle-ip' : 0 0 1 1 0 0 1 0
		 * ~mask    : 0 0 1 1 0 1 1 0
		 *--------------------------- (XOR)
		 *            0 0 0 0 0 1 0 0
		 */
		cpuidle_profile_collect_idle_ip(mode, reg_index,
				((val & ~mask) ^ ~mask));
	}

	return ret;
}

static int syspwr_mode_available(unsigned int mode)
{
	int index;

	for_each_idle_ip(index)
		if (exynos_check_idle_ip_stat(mode, index))
			return false;

	return true;
}

static DEFINE_SPINLOCK(idle_ip_mask_lock);
static void exynos_set_idle_ip_mask(enum sys_powerdown mode)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&idle_ip_mask_lock, flags);
	for_each_idle_ip(i)
		exynos_pmu_write(PMU_IDLE_IP_MASK(i),
				pm_info->idle_ip_mask[mode][i]);
	spin_unlock_irqrestore(&idle_ip_mask_lock, flags);
}

/**
 * There are 4 IDLE_IP registers in PMU, IDLE_IP therefore supports 128 index,
 * 0 from 127. To access the IDLE_IP register, convert_idle_ip_index() converts
 * idle_ip index to register index and bit in regster. For example, idle_ip index
 * 33 converts to IDLE_IP1[1]. convert_idle_ip_index() returns register index
 * and ships bit in register to *ip_index.
 */
static int convert_idle_ip_index(int *ip_index)
{
	int reg_index;

	reg_index = *ip_index / IDLE_IP_REG_SIZE;
	*ip_index = *ip_index % IDLE_IP_REG_SIZE;

	return reg_index;
}

static void idle_ip_unmask(int mode, int ip_index)
{
	int reg_index = convert_idle_ip_index(&ip_index);
	unsigned long flags;

	spin_lock_irqsave(&idle_ip_mask_lock, flags);
	pm_info->idle_ip_mask[mode][reg_index] &= ~(0x1 << ip_index);
	spin_unlock_irqrestore(&idle_ip_mask_lock, flags);
}

static int is_idle_ip_index_used(struct device_node *node, int ip_index)
{
	int proplen;
	int ref_idle_ip[IDLE_IP_MAX_INDEX];
	int i;

	proplen = of_property_count_u32_elems(node, "ref-idle-ip");

	if (proplen <= 0)
		return false;

	if (!of_property_read_u32_array(node, "ref-idle-ip",
					ref_idle_ip, proplen)) {
		for (i = 0; i < proplen; i++)
			if (ip_index == ref_idle_ip[i])
				return true;
	}

	return false;
}

static void exynos_create_idle_ip_mask(int ip_index)
{
	struct device_node *root = of_find_node_by_path("/exynos-powermode/idle_ip_mask");
	struct device_node *node;

	for_each_child_of_node(root, node) {
		int mode;

		if (of_property_read_u32(node, "mode-index", &mode))
			continue;

		if (is_idle_ip_index_used(node, ip_index))
			idle_ip_unmask(mode, ip_index);
	}
}

int exynos_get_idle_ip_index(const char *ip_name)
{
	struct device_node *np = of_find_node_by_name(NULL, "exynos-powermode");
	int ip_index;

	ip_index = of_property_match_string(np, "idle-ip", ip_name);
	if (ip_index < 0) {
		pr_err("%s: Fail to find %s in idle-ip list with err %d\n",
					__func__, ip_name, ip_index);
		return ip_index;
	}

	if (ip_index > IDLE_IP_MAX_CONFIGURABLE_INDEX) {
		pr_err("%s: %s index %d is out of range\n",
					__func__, ip_name, ip_index);
		return -EINVAL;
	}

	/**
	 * If it successes to find IP in idle_ip list, we set
	 * corresponding bit in idle_ip mask.
	 */
	exynos_create_idle_ip_mask(ip_index);

	return ip_index;
}

static DEFINE_SPINLOCK(ip_idle_lock);
void exynos_update_ip_idle_status(int ip_index, int idle)
{
	unsigned long flags;
	int reg_index;

	/*
	 * If ip_index is not valid, it should not update IDLE_IP.
	 */
	if (ip_index < 0 || ip_index > IDLE_IP_MAX_CONFIGURABLE_INDEX)
		return;

	reg_index = convert_idle_ip_index(&ip_index);

	spin_lock_irqsave(&ip_idle_lock, flags);
	exynos_pmu_update(PMU_IDLE_IP(reg_index),
				1 << ip_index, idle << ip_index);
	spin_unlock_irqrestore(&ip_idle_lock, flags);

	return;
}

void exynos_get_idle_ip_list(char *(*idle_ip_list)[IDLE_IP_REG_SIZE])
{
	struct device_node *np = of_find_node_by_name(NULL, "exynos-powermode");
	int size;
	const char *list[IDLE_IP_MAX_CONFIGURABLE_INDEX];
	int i, bit, reg_index;

	size = of_property_count_strings(np, "idle-ip");
	if (size < 0)
		return;

	of_property_read_string_array(np, "idle-ip", list, size);
	for (i = 0, bit = 0; i < size; i++, bit = i) {
		reg_index = convert_idle_ip_index(&bit);
		idle_ip_list[reg_index][bit] = (char *)list[i];
	}

	size = of_property_count_strings(np, "fix-idle-ip");
	if (size < 0)
		return;

	of_property_read_string_array(np, "fix-idle-ip", list, size);
	for (i = 0; i < size; i++) {
		if (!of_property_read_u32_index(np, "fix-idle-ip-index", i, &bit)) {
			reg_index = convert_idle_ip_index(&bit);
			idle_ip_list[reg_index][bit] = (char *)list[i];
		}
	}
}

static void __init init_idle_ip(void)
{
	struct device_node *np = of_find_node_by_name(NULL, "exynos-powermode");
	int mode, index, size, i;

	for_each_syspwr_mode(mode)
		for_each_idle_ip(index)
			pm_info->idle_ip_mask[mode][index] = 0xFFFFFFFF;

	/*
	 * To unmask fixed idle-ip, fix-idle-ip and fix-idle-ip-index,
	 * both properties must be existed and size must be same.
	 */
	if (!of_find_property(np, "fix-idle-ip", NULL)
			|| !of_find_property(np, "fix-idle-ip-index", NULL))
		return;

	size = of_property_count_strings(np, "fix-idle-ip");
	if (size != of_property_count_u32_elems(np, "fix-idle-ip-index")) {
		pr_err("Mismatch between fih-idle-ip and fix-idle-ip-index\n");
		return;
	}

	for (i = 0; i < size; i++) {
		of_property_read_u32_index(np, "fix-idle-ip-index", i, &index);
		exynos_create_idle_ip_mask(index);
	}
}

/******************************************************************************
 *                           CPU power management                             *
 ******************************************************************************/
/**
 * If cpu is powered down, c2_mask in struct exynos_powermode_info is set. On
 * the contrary, cpu is powered on, c2_mask is cleard. To keep coherency of
 * c2_mask, use the spinlock, c2_lock. In Exynos, it supports C2 subordinate
 * power mode, CPD.
 *
 * - CPD (Cluster Power Down)
 * All cpus in a cluster are set c2_mask, and these cpus have enough idle
 * time which is longer than cpd_residency, cluster can be powered off.
 *
 * SICD (System Idle Clock Down) : All cpus are set c2_mask and these cpus
 * have enough idle time which is longer than sicd_residency, and besides no
 * device is operated, AP can be put into SICD.
 */

static DEFINE_SPINLOCK(c2_lock);

static void update_c2_state(bool down, unsigned int cpu)
{
	if (down)
		cpumask_set_cpu(cpu, &pm_info->c2_mask);
	else
		cpumask_clear_cpu(cpu, &pm_info->c2_mask);
}

static s64 get_next_event_time_us(unsigned int cpu)
{
	return ktime_to_us(tick_nohz_get_sleep_length());
}

static int is_cpus_busy(unsigned int target_residency,
				const struct cpumask *mask)
{
	int cpu;

	/*
	 * If there is even one cpu in "mask" which has the smaller idle time
	 * than "target_residency", it returns -EBUSY.
	 */
	for_each_cpu_and(cpu, cpu_online_mask, mask) {
		if (!cpumask_test_cpu(cpu, &pm_info->c2_mask))
			return -EBUSY;

		/*
		 * Compare cpu's next event time and target_residency.
		 * Next event time means idle time.
		 */
		if (get_next_event_time_us(cpu) < target_residency)
			return -EBUSY;
	}

	return 0;
}

static unsigned int get_cluster_id(unsigned int cpu)
{
	return MPIDR_AFFINITY_LEVEL(cpu_logical_map(cpu), 1);
}

static bool is_cpu_boot_cluster(unsigned int cpu)
{
	/*
	 * The cluster included cpu0 is boot cluster
	 */
	return (get_cluster_id(0) == get_cluster_id(cpu));
}

static int is_cpd_available(unsigned int cpu)
{
	struct cpumask mask;

	if (!pm_info->cpd_enabled)
		return false;

	/* If other driver blocks cpd, cpd_blocking is true */
	if (pm_info->cpd_blocking || READ_ONCE(cpd_freq_blocked))
		return false;

	/*
	 * Power down of boot cluster have nothing to gain power consumption,
	 * so it is not supported.
	 */
	if (is_cpu_boot_cluster(cpu))
		return false;

	cpumask_and(&mask, cpu_coregroup_mask(cpu), cpu_online_mask);
	if (is_cpus_busy(pm_info->cpd_residency, &mask))
		return false;

	return true;
}

#if defined(CONFIG_SEC_PM) && defined(CONFIG_MUIC_NOTIFIER)
static bool jig_is_attached;

static inline bool is_jig_attached(void)
{
	return jig_is_attached;
}
#else
static inline bool is_jig_attached(void)
{
	return false;
}
#endif

static int is_sicd_available(unsigned int cpu)
{
	if (!pm_info->sicd_enabled)
		return false;

	if (is_jig_attached())
		return false;

	/*
	 * When the cpu in non-boot cluster enters SICD, interrupts of
	 * boot cluster is not blocked. For stability, SICD entry by
	 * non-boot cluster is not supported.
	 */
	if (!is_cpu_boot_cluster(cpu))
		return false;

	if (is_cpus_busy(pm_info->sicd_residency, cpu_online_mask))
		return false;

	if (syspwr_mode_available(SYS_SICD))
		return true;

	return false;
}

/**
 * cluster_idle_state shows whether cluster is in idle or not.
 *
 * check_cluster_idle_state() : Show cluster idle state.
 * 		If it returns true, cluster is in idle state.
 * update_cluster_idle_state() : Update cluster idle state.
 */
static int cluster_idle_state[MAX_CLUSTER];

int check_cluster_idle_state(unsigned int cpu)
{
	return cluster_idle_state[get_cluster_id(cpu)];
}

/* Keep the cluster awake through the full voltage/clock transition. */
void block_cpd(void)
{
	WRITE_ONCE(cpd_freq_blocked, true);
}

void release_cpd(void)
{
	WRITE_ONCE(cpd_freq_blocked, false);
}

static void update_cluster_idle_state(int idle, unsigned int cpu)
{
	cluster_idle_state[get_cluster_id(cpu)] = idle;
}

/**
 * Exynos cpuidle driver call exynos_cpu_pm_enter() and exynos_cpu_pm_exit() to
 * handle platform specific configuration to power off the cpu power domain.
 */
int exynos_cpu_pm_enter(unsigned int cpu, int index)
{
	cpu_disable(cpu);

	spin_lock(&c2_lock);
	update_c2_state(true, cpu);

	/*
	 * Below sequence determines whether to power down the cluster/enter SICD
	 * or not. If idle time of cpu is not enough, go out of this function.
	 */
	if (get_next_event_time_us(cpu) <
			min(pm_info->cpd_residency, pm_info->sicd_residency))
		goto out;

	if (is_cpd_available(cpu)) {
		cluster_disable(cpu);
		update_cluster_idle_state(true, cpu);

		index = PSCI_CLUSTER_SLEEP;
	}

	if (is_sicd_available(cpu)) {
		if (exynos_prepare_sys_powerdown(SYS_SICD))
			goto out;

		s3c24xx_serial_fifo_wait();
		exynos_ss_cpuidle(get_sys_powerdown_str(SYS_SICD),
						0, 0, ESS_FLAG_IN);

		pm_info->sicd_entered = true;
		index = PSCI_SYSTEM_IDLE;
	}
out:
	spin_unlock(&c2_lock);

	return index;
}

void exynos_cpu_pm_exit(unsigned int cpu, int enter_failed)
{
	if (enter_failed)
		cpu_enable(cpu);

	spin_lock(&c2_lock);

	if (check_cluster_idle_state(cpu)) {
		cluster_enable(cpu);
		update_cluster_idle_state(false, cpu);
	}

	if (pm_info->sicd_entered) {
		exynos_wakeup_sys_powerdown(SYS_SICD, enter_failed);
		exynos_ss_cpuidle(get_sys_powerdown_str(SYS_SICD),
						0, 0, ESS_FLAG_OUT);

		pm_info->sicd_entered = false;
	}

	update_c2_state(false, cpu);

	spin_unlock(&c2_lock);
}

/**
 * powermode_attr_read() / show_##file_name() -
 * print out power mode information
 *
 * powermode_attr_write() / store_##file_name() -
 * sysfs write access
 */
#define show_one(file_name, object)			\
static ssize_t show_##file_name(struct kobject *kobj,	\
	struct kobj_attribute *attr, char *buf)		\
{							\
	return snprintf(buf, 3, "%d\n",			\
				pm_info->object);	\
}

#define store_one(file_name, object)			\
static ssize_t store_##file_name(struct kobject *kobj,	\
	struct kobj_attribute *attr, const char *buf,	\
	size_t count)					\
{							\
	int input;					\
							\
	if (!sscanf(buf, "%1d", &input))		\
		return -EINVAL;				\
							\
	pm_info->object = !!input;				\
							\
	return count;					\
}

#define attr_rw(_name)					\
static struct kobj_attribute _name =			\
__ATTR(_name, 0644, show_##_name, store_##_name)

show_one(cpd, cpd_enabled);
show_one(sicd, sicd_enabled);
store_one(cpd, cpd_enabled);
store_one(sicd, sicd_enabled);

attr_rw(cpd);
attr_rw(sicd);

#endif /* __CONFIG_ARM64_EXYNOS_CPUIDLE__ */

/******************************************************************************
 *                              System power mode                             *
 ******************************************************************************/
#define PMU_EINT_WAKEUP_MASK	0x60C
static void exynos_set_wakeupmask(enum sys_powerdown mode)
{
	int i;
	u64 eintmask = exynos_get_eint_wake_mask();

	/* Set external interrupt mask */
	exynos_pmu_write(PMU_EINT_WAKEUP_MASK, (u32)eintmask);

	for (i = 0; i < pm_info->num_wakeup_mask; i++)
		exynos_pmu_write(pm_info->wakeup_mask_offset[i],
				pm_info->wakeup_mask[mode][i]);
}

int exynos_prepare_sys_powerdown(enum sys_powerdown mode)
{
	int ret;

#ifdef CONFIG_ARM64_EXYNOS_CPUIDLE
	exynos_set_idle_ip_mask(mode);
#endif
	exynos_set_wakeupmask(mode);

	ret = cal_pm_enter(mode);
	if (ret) {
		pr_err("CAL Fail to set powermode\n");
		goto out;
	}

	switch (mode) {
	case SYS_SICD:
		exynos_pm_notify(SICD_ENTER);
		break;
	default:
		break;
	}

out:
	return ret;
}

void exynos_wakeup_sys_powerdown(enum sys_powerdown mode, bool early_wakeup)
{
	if (early_wakeup)
		cal_pm_earlywakeup(mode);
	else
		cal_pm_exit(mode);

	switch (mode) {
	case SYS_SICD:
		exynos_pm_notify(SICD_EXIT);
		break;
	default:
		break;
	}
}

/******************************************************************************
 *                                  Notifier                                  *
 ******************************************************************************/
static int exynos_cpuidle_hotcpu_callback(struct notifier_block *nfb,
                                       unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned long)hcpu;
	struct cpumask mask;

	/*
	 * CPU_STARTING and CPU_DYING event are executed by incomming or
	 * outgoing cpu itself.
	 */
	switch (action) {
	case CPU_STARTING:
	case CPU_STARTING_FROZEN:
		cpumask_and(&mask, cpu_coregroup_mask(cpu), cpu_online_mask);
		if (cpumask_weight(&mask) == 0)
			cluster_enable(cpu);

		cpu_enable(cpu);
		break;
	case CPU_DYING:
	case CPU_DYING_FROZEN:
		cpu_disable(cpu);

		cpumask_and(&mask, cpu_coregroup_mask(cpu), cpu_online_mask);
		if (cpumask_weight(&mask) == 0)
			cluster_disable(cpu);
		break;
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		cpumask_and(&mask, cpu_coregroup_mask(cpu), cpu_online_mask);
		if (cpumask_weight(&mask) == 0) {
			/* Wait power down cluster */
			while (exynos_cpu.cluster_state(cpu))
				udelay(1);
		}
	}

	return NOTIFY_OK;
}

static struct notifier_block __refdata cpuidle_hotcpu_notifier = {
       .notifier_call = exynos_cpuidle_hotcpu_callback,
       .priority = INT_MAX,
};

/**
 * powermode_cpufreq_transition() blocks to power down the cluster
 * before frequency changing. And it release the blocking after
 * completion of frequency changing.
 */
#ifdef CONFIG_ARM64_EXYNOS_CPUIDLE
static void nop_func(void *info) {}
#endif
static int exynos_powermode_cpufreq_transition(struct notifier_block *nb,
				unsigned long val, void *data)
{
#ifdef CONFIG_ARM64_EXYNOS_CPUIDLE
	struct cpufreq_freqs *freq = data;
	int cpu = freq->cpu;

	/*
	 * Boot cluster does not support cluster power down.
	 * Do nothing in this notify call.
	 */
	if (is_cpu_boot_cluster(cpu))
		return NOTIFY_OK;

	if (!pm_info->cpd_enabled)
		return NOTIFY_OK;;

	switch (val) {
	case CPUFREQ_PRECHANGE:
		pm_info->cpd_blocking = true;
		if (check_cluster_idle_state(cpu))
			smp_call_function_single(cpu, nop_func, NULL, 0);
		break;
	case CPUFREQ_POSTCHANGE:
		pm_info->cpd_blocking = false;
		break;
	}
#endif

	return NOTIFY_OK;
}

static struct notifier_block exynos_powermode_cpufreq_notifier = {
	.notifier_call = exynos_powermode_cpufreq_transition,
};

/******************************************************************************
 *                               Extern function                              *
 ******************************************************************************/
int exynos_rtc_wakeup(void)
{
#define WAKEUP_MASK_RTC_TICK	BIT(2)
#define WAKEUP_MASK_RTC_ALARM	BIT(1)
	unsigned int sleep_mask = pm_info->wakeup_mask[SYS_SLEEP][0];

	if (!(sleep_mask & WAKEUP_MASK_RTC_ALARM) ||
			!(sleep_mask & WAKEUP_MASK_RTC_TICK))
		return 0;

	return -ENXIO;
}

/******************************************************************************
 *                            Driver initialization                           *
 ******************************************************************************/
static int alloc_wakeup_mask(int num_wakeup_mask)
{
	unsigned int mode;

	pm_info->wakeup_mask_offset = kzalloc(sizeof(unsigned int)
				* num_wakeup_mask, GFP_KERNEL);
	if (!pm_info->wakeup_mask_offset)
		return -ENOMEM;

	for_each_syspwr_mode(mode) {
		pm_info->wakeup_mask[mode] = kzalloc(sizeof(unsigned int)
				* num_wakeup_mask, GFP_KERNEL);

		if (!pm_info->wakeup_mask[mode])
			goto free_reg_offset;
	}

	return 0;

free_reg_offset:
	for_each_syspwr_mode(mode)
		if (pm_info->wakeup_mask[mode])
			kfree(pm_info->wakeup_mask[mode]);

	kfree(pm_info->wakeup_mask_offset);

	return -ENOMEM;
}

static int parsing_dt_wakeup_mask(struct device_node *np)
{
	int ret;
	struct device_node *root, *child;
	unsigned int mode, mask_index = 0;

	root = of_find_node_by_name(np, "wakeup-masks");
	pm_info->num_wakeup_mask = of_get_child_count(root);

	ret = alloc_wakeup_mask(pm_info->num_wakeup_mask);
	if (ret)
		return ret;

	for_each_child_of_node(root, child) {
		for_each_syspwr_mode(mode) {
			ret = of_property_read_u32_index(child, "mask",
				mode, &pm_info->wakeup_mask[mode][mask_index]);
			if (ret)
				return ret;
		}

		ret = of_property_read_u32(child, "reg-offset",
				&pm_info->wakeup_mask_offset[mask_index]);
		if (ret)
			return ret;

		mask_index++;
	}

	return 0;
}

static int __init dt_init(void)
{
	struct device_node *np = of_find_node_by_name(NULL, "exynos-powermode");
	int ret;

	ret = parsing_dt_wakeup_mask(np);
	if (ret)
		pr_warn("Fail to initialize the wakeup mask with err = %d\n", ret);

	if (of_property_read_u32(np, "cpd_residency", &pm_info->cpd_residency))
		pr_warn("No matching property: cpd_residency\n");

	if (of_property_read_u32(np, "sicd_residency", &pm_info->sicd_residency))
		pr_warn("No matching property: sicd_residency\n");

	if (of_property_read_u32(np, "cpd_enabled", &pm_info->cpd_enabled))
		pr_warn("No matching property: cpd_enabled\n");

	if (of_property_read_u32(np, "sicd_enabled", &pm_info->sicd_enabled))
		pr_warn("No matching property: sicd_enabled\n");

	return 0;
}

static int __init exynos_powermode_early_init(void)
{
#if defined(CONFIG_SOC_EXYNOS8890)
	int ret;

	/* The 8890 CPU power operations need the PMU map during SMP bring-up. */
	ret = exynos_pmu_early_init();
	if (ret) {
		pr_err("%s: failed to initialize PMU: %d\n", __func__, ret);
		return ret;
	}
#endif
	return register_hotcpu_notifier(&cpuidle_hotcpu_notifier);
}
early_initcall(exynos_powermode_early_init);

static int __init exynos_powermode_init(void)
{
	pm_info = kzalloc(sizeof(struct exynos_powermode_info), GFP_KERNEL);
	if (pm_info == NULL) {
		pr_err("%s: failed to allocate exynos_powermode_info\n", __func__);
		return -ENOMEM;
	}

	dt_init();

#ifdef CONFIG_ARM64_EXYNOS_CPUIDLE
	init_idle_ip();

	if (sysfs_create_file(power_kobj, &cpd.attr))
		pr_err("%s: failed to create sysfs to control CPD\n", __func__);

	if (sysfs_create_file(power_kobj, &sicd.attr))
		pr_err("%s: failed to create sysfs to control SICD\n", __func__);
#endif

	cpufreq_register_notifier(&exynos_powermode_cpufreq_notifier,
					CPUFREQ_TRANSITION_NOTIFIER);

	return 0;
}
arch_initcall(exynos_powermode_init);

#if defined(CONFIG_SEC_PM) && defined(CONFIG_MUIC_NOTIFIER)
struct notifier_block cpuidle_muic_nb;

static int exynos_cpuidle_muic_notifier(struct notifier_block *nb,
				unsigned long action, void *data)
{
#ifdef CONFIG_CCIC_NOTIFIER
	CC_NOTI_ATTACH_TYPEDEF *pnoti = (CC_NOTI_ATTACH_TYPEDEF *)data;
	muic_attached_dev_t attached_dev = pnoti->cable_type;
#else
	muic_attached_dev_t attached_dev = *(muic_attached_dev_t *)data;
#endif

	switch (attached_dev) {
	case ATTACHED_DEV_JIG_UART_OFF_MUIC:
	case ATTACHED_DEV_JIG_UART_OFF_VB_MUIC:
	case ATTACHED_DEV_JIG_UART_OFF_VB_OTG_MUIC:
	case ATTACHED_DEV_JIG_UART_OFF_VB_FG_MUIC:
#ifdef CONFIG_CCIC_NOTIFIER
	case ATTACHED_DEV_JIG_UART_ON_MUIC:
	case ATTACHED_DEV_JIG_UART_ON_VB_MUIC:
#endif
		if (action == MUIC_NOTIFY_CMD_DETACH)
			jig_is_attached = false;
		else if (action == MUIC_NOTIFY_CMD_ATTACH)
			jig_is_attached = true;
		else
			pr_err("%s: ACTION Error!\n", __func__);
		break;
	default:
		break;
	}

	pr_info("%s: dev=%d, action=%lu\n", __func__, attached_dev, action);

	return NOTIFY_DONE;
}

static int __init exynos_powermode_muic_notifier_init(void)
{
	return muic_notifier_register(&cpuidle_muic_nb,
			exynos_cpuidle_muic_notifier, MUIC_NOTIFY_DEV_CPUIDLE);
}
late_initcall(exynos_powermode_muic_notifier_init);
#endif

