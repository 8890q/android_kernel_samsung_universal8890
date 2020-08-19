/*
 *  linux/include/linux/nmi.h
 */
#ifndef LINUX_NMI_H
#define LINUX_NMI_H

#include <linux/sched.h>
#include <asm/irq.h>

/**
 * touch_nmi_watchdog - restart NMI watchdog timeout.
 * 
 * If the architecture supports the NMI watchdog, touch_nmi_watchdog()
 * may be used to reset the timeout - for code which intentionally
 * disables interrupts for a long time. This call is stateless.
 */
#if defined(CONFIG_HAVE_NMI_WATCHDOG) || defined(CONFIG_HARDLOCKUP_DETECTOR_NMI)
#include <asm/nmi.h>
#endif

#ifdef CONFIG_SEC_DEBUG
#define TASK_COMM_LEN 16
#define SOFTIRQ_TYPE_LEN 16

enum hardlockup_type {
	HL_TASK_STUCK = 1,
	HL_IRQ_STUCK,
	HL_IDLE_STUCK,
	HL_SMC_CALL_STUCK,
	HL_IRQ_STORM,
	HL_HRTIMER_ERROR,
	HL_UNKNOWN_STUCK
};

struct task_info {
	char task_comm[TASK_COMM_LEN];
};

struct cpuidle_info {
	char *mode;
};

struct smc_info {
	int cmd;
};

struct irq_info {
	int irq;
	void *fn;
	unsigned long long avg_period;
};

struct hardlockup_info {
	enum hardlockup_type hl_type;
	unsigned long long delay_time;
	union {
		struct task_info task_info;
		struct cpuidle_info cpuidle_info;
		struct smc_info smc_info;
		struct irq_info irq_info;
	};
};

struct softirq_info {
	u64 last_arrival;
	char softirq_type[SOFTIRQ_TYPE_LEN];
	void *fn;
};

enum softlockup_type {
	SL_SOFTIRQ_STUCK = 1,
	SL_TASK_STUCK,
	SL_UNKNOWN_STUCK
};

struct softlockup_info {
	enum softlockup_type sl_type;
	unsigned long long delay_time;
	int preempt_count;
	union {
		struct softirq_info softirq_info;
		struct task_info task_info;
	};
};
#if defined(CONFIG_HARDLOCKUP_DETECTOR_OTHER_CPU)
extern void update_hardlockup_type(unsigned int cpu);
unsigned long long get_hardlockup_thresh(void);
#endif

unsigned long long get_ess_softlockup_thresh(void);
extern void sl_softirq_entry(const char *, void *);
extern void sl_softirq_exit(void);
#else
static inline void void sl_softirq_entry(const char *, void *) { }
static inline void sl_softirq_exit(void) { }
#endif

#if defined(CONFIG_HAVE_NMI_WATCHDOG) || defined(CONFIG_HARDLOCKUP_DETECTOR)
extern void touch_nmi_watchdog(void);
#else
static inline void touch_nmi_watchdog(void)
{
	touch_softlockup_watchdog();
}
#endif

#if defined(CONFIG_HARDLOCKUP_DETECTOR)
extern void watchdog_enable_hardlockup_detector(bool val);
extern bool watchdog_hardlockup_detector_is_enabled(void);
#else
static inline void watchdog_enable_hardlockup_detector(bool val)
{
}
static inline bool watchdog_hardlockup_detector_is_enabled(void)
{
	return true;
}
#endif

/*
 * Create trigger_all_cpu_backtrace() out of the arch-provided
 * base function. Return whether such support was available,
 * to allow calling code to fall back to some other mechanism:
 */
#ifdef arch_trigger_all_cpu_backtrace
static inline bool trigger_all_cpu_backtrace(void)
{
	#if defined(CONFIG_ARM)
	arch_trigger_all_cpu_backtrace();
	#else
	arch_trigger_all_cpu_backtrace(true);
	#endif

	return true;
}
static inline bool trigger_allbutself_cpu_backtrace(void)
{
	#if defined(CONFIG_ARM)
	arch_trigger_all_cpu_backtrace();
	#else
	arch_trigger_all_cpu_backtrace(false);
	#endif


	return true;
}
#else
static inline bool trigger_all_cpu_backtrace(void)
{
	return false;
}
static inline bool trigger_allbutself_cpu_backtrace(void)
{
	return false;
}
#endif

#ifdef CONFIG_LOCKUP_DETECTOR
int hw_nmi_is_cpu_stuck(struct pt_regs *);
u64 hw_nmi_get_sample_period(int watchdog_thresh);
extern int watchdog_user_enabled;
extern int watchdog_thresh;
extern int sysctl_softlockup_all_cpu_backtrace;
struct ctl_table;
extern int proc_dowatchdog(struct ctl_table *, int ,
			   void __user *, size_t *, loff_t *);
#endif

#ifdef CONFIG_HAVE_ACPI_APEI_NMI
#include <asm/nmi.h>
#endif

#endif
