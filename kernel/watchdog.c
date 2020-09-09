/*
 * Detect hard and soft lockups on a system
 *
 * started by Don Zickus, Copyright (C) 2010 Red Hat, Inc.
 *
 * Note: Most of this code is borrowed heavily from the original softlockup
 * detector, so thanks to Ingo for the initial implementation.
 * Some chunks also taken from the old x86-specific nmi watchdog code, thanks
 * to those contributors as well.
 */

#define pr_fmt(fmt) "NMI watchdog: " fmt

#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/nmi.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/smpboot.h>
#include <linux/sched/rt.h>

#include <asm/irq_regs.h>
#include <linux/kvm_para.h>
#include <linux/perf_event.h>

#ifdef CONFIG_SEC_DEBUG_EXTRA_INFO
#include <linux/sec_debug.h>
#endif

#include <linux/exynos-ss.h>
#include <linux/irqflags.h>

#ifdef CONFIG_SEC_DEBUG
static const char * const hl_to_name[] = {
	"NONE", "TASK STUCK", "IRQ STUCK",
	"IDLE STUCK", "SMCCALL STUCK", "IRQ STORM",
	"HRTIMER ERROR", "UNKNOWN STUCK"
};

static const char * const sl_to_name[] = {
	"NONE", "SOFTIRQ STUCK", "TASK STUCK", "UNKNOWN STUCK"
};

#endif
int watchdog_user_enabled = 1;
int __read_mostly watchdog_thresh = 10;
#ifdef CONFIG_SMP
int __read_mostly sysctl_softlockup_all_cpu_backtrace;
#else
#define sysctl_softlockup_all_cpu_backtrace 0
#endif

static int __read_mostly watchdog_running;
static u64 __read_mostly sample_period;
static unsigned long __read_mostly hardlockup_thresh;

static DEFINE_PER_CPU(unsigned long, watchdog_touch_ts);
static DEFINE_PER_CPU(unsigned long, hardlockup_touch_ts);
static DEFINE_PER_CPU(struct task_struct *, softlockup_watchdog);
static DEFINE_PER_CPU(struct hrtimer, watchdog_hrtimer);
static DEFINE_PER_CPU(bool, softlockup_touch_sync);
static DEFINE_PER_CPU(bool, soft_watchdog_warn);
static DEFINE_PER_CPU(unsigned long, hrtimer_interrupts);
static DEFINE_PER_CPU(unsigned long, soft_lockup_hrtimer_cnt);
static DEFINE_PER_CPU(struct task_struct *, softlockup_task_ptr_saved);
#ifdef CONFIG_HARDLOCKUP_DETECTOR
static DEFINE_PER_CPU(bool, hard_watchdog_warn);
static DEFINE_PER_CPU(bool, watchdog_nmi_touch);
static DEFINE_PER_CPU(unsigned long, hrtimer_interrupts_saved);
#endif
#ifdef CONFIG_HARDLOCKUP_DETECTOR_OTHER_CPU
static cpumask_t __read_mostly watchdog_cpus;
#endif
#ifdef CONFIG_HARDLOCKUP_DETECTOR_NMI
static DEFINE_PER_CPU(struct perf_event *, watchdog_ev);
#endif
static unsigned long soft_lockup_nmi_warn;

#ifdef CONFIG_SEC_DEBUG
static DEFINE_PER_CPU(struct softlockup_info, percpu_sl_info);
static void check_softlockup_type(void);

#ifdef CONFIG_HARDLOCKUP_DETECTOR_OTHER_CPU
static DEFINE_PER_CPU(struct hardlockup_info, percpu_hl_info);
static void check_hardlockup_type(unsigned int cpu);
#endif
#endif

/* boot commands */
/*
 * Should we panic when a soft-lockup or hard-lockup occurs:
 */
#ifdef CONFIG_HARDLOCKUP_DETECTOR
static int hardlockup_panic =
			CONFIG_BOOTPARAM_HARDLOCKUP_PANIC_VALUE;

static bool hardlockup_detector_enabled = true;
/*
 * We may not want to enable hard lockup detection by default in all cases,
 * for example when running the kernel as a guest on a hypervisor. In these
 * cases this function can be called to disable hard lockup detection. This
 * function should only be executed once by the boot processor before the
 * kernel command line parameters are parsed, because otherwise it is not
 * possible to override this in hardlockup_panic_setup().
 */
void watchdog_enable_hardlockup_detector(bool val)
{
	hardlockup_detector_enabled = val;
}

bool watchdog_hardlockup_detector_is_enabled(void)
{
	return hardlockup_detector_enabled;
}

static int __init hardlockup_panic_setup(char *str)
{
	if (!strncmp(str, "panic", 5))
		hardlockup_panic = 1;
	else if (!strncmp(str, "nopanic", 7))
		hardlockup_panic = 0;
	else if (!strncmp(str, "0", 1))
		watchdog_user_enabled = 0;
	else if (!strncmp(str, "1", 1) || !strncmp(str, "2", 1)) {
		/*
		 * Setting 'nmi_watchdog=1' or 'nmi_watchdog=2' (legacy option)
		 * has the same effect.
		 */
		watchdog_user_enabled = 1;
		watchdog_enable_hardlockup_detector(true);
	}
	return 1;
}
__setup("nmi_watchdog=", hardlockup_panic_setup);
#endif

unsigned int __read_mostly softlockup_panic =
			CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC_VALUE;

static int __init softlockup_panic_setup(char *str)
{
	softlockup_panic = simple_strtoul(str, NULL, 0);

	return 1;
}
__setup("softlockup_panic=", softlockup_panic_setup);

static int __init nowatchdog_setup(char *str)
{
	watchdog_user_enabled = 0;
	return 1;
}
__setup("nowatchdog", nowatchdog_setup);

/* deprecated */
static int __init nosoftlockup_setup(char *str)
{
	watchdog_user_enabled = 0;
	return 1;
}
__setup("nosoftlockup", nosoftlockup_setup);
/*  */
#ifdef CONFIG_SMP
static int __init softlockup_all_cpu_backtrace_setup(char *str)
{
	sysctl_softlockup_all_cpu_backtrace =
		!!simple_strtol(str, NULL, 0);
	return 1;
}
__setup("softlockup_all_cpu_backtrace=", softlockup_all_cpu_backtrace_setup);
#endif

/*
 * Hard-lockup warnings should be triggered after just a few seconds. Soft-
 * lockups can have false positives under extreme conditions. So we generally
 * want a higher threshold for soft lockups than for hard lockups. So we couple
 * the thresholds with a factor: we make the soft threshold twice the amount of
 * time the hard threshold is.
 */
static int get_softlockup_thresh(void)
{
	return watchdog_thresh * 2;
}

/*
 * Returns seconds, approximately.  We don't need nanosecond
 * resolution, and we don't need to waste time with a big divide when
 * 2^30ns == 1.074s.
 */
static unsigned long get_timestamp(void)
{
	return local_clock() >> 30LL;  /* 2^30 ~= 10^9 */
}

static void set_sample_period(void)
{
	/*
	 * convert watchdog_thresh from seconds to ns
	 * the divide by 5 is to give hrtimer several chances (two
	 * or three with the current relation between the soft
	 * and hard thresholds) to increment before the
	 * hardlockup detector generates a warning
	 */
	sample_period = get_softlockup_thresh() * ((u64)NSEC_PER_SEC / 5);
	hardlockup_thresh = sample_period * 3 / NSEC_PER_SEC;
}

/* Commands for resetting the watchdog */
static void __touch_watchdog(void)
{
	__this_cpu_write(watchdog_touch_ts, get_timestamp());
	__this_cpu_write(hardlockup_touch_ts, get_timestamp());
}

void touch_softlockup_watchdog(void)
{
	/*
	 * Preemption can be enabled.  It doesn't matter which CPU's timestamp
	 * gets zeroed here, so use the raw_ operation.
	 */
	raw_cpu_write(watchdog_touch_ts, 0);
}
EXPORT_SYMBOL(touch_softlockup_watchdog);

void touch_all_softlockup_watchdogs(void)
{
	int cpu;

	/*
	 * this is done lockless
	 * do we care if a 0 races with a timestamp?
	 * all it means is the softlock check starts one cycle later
	 */
	for_each_online_cpu(cpu)
		per_cpu(watchdog_touch_ts, cpu) = 0;
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR
void touch_nmi_watchdog(void)
{
	/*
	 * Using __raw here because some code paths have
	 * preemption enabled.  If preemption is enabled
	 * then interrupts should be enabled too, in which
	 * case we shouldn't have to worry about the watchdog
	 * going off.
	 */
	raw_cpu_write(watchdog_nmi_touch, true);
	touch_softlockup_watchdog();
}
EXPORT_SYMBOL(touch_nmi_watchdog);

#endif

void touch_softlockup_watchdog_sync(void)
{
	__this_cpu_write(softlockup_touch_sync, true);
	__this_cpu_write(watchdog_touch_ts, 0);
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR_NMI
/* watchdog detector functions */
static int is_hardlockup(void)
{
	unsigned long hrint = __this_cpu_read(hrtimer_interrupts);

	if (__this_cpu_read(hrtimer_interrupts_saved) == hrint)
		return 1;

	__this_cpu_write(hrtimer_interrupts_saved, hrint);
	return 0;
}
#endif

#ifdef CONFIG_HARDLOCKUP_DETECTOR_OTHER_CPU
static unsigned int watchdog_next_cpu(unsigned int cpu)
{
	cpumask_t cpus = watchdog_cpus;
	unsigned int next_cpu;

	next_cpu = cpumask_next(cpu, &cpus);
	if (next_cpu >= nr_cpu_ids)
		next_cpu = cpumask_first(&cpus);

	if (next_cpu == cpu)
		return nr_cpu_ids;

	return next_cpu;
}

static int is_hardlockup_other_cpu(unsigned int cpu)
{
	unsigned long hrint = per_cpu(hrtimer_interrupts, cpu);

	if (per_cpu(hrtimer_interrupts_saved, cpu) == hrint) {
		unsigned long now = get_timestamp();
		unsigned long touch_ts = per_cpu(hardlockup_touch_ts, cpu);

		if (time_after(now, touch_ts) &&
				(now - touch_ts >= hardlockup_thresh))
			return 1;
	}

	per_cpu(hrtimer_interrupts_saved, cpu) = hrint;
	return 0;
}

static void watchdog_check_hardlockup_other_cpu(void)
{
	unsigned int next_cpu;

	/*
	 * Test for hardlockups every 3 samples.  The sample period is
	 *  watchdog_thresh * 2 / 5, so 3 samples gets us back to slightly over
	 *  watchdog_thresh (over by 20%).
	 */
	if (__this_cpu_read(hrtimer_interrupts) % 3 != 0)
		return;

	/* check for a hardlockup on the next cpu */
	next_cpu = watchdog_next_cpu(smp_processor_id());
	if (next_cpu >= nr_cpu_ids)
		return;

	smp_rmb();

	if (per_cpu(watchdog_nmi_touch, next_cpu) == true) {
		per_cpu(watchdog_nmi_touch, next_cpu) = false;
		return;
	}

	if (is_hardlockup_other_cpu(next_cpu)) {
#ifdef CONFIG_SEC_DEBUG
		check_hardlockup_type(next_cpu);
#endif	
		/* only warn once */
		if (per_cpu(hard_watchdog_warn, next_cpu) == true)
			return;

		if (hardlockup_panic) {
			exynos_ss_set_hardlockup(hardlockup_panic);
			panic("Watchdog detected hard LOCKUP on cpu %u", next_cpu);
		} else {
			WARN(1, "Watchdog detected hard LOCKUP on cpu %u", next_cpu);
		}

		per_cpu(hard_watchdog_warn, next_cpu) = true;
	} else {
		per_cpu(hard_watchdog_warn, next_cpu) = false;
	}
}
#else
static inline void watchdog_check_hardlockup_other_cpu(void) { return; }
#endif

static int is_softlockup(unsigned long touch_ts)
{
	unsigned long now = get_timestamp();

	/* Warn about unreasonable delays: */
	if (time_after(now, touch_ts + get_softlockup_thresh()))
		return now - touch_ts;

	return 0;
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR_NMI

static struct perf_event_attr wd_hw_attr = {
	.type		= PERF_TYPE_HARDWARE,
	.config		= PERF_COUNT_HW_CPU_CYCLES,
	.size		= sizeof(struct perf_event_attr),
	.pinned		= 1,
	.disabled	= 1,
};

/* Callback function for perf event subsystem */
static void watchdog_overflow_callback(struct perf_event *event,
		 struct perf_sample_data *data,
		 struct pt_regs *regs)
{
	/* Ensure the watchdog never gets throttled */
	event->hw.interrupts = 0;

	if (__this_cpu_read(watchdog_nmi_touch) == true) {
		__this_cpu_write(watchdog_nmi_touch, false);
		return;
	}

	/* check for a hardlockup
	 * This is done by making sure our timer interrupt
	 * is incrementing.  The timer interrupt should have
	 * fired multiple times before we overflow'd.  If it hasn't
	 * then this is a good indication the cpu is stuck
	 */
	if (is_hardlockup()) {
		int this_cpu = smp_processor_id();

		/* only print hardlockups once */
		if (__this_cpu_read(hard_watchdog_warn) == true)
			return;

		if (hardlockup_panic) {
			exynos_ss_set_hardlockup(hardlockup_panic);
			panic("Watchdog detected hard LOCKUP on cpu %d",
			      this_cpu);
		} else {
			WARN(1, "Watchdog detected hard LOCKUP on cpu %d",
			     this_cpu);
		}

		__this_cpu_write(hard_watchdog_warn, true);
		return;
	}

	__this_cpu_write(hard_watchdog_warn, false);
	return;
}
#endif /* CONFIG_HARDLOCKUP_DETECTOR_NMI */

static void watchdog_interrupt_count(void)
{
	__this_cpu_inc(hrtimer_interrupts);
}

static int watchdog_nmi_enable(unsigned int cpu);
static void watchdog_nmi_disable(unsigned int cpu);

/* watchdog kicker functions */
static enum hrtimer_restart watchdog_timer_fn(struct hrtimer *hrtimer)
{
	unsigned long touch_ts = __this_cpu_read(watchdog_touch_ts);
	struct pt_regs *regs = get_irq_regs();
	int duration;
	int softlockup_all_cpu_backtrace = sysctl_softlockup_all_cpu_backtrace;

	/* try to enable log_kevent of exynos-snapshot if log_kevent was off because of rcu stall */
	exynos_ss_try_enable("log_kevent", NSEC_PER_SEC * 60);

	/* kick the hardlockup detector */
	watchdog_interrupt_count();

	/* test for hardlockups on the next cpu */
	watchdog_check_hardlockup_other_cpu();

	/* kick the softlockup detector */
	wake_up_process(__this_cpu_read(softlockup_watchdog));

	/* .. and repeat */
	hrtimer_forward_now(hrtimer, ns_to_ktime(sample_period));

	if (touch_ts == 0) {
		if (unlikely(__this_cpu_read(softlockup_touch_sync))) {
			/*
			 * If the time stamp was touched atomically
			 * make sure the scheduler tick is up to date.
			 */
			__this_cpu_write(softlockup_touch_sync, false);
			sched_clock_tick();
		}

		/* Clear the guest paused flag on watchdog reset */
		kvm_check_and_clear_guest_paused();
		__touch_watchdog();
		return HRTIMER_RESTART;
	}

	/* check for a softlockup
	 * This is done by making sure a high priority task is
	 * being scheduled.  The task touches the watchdog to
	 * indicate it is getting cpu time.  If it hasn't then
	 * this is a good indication some task is hogging the cpu
	 */
	duration = is_softlockup(touch_ts);
	if (unlikely(duration)) {
		/*
		 * If a virtual machine is stopped by the host it can look to
		 * the watchdog like a soft lockup, check to see if the host
		 * stopped the vm before we issue the warning
		 */
		if (kvm_check_and_clear_guest_paused())
			return HRTIMER_RESTART;

		/* only warn once */
		if (__this_cpu_read(soft_watchdog_warn) == true) {
			/*
			 * When multiple processes are causing softlockups the
			 * softlockup detector only warns on the first one
			 * because the code relies on a full quiet cycle to
			 * re-arm.  The second process prevents the quiet cycle
			 * and never gets reported.  Use task pointers to detect
			 * this.
			 */
			if (__this_cpu_read(softlockup_task_ptr_saved) !=
			    current) {
				__this_cpu_write(soft_watchdog_warn, false);
				__touch_watchdog();
			}
			return HRTIMER_RESTART;
		}

		if (softlockup_all_cpu_backtrace) {
			/* Prevent multiple soft-lockup reports if one cpu is already
			 * engaged in dumping cpu back traces
			 */
			if (test_and_set_bit(0, &soft_lockup_nmi_warn)) {
				/* Someone else will report us. Let's give up */
				__this_cpu_write(soft_watchdog_warn, true);
				return HRTIMER_RESTART;
			}
		}

		pr_auto(ASL1, "BUG: soft lockup - CPU#%d stuck for %us! [%s:%d]\n",
			smp_processor_id(), duration,
			current->comm, task_pid_nr(current));
#ifdef CONFIG_SEC_DEBUG
		check_softlockup_type();
#endif
		__this_cpu_write(softlockup_task_ptr_saved, current);
		print_modules();
		print_irqtrace_events(current);
		if (regs)
			show_regs(regs);
		else
			dump_stack();

		if (softlockup_all_cpu_backtrace) {
			/* Avoid generating two back traces for current
			 * given that one is already made above
			 */
			trigger_allbutself_cpu_backtrace();

			clear_bit(0, &soft_lockup_nmi_warn);
			/* Barrier to sync with other cpus */
			smp_mb__after_atomic();
		}

		add_taint(TAINT_SOFTLOCKUP, LOCKDEP_STILL_OK);
		if (softlockup_panic) {
#ifdef CONFIG_SEC_DEBUG_EXTRA_INFO
			if (regs) {
				sec_debug_set_extra_info_fault(WATCHDOG_FAULT, (unsigned long)regs->pc, regs);
				sec_debug_set_extra_info_backtrace(regs);
			}
#endif
			panic("softlockup: hung tasks");
		}
		__this_cpu_write(soft_watchdog_warn, true);
	} else
		__this_cpu_write(soft_watchdog_warn, false);

	return HRTIMER_RESTART;
}

static void watchdog_set_prio(unsigned int policy, unsigned int prio)
{
	struct sched_param param = { .sched_priority = prio };

	sched_setscheduler(current, policy, &param);
}

static void watchdog_enable(unsigned int cpu)
{
	struct hrtimer *hrtimer = raw_cpu_ptr(&watchdog_hrtimer);

	/* kick off the timer for the hardlockup detector */
	hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer->function = watchdog_timer_fn;

	/* Enable the perf event */
	watchdog_nmi_enable(cpu);

	/* done here because hrtimer_start can only pin to smp_processor_id() */
	hrtimer_start(hrtimer, ns_to_ktime(sample_period),
		      HRTIMER_MODE_REL_PINNED);

	/* initialize timestamp */
	watchdog_set_prio(SCHED_FIFO, MAX_RT_PRIO - 1);
	__touch_watchdog();
}

static void watchdog_disable(unsigned int cpu)
{
	struct hrtimer *hrtimer = raw_cpu_ptr(&watchdog_hrtimer);

	watchdog_set_prio(SCHED_NORMAL, 0);
	hrtimer_cancel(hrtimer);
	/* disable the perf event */
	watchdog_nmi_disable(cpu);
}

static void watchdog_cleanup(unsigned int cpu, bool online)
{
	watchdog_disable(cpu);
}

static int watchdog_should_run(unsigned int cpu)
{
	return __this_cpu_read(hrtimer_interrupts) !=
		__this_cpu_read(soft_lockup_hrtimer_cnt);
}

/*
 * The watchdog thread function - touches the timestamp.
 *
 * It only runs once every sample_period seconds (4 seconds by
 * default) to reset the softlockup timestamp. If this gets delayed
 * for more than 2*watchdog_thresh seconds then the debug-printout
 * triggers in watchdog_timer_fn().
 */
static void watchdog(unsigned int cpu)
{
	__this_cpu_write(soft_lockup_hrtimer_cnt,
			 __this_cpu_read(hrtimer_interrupts));
	__touch_watchdog();
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR_NMI
/*
 * People like the simple clean cpu node info on boot.
 * Reduce the watchdog noise by only printing messages
 * that are different from what cpu0 displayed.
 */
static unsigned long cpu0_err;

static int watchdog_nmi_enable(unsigned int cpu)
{
	struct perf_event_attr *wd_attr;
	struct perf_event *event = per_cpu(watchdog_ev, cpu);

	/*
	 * Some kernels need to default hard lockup detection to
	 * 'disabled', for example a guest on a hypervisor.
	 */
	if (!watchdog_hardlockup_detector_is_enabled()) {
		event = ERR_PTR(-ENOENT);
		goto handle_err;
	}

	/* is it already setup and enabled? */
	if (event && event->state > PERF_EVENT_STATE_OFF)
		goto out;

	/* it is setup but not enabled */
	if (event != NULL)
		goto out_enable;

	wd_attr = &wd_hw_attr;
	wd_attr->sample_period = hw_nmi_get_sample_period(watchdog_thresh);

	/* Try to register using hardware perf events */
	event = perf_event_create_kernel_counter(wd_attr, cpu, NULL, watchdog_overflow_callback, NULL);

handle_err:
	/* save cpu0 error for future comparision */
	if (cpu == 0 && IS_ERR(event))
		cpu0_err = PTR_ERR(event);

	if (!IS_ERR(event)) {
		/* only print for cpu0 or different than cpu0 */
		if (cpu == 0 || cpu0_err)
			pr_info("enabled on all CPUs, permanently consumes one hw-PMU counter.\n");
		goto out_save;
	}

	/* skip displaying the same error again */
	if (cpu > 0 && (PTR_ERR(event) == cpu0_err))
		return PTR_ERR(event);

	/* vary the KERN level based on the returned errno */
	if (PTR_ERR(event) == -EOPNOTSUPP)
		pr_info("disabled (cpu%i): not supported (no LAPIC?)\n", cpu);
	else if (PTR_ERR(event) == -ENOENT)
		pr_warn("disabled (cpu%i): hardware events not enabled\n",
			 cpu);
	else
		pr_err("disabled (cpu%i): unable to create perf event: %ld\n",
			cpu, PTR_ERR(event));
	return PTR_ERR(event);

	/* success path */
out_save:
	per_cpu(watchdog_ev, cpu) = event;
out_enable:
	perf_event_enable(per_cpu(watchdog_ev, cpu));
out:
	return 0;
}

static void watchdog_nmi_disable(unsigned int cpu)
{
	struct perf_event *event = per_cpu(watchdog_ev, cpu);

	if (event) {
		perf_event_disable(event);
		per_cpu(watchdog_ev, cpu) = NULL;

		/* should be in cleanup, but blocks oprofile */
		perf_event_release_kernel(event);
	}
	if (cpu == 0) {
		/* watchdog_nmi_enable() expects this to be zero initially. */
		cpu0_err = 0;
	}
}
#else
#ifdef CONFIG_HARDLOCKUP_DETECTOR_OTHER_CPU
static int watchdog_nmi_enable(unsigned int cpu)
{
	/*
	 * The new cpu will be marked online before the first hrtimer interrupt
	 * runs on it.  If another cpu tests for a hardlockup on the new cpu
	 * before it has run its first hrtimer, it will get a false positive.
	 * Touch the watchdog on the new cpu to delay the first check for at
	 * least 3 sampling periods to guarantee one hrtimer has run on the new
	 * cpu.
	 */
	per_cpu(watchdog_nmi_touch, cpu) = true;
	smp_wmb();
	cpumask_set_cpu(cpu, &watchdog_cpus);
	return 0;
}

static void watchdog_nmi_disable(unsigned int cpu)
{
	unsigned int next_cpu = watchdog_next_cpu(cpu);

	/*
	 * Offlining this cpu will cause the cpu before this one to start
	 * checking the one after this one.  If this cpu just finished checking
	 * the next cpu and updating hrtimer_interrupts_saved, and then the
	 * previous cpu checks it within one sample period, it will trigger a
	 * false positive.  Touch the watchdog on the next cpu to prevent it.
	 */
	if (next_cpu < nr_cpu_ids)
		per_cpu(watchdog_nmi_touch, next_cpu) = true;
	smp_wmb();
	cpumask_clear_cpu(cpu, &watchdog_cpus);
}
#else
static int watchdog_nmi_enable(unsigned int cpu) { return 0; }
static void watchdog_nmi_disable(unsigned int cpu) { return; }
#endif /* CONFIG_HARDLOCKUP_DETECTOR_OTHER_CPU */
#endif /* CONFIG_HARDLOCKUP_DETECTOR_NMI */

static struct smp_hotplug_thread watchdog_threads = {
	.store			= &softlockup_watchdog,
	.thread_should_run	= watchdog_should_run,
	.thread_fn		= watchdog,
	.thread_comm		= "watchdog/%u",
	.setup			= watchdog_enable,
	.cleanup		= watchdog_cleanup,
	.park			= watchdog_disable,
	.unpark			= watchdog_enable,
};

static void restart_watchdog_hrtimer(void *info)
{
	struct hrtimer *hrtimer = raw_cpu_ptr(&watchdog_hrtimer);
	int ret;

	/*
	 * No need to cancel and restart hrtimer if it is currently executing
	 * because it will reprogram itself with the new period now.
	 * We should never see it unqueued here because we are running per-cpu
	 * with interrupts disabled.
	 */
	ret = hrtimer_try_to_cancel(hrtimer);
	if (ret == 1)
		hrtimer_start(hrtimer, ns_to_ktime(sample_period),
				HRTIMER_MODE_REL_PINNED);
}

static void update_timers(int cpu)
{
	/*
	 * Make sure that perf event counter will adopt to a new
	 * sampling period. Updating the sampling period directly would
	 * be much nicer but we do not have an API for that now so
	 * let's use a big hammer.
	 * Hrtimer will adopt the new period on the next tick but this
	 * might be late already so we have to restart the timer as well.
	 */
	watchdog_nmi_disable(cpu);
	smp_call_function_single(cpu, restart_watchdog_hrtimer, NULL, 1);
	watchdog_nmi_enable(cpu);
}

static void update_timers_all_cpus(void)
{
	int cpu;

	get_online_cpus();
	for_each_online_cpu(cpu)
		update_timers(cpu);
	put_online_cpus();
}

static int watchdog_enable_all_cpus(bool sample_period_changed)
{
	int err = 0;

	if (!watchdog_running) {
		err = smpboot_register_percpu_thread(&watchdog_threads);
		if (err)
			pr_err("Failed to create watchdog threads, disabled\n");
		else
			watchdog_running = 1;
	} else if (sample_period_changed) {
		update_timers_all_cpus();
	}

	return err;
}

/* prepare/enable/disable routines */
/* sysctl functions */
#ifdef CONFIG_SYSCTL
static void watchdog_disable_all_cpus(void)
{
	if (watchdog_running) {
		watchdog_running = 0;
		smpboot_unregister_percpu_thread(&watchdog_threads);
	}
}

/*
 * proc handler for /proc/sys/kernel/nmi_watchdog,watchdog_thresh
 */

int proc_dowatchdog(struct ctl_table *table, int write,
		    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int err, old_thresh, old_enabled;
	bool old_hardlockup;
	static DEFINE_MUTEX(watchdog_proc_mutex);

	mutex_lock(&watchdog_proc_mutex);
	old_thresh = ACCESS_ONCE(watchdog_thresh);
	old_enabled = ACCESS_ONCE(watchdog_user_enabled);
	old_hardlockup = watchdog_hardlockup_detector_is_enabled();

	err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (err || !write)
		goto out;

	set_sample_period();
	/*
	 * Watchdog threads shouldn't be enabled if they are
	 * disabled. The 'watchdog_running' variable check in
	 * watchdog_*_all_cpus() function takes care of this.
	 */
	if (watchdog_user_enabled && watchdog_thresh) {
		/*
		 * Prevent a change in watchdog_thresh accidentally overriding
		 * the enablement of the hardlockup detector.
		 */
		if (watchdog_user_enabled != old_enabled)
			watchdog_enable_hardlockup_detector(true);
		err = watchdog_enable_all_cpus(old_thresh != watchdog_thresh);
	} else
		watchdog_disable_all_cpus();

	/* Restore old values on failure */
	if (err) {
		watchdog_thresh = old_thresh;
		watchdog_user_enabled = old_enabled;
		watchdog_enable_hardlockup_detector(old_hardlockup);
	}
out:
	mutex_unlock(&watchdog_proc_mutex);
	return err;
}
#endif /* CONFIG_SYSCTL */

void __init lockup_detector_init(void)
{
	set_sample_period();

	if (watchdog_user_enabled)
		watchdog_enable_all_cpus(false);
}

#ifdef CONFIG_SEC_DEBUG
void sl_softirq_entry(const char *softirq_type, void *fn)
{
	struct softlockup_info *sl_info = per_cpu_ptr(&percpu_sl_info, smp_processor_id());

	if (softirq_type) {
		strncpy(sl_info->softirq_info.softirq_type, softirq_type, sizeof(sl_info->softirq_info.softirq_type) - 1);
		sl_info->softirq_info.softirq_type[SOFTIRQ_TYPE_LEN - 1] = '\0';
	}
	sl_info->softirq_info.last_arrival = local_clock();
	sl_info->softirq_info.fn = fn;
}

void sl_softirq_exit(void)
{
	struct softlockup_info *sl_info = per_cpu_ptr(&percpu_sl_info, smp_processor_id());

	sl_info->softirq_info.last_arrival = 0;
	sl_info->softirq_info.fn = (void *)0;
	sl_info->softirq_info.softirq_type[0] = '\0';
}

void check_softlockup_type(void)
{
	int cpu = smp_processor_id();
	struct softlockup_info *sl_info = per_cpu_ptr(&percpu_sl_info, cpu);

	sl_info->preempt_count = preempt_count();
	if (softirq_count() &&
		sl_info->softirq_info.last_arrival != 0 && sl_info->softirq_info.fn != NULL) {
		sl_info->delay_time = local_clock() - sl_info->softirq_info.last_arrival;
		sl_info->sl_type = SL_SOFTIRQ_STUCK;
		pr_auto(ASL9, "Softlockup state: %s, Latency: %lluns, Softirq type: %s, Func: %pf, preempt_count : %x\n",
			sl_to_name[sl_info->sl_type], sl_info->delay_time, sl_info->softirq_info.softirq_type, sl_info->softirq_info.fn, sl_info->preempt_count);
	} else {
		exynos_ss_get_softlockup_info(cpu, sl_info);
		if (!(preempt_count() & PREEMPT_MASK) || softirq_count())
			sl_info->sl_type = SL_UNKNOWN_STUCK;
		pr_auto(ASL9, "Softlockup state: %s, Latency: %lluns, Task: %s, preempt_count: %x\n",
			sl_to_name[sl_info->sl_type], sl_info->delay_time, sl_info->task_info.task_comm, sl_info->preempt_count);
	}
}

unsigned long long get_ess_softlockup_thresh(void)
{
	return watchdog_thresh * 2 * NSEC_PER_SEC;
}
EXPORT_SYMBOL(get_ess_softlockup_thresh);

#ifdef CONFIG_HARDLOCKUP_DETECTOR_OTHER_CPU
static void check_hardlockup_type(unsigned int cpu)
{
	struct hardlockup_info *hl_info = per_cpu_ptr(&percpu_hl_info, cpu);

	exynos_ss_get_hardlockup_info(cpu, hl_info);

	if (hl_info->hl_type == HL_TASK_STUCK) {
		pr_auto(ASL9, "Hardlockup state: %s, Latency: %lluns, TASK: %s\n",
			hl_to_name[hl_info->hl_type], hl_info->delay_time, hl_info->task_info.task_comm);
	} else if (hl_info->hl_type == HL_IRQ_STUCK) {
		pr_auto(ASL9, "Hardlockup state: %s, Latency: %lluns, IRQ: %d, Func: %pf\n",
			hl_to_name[hl_info->hl_type], hl_info->delay_time, hl_info->irq_info.irq, hl_info->irq_info.fn);
	} else if (hl_info->hl_type == HL_IDLE_STUCK) {
		pr_auto(ASL9, "Hardlockup state: %s, Latency: %lluns, mode: %s\n",
			hl_to_name[hl_info->hl_type], hl_info->delay_time,  hl_info->cpuidle_info.mode);
	} else if (hl_info->hl_type == HL_SMC_CALL_STUCK) {
		pr_auto(ASL9, "Hardlockup state: %s, Latency: %lluns, CMD: %u\n",
			hl_to_name[hl_info->hl_type], hl_info->delay_time,  hl_info->smc_info.cmd);
	} else if (hl_info->hl_type == HL_IRQ_STORM) {
		pr_auto(ASL9, "Hardlockup state: %s, Latency: %lluns, IRQ : %d, Func: %pf, Avg period: %lluns\n",
			hl_to_name[hl_info->hl_type], hl_info->delay_time, hl_info->irq_info.irq, hl_info->irq_info.fn, hl_info->irq_info.avg_period);
	} else if (hl_info->hl_type == HL_UNKNOWN_STUCK) {
		pr_auto(ASL9, "Hardlockup state: %s, Latency: %lluns, TASK: %s\n",
			hl_to_name[hl_info->hl_type], hl_info->delay_time, hl_info->task_info.task_comm);
	}
}

void update_hardlockup_type(unsigned int cpu)
{
	struct hardlockup_info *hl_info = per_cpu_ptr(&percpu_hl_info, cpu);

	if (hl_info->hl_type == HL_TASK_STUCK && !irqs_disabled()) {
		hl_info->hl_type = HL_UNKNOWN_STUCK;
		pr_info("Unknown stuck because IRQ was enabled but IRQ was not generated\n");
	}
}
EXPORT_SYMBOL(update_hardlockup_type);

unsigned long long get_hardlockup_thresh(void)
{
	return (hardlockup_thresh * NSEC_PER_SEC - sample_period);
}
EXPORT_SYMBOL(get_hardlockup_thresh);
#endif
#endif
