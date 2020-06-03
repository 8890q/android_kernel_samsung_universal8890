/*
 * Copyright (c) 2013-2017 TRUSTONIC LIMITED
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/workqueue.h>
#include <linux/cpu.h>
#include <linux/moduleparam.h>
#include <linux/debugfs.h>
#include <linux/sched.h>	/* local_clock */
#include <linux/version.h>
#if KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE
#include <linux/sched/clock.h>	/* local_clock */
#endif
#include <linux/uaccess.h>
#include <linux/irq.h>
#include <linux/interrupt.h>

#include "public/mc_user.h"
#include "public/mc_linux_api.h"

#include "mci/mcifc.h"

#include "platform.h"	/* MC_FASTCALL_WORKER_THREAD and more */
#include "main.h"
#include "clock.h"	/* mc_clock_enable, mc_clock_disable */
#include "fastcall.h"

/* ExySp: Lock for core switch processing */
#ifdef CONFIG_SECURE_OS_BOOSTER_API
struct mutex core_switch_lock;
uint8_t core_status = 0xFF;
static int disable_local_timer;
int mc_timer(void);
void mc_set_schedule_policy(int core);
int __mc_switch_core(int cpu);
#endif

#if KERNEL_VERSION(3, 15, 0) > LINUX_VERSION_CODE
#define MIN_NICE   -20
#endif

struct fastcall_work {
#ifdef MC_FASTCALL_WORKER_THREAD
	struct kthread_work work;
#else
	struct work_struct work;
#endif
	void *data;
};

/* generic fast call parameters */
union mc_fc_generic {
	struct mc_fc_as_in {
		u32 cmd;
		u32 param[3];
	} as_in;
	struct {
		u32 resp;
		u32 ret;
		u32 param[2];
	} as_out;
};

/* fast call init */
union mc_fc_init {
	union mc_fc_generic as_generic;
	struct {
		u32 cmd;
		u32 base;
		u32 nq_info;
		u32 mcp_info;
	} as_in;
	struct {
		u32 resp;
		u32 ret;
		u32 flags;
		u32 rfu;
	} as_out;
};

/* fast call info parameters */
union mc_fc_info {
	union mc_fc_generic as_generic;
	struct {
		u32 cmd;
		u32 ext_info_id;
		u32 rfu[2];
	} as_in;
	struct {
		u32 resp;
		u32 ret;
		u32 state;
		u32 ext_info;
	} as_out;
};

#ifdef TBASE_CORE_SWITCHER
/* fast call switch Core parameters */
union mc_fc_swich_core {
	union mc_fc_generic as_generic;
	struct {
		u32 cmd;
		u32 core_id;
		u32 rfu[2];
	} as_in;
	struct {
		u32 resp;
		u32 ret;
		u32 state;
		u32 ext_info;
	} as_out;
};
#endif

#ifdef MC_FASTCALL_WORKER_THREAD
static struct task_struct *fastcall_thread;
static DEFINE_KTHREAD_WORKER(fastcall_worker);
#endif

/* Structure to log SMC calls */
struct smc_log_entry {
	u64 cpu_clk;
	struct mc_fc_as_in as_in;
};

#define SMC_LOG_SIZE 256
static struct smc_log_entry smc_log[SMC_LOG_SIZE];
static int smc_log_index;

/*
 * _smc() - fast call to MobiCore
 *
 * @data: pointer to fast call data
 */
static inline int _smc(union mc_fc_generic *mc_fc_generic)
{
	if (!mc_fc_generic)
		return -EINVAL;

	/* Log SMC call */
	smc_log[smc_log_index].cpu_clk = local_clock();
	smc_log[smc_log_index].as_in = mc_fc_generic->as_in;
	if (++smc_log_index >= SMC_LOG_SIZE)
		smc_log_index = 0;

#ifdef MC_SMC_FASTCALL
	return smc_fastcall(mc_fc_generic, sizeof(*mc_fc_generic));
#else /* MC_SMC_FASTCALL */
	{
#ifdef CONFIG_ARM64
		/* SMC expect values in x0-x3 */
		register u64 reg0 __asm__("x0") = mc_fc_generic->as_in.cmd;
		register u64 reg1 __asm__("x1") = mc_fc_generic->as_in.param[0];
		register u64 reg2 __asm__("x2") = mc_fc_generic->as_in.param[1];
		register u64 reg3 __asm__("x3") = mc_fc_generic->as_in.param[2];

		/*
		 * According to AARCH64 SMC Calling Convention (ARM DEN 0028A),
		 * section 3.1: registers x4-x17 are unpredictable/scratch
		 * registers.  So we have to make sure that the compiler does
		 * not allocate any of those registers by letting him know that
		 * the asm code might clobber them.
		 */
		__asm__ volatile (
			"smc #0\n"
			: "+r"(reg0), "+r"(reg1), "+r"(reg2), "+r"(reg3)
			:
			: "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			  "x12", "x13", "x14", "x15", "x16", "x17"
		);
#else /* CONFIG_ARM64 */
		/* SMC expect values in r0-r3 */
		register u32 reg0 __asm__("r0") = mc_fc_generic->as_in.cmd;
		register u32 reg1 __asm__("r1") = mc_fc_generic->as_in.param[0];
		register u32 reg2 __asm__("r2") = mc_fc_generic->as_in.param[1];
		register u32 reg3 __asm__("r3") = mc_fc_generic->as_in.param[2];

		__asm__ volatile (
#ifdef MC_ARCH_EXTENSION_SEC
			/*
			 * This pseudo op is supported and required from
			 * binutils 2.21 on
			 */
			".arch_extension sec\n"
#endif /* MC_ARCH_EXTENSION_SEC */
			"smc #0\n"
			: "+r"(reg0), "+r"(reg1), "+r"(reg2), "+r"(reg3)
		);

#ifdef __ARM_VE_A9X4_QEMU__
		/*
		 * Qemu does not return to the address following the SMC
		 * instruction so we have to insert several nop instructions to
		 * workaround this Qemu bug.
		 */
		__asm__ volatile (
			"nop\n"
			"nop\n"
			"nop\n"
			"nop"
		);
#endif /* __ARM_VE_A9X4_QEMU__ */
#endif /* !CONFIG_ARM64 */

		/* set response */
		mc_fc_generic->as_out.resp     = reg0;
		mc_fc_generic->as_out.ret      = reg1;
		mc_fc_generic->as_out.param[0] = reg2;
		mc_fc_generic->as_out.param[1] = reg3;
	}
	return 0;
#endif /* !MC_SMC_FASTCALL */
}

#ifdef TBASE_CORE_SWITCHER
static int active_cpu;

#ifdef CONFIG_SECURE_OS_BOOSTER_API
/* ExySp: for sos performance */
void mc_set_schedule_policy(int core)
{
	if (core == DEFAULT_BIG_CORE)
		disable_local_timer = 1;
	else
		disable_local_timer = 0;

	return;
}
#endif

#ifdef MC_FASTCALL_WORKER_THREAD
#ifdef CONFIG_SECURE_OS_BOOSTER_API
/* ExySp: for sos performance */
static void mc_cpu_offline(int cpu)
{
	int i;

	mutex_lock(&core_switch_lock);
	core_status &= ~(0x1 << cpu);
	if (active_cpu != cpu) {
		mc_dev_devel("not active CPU, no action taken\n");
		mutex_unlock(&core_switch_lock);
		return;
	}

	/* Chose the first online CPU and switch! */
	for_each_online_cpu(i) {
		if (cpu != i) {
			mc_dev_devel("CPU %d is dying, switching to %d\n",
				     cpu, i);
			mc_set_schedule_policy(DEFAULT_LITTLE_CORE);
			__mc_switch_core(i);
			break;
		}

		mc_dev_devel("Skipping CPU %d\n", cpu);
	}
	mutex_unlock(&core_switch_lock);
}

void mc_cpu_online(int cpu)
{
	mutex_lock(&core_switch_lock);
	core_status |= (0x1 << cpu);

	if (cpu == NONBOOT_LITTLE_CORE)
		__mc_switch_core(NONBOOT_LITTLE_CORE);
	mutex_unlock(&core_switch_lock);
}
#else
static void mc_cpu_offline(int cpu)
{
	int i;

	if (active_cpu != cpu) {
		mc_dev_devel("not active CPU, no action taken\n");
		return;
	}

	/* Chose the first online CPU and switch! */
	for_each_online_cpu(i) {
		if (cpu != i) {
			mc_dev_devel("CPU %d is dying, switching to %d\n",
				     cpu, i);
			mc_switch_core(i);
			break;
		}

		mc_dev_devel("Skipping CPU %d\n", cpu);
	}
}
#endif

static int mobicore_cpu_callback(struct notifier_block *nfb,
				 unsigned long action, void *hcpu)
{
	int cpu = (int)(uintptr_t)hcpu;

	switch (action) {
#ifdef CONFIG_SECURE_OS_BOOSTER_API
/* ExySp: for sos performance */
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		mc_cpu_online(cpu);
		break;
#endif
	case CPU_DOWN_PREPARE:
	case CPU_DOWN_PREPARE_FROZEN:
		/* ExySp */
		mc_dev_devel("Cpu %d is going to hotplug out\n", cpu);
		mc_cpu_offline(cpu);
		break;
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		/* ExySp */
		mc_dev_devel("Cpu %d is hotplug out\n", cpu);
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block mobicore_cpu_notifer = {
	.notifier_call = mobicore_cpu_callback,
};
#endif /* MC_FASTCALL_WORKER_THREAD */

static cpumask_t mc_exec_core_switch(union mc_fc_generic *mc_fc_generic)
{
	cpumask_t cpu;
	int new_cpu;
	u32 cpu_id[] = CPU_IDS;

	new_cpu = mc_fc_generic->as_in.param[0];
	mc_fc_generic->as_in.param[0] = cpu_id[mc_fc_generic->as_in.param[0]];

	if (_smc(mc_fc_generic) != 0 || mc_fc_generic->as_out.ret != 0) {
		/* ExySp: print info */
		mc_dev_info("CoreSwap failed %d -> %d (cpu %d still active)\n",
			     raw_smp_processor_id(),
			     mc_fc_generic->as_in.param[0],
			     raw_smp_processor_id());
	} else {
		active_cpu = new_cpu;
		/* ExySp: print info */
		mc_dev_info("CoreSwap ok %d -> %d\n",
			     raw_smp_processor_id(), active_cpu);
	}
	cpumask_clear(&cpu);
	cpumask_set_cpu(active_cpu, &cpu);
	return cpu;
}

static ssize_t debug_coreswitch_write(struct file *file,
				      const char __user *buffer,
				      size_t buffer_len, loff_t *x)
{
	int new_cpu = 0;

	/* Invalid data, nothing to do */
	if (buffer_len < 1)
		return -EINVAL;

	if (kstrtoint_from_user(buffer, buffer_len, 0, &new_cpu))
		return -EINVAL;

	mc_dev_devel("Set active cpu to %d\n", new_cpu);
	mc_switch_core(new_cpu);
	return buffer_len;
}

static const struct file_operations mc_debug_coreswitch_ops = {
	.write = debug_coreswitch_write,
};
#else /* TBASE_CORE_SWITCHER */
static inline cpumask_t mc_exec_core_switch(union mc_fc_generic *mc_fc_generic)
{
	return CPU_MASK_CPU0;
}
#endif /* !TBASE_CORE_SWITCHER */

#ifdef MC_FASTCALL_WORKER_THREAD
static void fastcall_work_func(struct kthread_work *work)
#else
static void fastcall_work_func(struct work_struct *work)
#endif
{
	struct fastcall_work *fc_work =
		container_of(work, struct fastcall_work, work);
	union mc_fc_generic *mc_fc_generic = fc_work->data;
/* ExySp: for sos performance */
#ifdef CONFIG_SECURE_OS_BOOSTER_API
	int irq_check_cnt = 0;
	struct irq_desc *desc = irq_to_desc(MC_INTR_LOCAL_TIMER);
#endif

	if (!mc_fc_generic)
		return;

	mc_clock_enable();

	if (mc_fc_generic->as_in.cmd == MC_FC_SWAP_CPU) {
#ifdef MC_FASTCALL_WORKER_THREAD
		cpumask_t new_msk = mc_exec_core_switch(mc_fc_generic);

		set_cpus_allowed_ptr(fastcall_thread, &new_msk);
#else
		mc_exec_core_switch(mc_fc_generic);
#endif
	} else {
		/* ExySp: for sos performance */
#ifdef CONFIG_SECURE_OS_BOOSTER_API
		if (active_cpu == DEFAULT_BIG_CORE && disable_local_timer) {
			irq_check_cnt++;
			disable_irq(MC_INTR_LOCAL_TIMER);
			mc_timer();
		}
#endif
		_smc(mc_fc_generic);

	/* ExySp: for sos performance */
#ifdef CONFIG_SECURE_OS_BOOSTER_API
		if (irq_check_cnt) {
			if (desc->depth != 0)
				enable_irq(MC_INTR_LOCAL_TIMER);
		}
#endif
	}

	mc_clock_disable();
}

static bool mc_fastcall(void *data)
{
#ifdef MC_FASTCALL_WORKER_THREAD
	struct fastcall_work fc_work = {
		KTHREAD_WORK_INIT(fc_work.work, fastcall_work_func),
		.data = data,
	};

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
	if (!kthread_queue_work(&fastcall_worker, &fc_work.work))
		return false;

	/* If work is queued or executing, wait for it to finish execution */
	kthread_flush_work(&fc_work.work);
#else
	if (!queue_kthread_work(&fastcall_worker, &fc_work.work))
		return false;

	/* If work is queued or executing, wait for it to finish execution */
	flush_kthread_work(&fc_work.work);
#endif
#else
	struct fastcall_work fc_work = {
		.data = data,
	};
	INIT_WORK_ONSTACK(&fc_work.work, fastcall_work_func);

	if (!schedule_work_on(0, &fc_work.work))
		return false;

	flush_work(&fc_work.work);
#endif
	return true;
}

int mc_fastcall_init(void)
{
	cpumask_t new_msk = CPU_MASK_CPU0;
	int ret = mc_clock_init();

	if (ret)
		return ret;

#ifdef MC_FASTCALL_WORKER_THREAD
	fastcall_thread = kthread_create(kthread_worker_fn, &fastcall_worker,
					 "tee_fastcall");
	if (IS_ERR(fastcall_thread)) {
		ret = PTR_ERR(fastcall_thread);
		fastcall_thread = NULL;
		mc_dev_err("cannot create fastcall wq: %d\n", ret);
		return ret;
	}

	set_user_nice(fastcall_thread, MIN_NICE);

	/* this thread MUST run on CPU 0 at startup */
	set_cpus_allowed_ptr(fastcall_thread, &new_msk);

	wake_up_process(fastcall_thread);
#ifdef TBASE_CORE_SWITCHER
	ret = register_cpu_notifier(&mobicore_cpu_notifer);
	/* Create debugfs structs entry */
	debugfs_create_file("active_cpu", 0600, g_ctx.debug_dir, NULL,
			    &mc_debug_coreswitch_ops);
#endif
#endif /* MC_FASTCALL_WORKER_THREAD */

	/* ExySp: init lock for core switch processing */
#ifdef CONFIG_SECURE_OS_BOOSTER_API
	mutex_init(&core_switch_lock);
#endif

	return ret;
}

void mc_fastcall_exit(void)
{
#ifdef MC_FASTCALL_WORKER_THREAD
	if (!IS_ERR_OR_NULL(fastcall_thread)) {
#ifdef TBASE_CORE_SWITCHER
		unregister_cpu_notifier(&mobicore_cpu_notifer);
#endif
		kthread_stop(fastcall_thread);
		fastcall_thread = NULL;
	}
#endif /* MC_FASTCALL_WORKER_THREAD */
	mc_clock_exit();
}

/*
 * convert fast call return code to linux driver module error code
 */
static int convert_fc_ret(u32 ret)
{
	switch (ret) {
	case MC_FC_RET_OK:
		return 0;
	case MC_FC_RET_ERR_INVALID:
		return -EINVAL;
	case MC_FC_RET_ERR_ALREADY_INITIALIZED:
		return -EBUSY;
	default:
		return -EFAULT;
	}
}

int mc_fc_init(uintptr_t base_pa, ptrdiff_t off, size_t q_len, size_t buf_len)
{
#ifdef CONFIG_ARM64
	u32 base_high = (u32)(base_pa >> 32);
#else
	u32 base_high = 0;
#endif
	union mc_fc_init fc_init;

	/* Call the INIT fastcall to setup MobiCore initialization */
	memset(&fc_init, 0, sizeof(fc_init));
	fc_init.as_in.cmd = MC_FC_INIT;
	/* base address of mci buffer PAGE_SIZE (default is 4KB) aligned */
	fc_init.as_in.base = (u32)base_pa;
	/* notification buffer start/length [16:16] [start, length] */
	fc_init.as_in.nq_info =
	    (u32)(((base_high & 0xFFFF) << 16) | (q_len & 0xFFFF));
	/* mcp buffer start/length [16:16] [start, length] */
	fc_init.as_in.mcp_info = (u32)((off << 16) | (buf_len & 0xFFFF));
	mc_dev_devel("cmd=%d, base=0x%08x,nq_info=0x%08x, mcp_info=0x%08x\n",
		     fc_init.as_in.cmd, fc_init.as_in.base,
		     fc_init.as_in.nq_info, fc_init.as_in.mcp_info);
	mc_fastcall(&fc_init.as_generic);
	mc_dev_devel("out cmd=0x%08x, ret=0x%08x\n", fc_init.as_out.resp,
		     fc_init.as_out.ret);
	if (fc_init.as_out.flags & MC_FC_INIT_FLAG_LPAE)
		g_ctx.f_lpae = true;

	return convert_fc_ret(fc_init.as_out.ret);
}

int mc_fc_info(u32 ext_info_id, u32 *state, u32 *ext_info)
{
	union mc_fc_info fc_info;
	int ret = 0;

	memset(&fc_info, 0, sizeof(fc_info));
	fc_info.as_in.cmd = MC_FC_INFO;
	fc_info.as_in.ext_info_id = ext_info_id;
	mc_fastcall(&fc_info.as_generic);
	ret = convert_fc_ret(fc_info.as_out.ret);
	if (ret) {
		if (state)
			*state = MC_STATUS_NOT_INITIALIZED;

		if (ext_info)
			*ext_info = 0;

		mc_dev_err("code %d for idx %d\n", ret, ext_info_id);
	} else {
		if (state)
			*state = fc_info.as_out.state;

		if (ext_info)
			*ext_info = fc_info.as_out.ext_info;
	}

	return ret;
}

int mc_fc_mem_trace(phys_addr_t buffer, u32 size)
{
	union mc_fc_generic mc_fc_generic;

	memset(&mc_fc_generic, 0, sizeof(mc_fc_generic));
	mc_fc_generic.as_in.cmd = MC_FC_MEM_TRACE;
	mc_fc_generic.as_in.param[0] = (u32)buffer;
#ifdef CONFIG_ARM64
	mc_fc_generic.as_in.param[1] = (u32)(buffer >> 32);
#endif
	mc_fc_generic.as_in.param[2] = size;
	mc_fastcall(&mc_fc_generic);
	return convert_fc_ret(mc_fc_generic.as_out.ret);
}

int mc_fc_nsiq(void)
{
	union mc_fc_generic fc;
	int ret;

	memset(&fc, 0, sizeof(fc));
	fc.as_in.cmd = MC_SMC_N_SIQ;
	mc_fastcall(&fc);
	ret = convert_fc_ret(fc.as_out.ret);
	if (ret)
		mc_dev_err("failed: %d\n", ret);

	return ret;
}

int mc_fc_yield(void)
{
	union mc_fc_generic fc;
	int ret;

	memset(&fc, 0, sizeof(fc));
	fc.as_in.cmd = MC_SMC_N_YIELD;
	mc_fastcall(&fc);
	ret = convert_fc_ret(fc.as_out.ret);
	if (ret)
		mc_dev_err("failed: %d\n", ret);

	return ret;
}

static int show_smc_log_entry(struct kasnprintf_buf *buf,
			      struct smc_log_entry *entry)
{
	return kasnprintf(buf, "%20llu %10d 0x%08x 0x%08x 0x%08x\n",
			  entry->cpu_clk, (s32)entry->as_in.cmd,
			  entry->as_in.param[0], entry->as_in.param[1],
			  entry->as_in.param[2]);
}

/*
 * Dump SMC log circular buffer, starting from oldest command. It is assumed
 * nothing goes in any more at this point.
 */
int mc_fastcall_debug_smclog(struct kasnprintf_buf *buf)
{
	int i, ret = 0;

	ret = kasnprintf(buf, "%20s %10s %-10s %-10s %-10s\n",
			 "CPU clock", "command", "param1", "param2", "param3");
	if (ret < 0)
		return ret;

	if (smc_log[smc_log_index].cpu_clk)
		/* Buffer has wrapped around, dump end (oldest records) */
		for (i = smc_log_index; i < SMC_LOG_SIZE; i++) {
			ret = show_smc_log_entry(buf, &smc_log[i]);
			if (ret < 0)
				return ret;
		}

	/* Dump first records */
	for (i = 0; i < smc_log_index; i++) {
		ret = show_smc_log_entry(buf, &smc_log[i]);
		if (ret < 0)
			return ret;
	}

	return ret;
}

#ifdef TBASE_CORE_SWITCHER
int mc_active_core(void)
{
	return active_cpu;
}

/* ExySp: for sos performance */
#ifdef CONFIG_SECURE_OS_BOOSTER_API
int __mc_switch_core(int cpu)
#else
int mc_switch_core(int cpu)
#endif
{
	s32 ret = 0;
	union mc_fc_swich_core fc_switch_core;

	if (!cpu_online(cpu))
		return 1;

	memset(&fc_switch_core, 0, sizeof(fc_switch_core));
	fc_switch_core.as_in.cmd = MC_FC_SWAP_CPU;
	if (cpu < COUNT_OF_CPUS)
		fc_switch_core.as_in.core_id = cpu;
	else
		fc_switch_core.as_in.core_id = 0;

	mc_dev_devel("<- cmd=0x%08x, core_id=0x%08x\n",
		     fc_switch_core.as_in.cmd, fc_switch_core.as_in.core_id);
	/* ExySp: for sos performance */
	mc_dev_info("<- cpu=0x%08x, active_cpu=0x%08x\n",
		     cpu, active_cpu);
	mc_fastcall(&fc_switch_core.as_generic);
	ret = convert_fc_ret(fc_switch_core.as_out.ret);
	mc_dev_devel("exit with %d/0x%08X\n", ret, ret);
	return ret;
}

/* ExySp: for sos performance */
#ifdef CONFIG_SECURE_OS_BOOSTER_API
int mc_switch_core(int cpu)
{
       int ret;
       mutex_lock(&core_switch_lock);
       if (!(core_status & (0x1 << cpu))){
               mc_dev_devel("Core status... core #%d is off line\n", cpu);
               mutex_unlock(&core_switch_lock);
               return 1;
       }
       ret = __mc_switch_core(cpu);
       mutex_unlock(&core_switch_lock);
       return ret;
}
#endif
#endif
