/* drivers/gpu/arm/.../platform/mali_kbase_platform.c
 *
 * Copyright 2011 by S.LSI. Samsung Electronics Inc.
 * San#24, Nongseo-Dong, Giheung-Gu, Yongin, Korea
 *
 * Samsung SoC Mali-T Series platform-dependent codes
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software FoundatIon.
 */

/**
 * @file mali_kbase_platform.c
 * Platform-dependent init.
 */

#include <mali_kbase.h>

#include "mali_kbase_platform.h"
#include "gpu_custom_interface.h"
#include "gpu_dvfs_handler.h"
#include "gpu_notifier.h"
#include "gpu_dvfs_governor.h"
#include "gpu_control.h"

// MALI_SEC_SECURE_RENDERING_ASP
#if MALI_SEC_ASP_SECURE_BUF_CTRL && !MALI_SEC_ASP_SECURE_RENDERING
#error YOU MUST check definition for Secure Rendering!!
#endif

/* MALI_SEC_SECURE_RENDERING */
#if defined(CONFIG_ION) && defined(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
#include <linux/smc.h>
#include <asm/cacheflush.h>
#if MALI_SEC_ASP_SECURE_BUF_CTRL
#include <linux/exynos_ion.h>
extern struct ion_device *ion_exynos;
#endif
#endif

struct kbase_device *pkbdev;
static int gpu_debug_level;

struct kbase_device *gpu_get_device_structure(void)
{
	return pkbdev;
}

void gpu_set_debug_level(int level)
{
	gpu_debug_level = level;
}

int gpu_get_debug_level(void)
{
	return gpu_debug_level;
}

#ifdef CONFIG_MALI_EXYNOS_TRACE
struct kbase_trace exynos_trace_buf[KBASE_TRACE_SIZE];
extern const struct file_operations kbasep_trace_debugfs_fops;
static int gpu_trace_init(struct kbase_device *kbdev)
{
	kbdev->trace_rbuf = exynos_trace_buf;

	spin_lock_init(&kbdev->trace_lock);
//	kbasep_trace_debugfs_init(kbdev);
/* below work : register entry from making debugfs create file to trace_dentry
 * is same work as kbasep_trace_debugfs_init */
#ifdef MALI_SEC_INTEGRATION
	kbdev->trace_dentry = debugfs_create_file("mali_trace", S_IRUGO,
			kbdev->mali_debugfs_directory, kbdev,
			&kbasep_trace_debugfs_fops);
#endif /* MALI_SEC_INTEGRATION */
	return 0;
}

static int gpu_trace_level;

void gpu_set_trace_level(int level)
{
	int i;

	if (level == TRACE_ALL) {
		for (i = TRACE_NONE + 1; i < TRACE_ALL; i++)
			gpu_trace_level |= (1U << i);
	} else if (level == TRACE_NONE) {
		gpu_trace_level = TRACE_NONE;
	} else {
		gpu_trace_level |= (1U << level);
	}
}

bool gpu_check_trace_level(int level)
{
	if (gpu_trace_level & (1U << level))
		return true;
	return false;
}

bool gpu_check_trace_code(int code)
{
	int level;
	switch (code) {
	case KBASE_TRACE_CODE(DUMMY):
		return false;
	case KBASE_TRACE_CODE(LSI_CLOCK_VALUE):
	case KBASE_TRACE_CODE(LSI_CLOCK_ON):
	case KBASE_TRACE_CODE(LSI_CLOCK_OFF):
	case KBASE_TRACE_CODE(LSI_GPU_MAX_LOCK):
	case KBASE_TRACE_CODE(LSI_GPU_MIN_LOCK):
		level = TRACE_CLK;
		break;
	case KBASE_TRACE_CODE(LSI_VOL_VALUE):
		level = TRACE_VOL;
		break;
	case KBASE_TRACE_CODE(LSI_GPU_ON):
	case KBASE_TRACE_CODE(LSI_GPU_OFF):
	case KBASE_TRACE_CODE(LSI_SUSPEND):
	case KBASE_TRACE_CODE(LSI_RESUME):
	case KBASE_TRACE_CODE(LSI_TMU_VALUE):
		level = TRACE_NOTIFIER;
		break;
	case KBASE_TRACE_CODE(LSI_REGISTER_DUMP):
		level = TRACE_DUMP;
		break;
	default:
		level = TRACE_DEFAULT;
		break;
	}

	return gpu_check_trace_level(level);
}
#endif /* CONFIG_MALI_EXYNOS_TRACE */

uintptr_t gpu_get_attrib_data(gpu_attribute *attrib, int id)
{
	int i;

	for (i = 0; i < GPU_CONFIG_LIST_END; i++) {
		if (attrib[i].id == id)
			return attrib[i].data;
	}

	return 0;
}

static int gpu_validate_attrib_data(struct exynos_context *platform)
{
	uintptr_t data;
	gpu_attribute *attrib = (gpu_attribute *)gpu_get_config_attributes();

	platform->attrib = attrib;

	data = gpu_get_attrib_data(attrib, GPU_MAX_CLOCK);
	platform->gpu_max_clock = data == 0 ? 500 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_MAX_CLOCK_LIMIT);
	platform->gpu_max_clock_limit = data == 0 ? 500 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_MIN_CLOCK);
	platform->gpu_min_clock = data == 0 ? 160 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_DVFS_BL_CONFIG_CLOCK);
	platform->gpu_dvfs_config_clock = data == 0 ? 266 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_DVFS_START_CLOCK);
	platform->gpu_dvfs_start_clock = data == 0 ? 266 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_DVFS_BL_CONFIG_CLOCK);
	platform->gpu_dvfs_config_clock = data == 0 ? 266 : (u32) data;

#ifdef CONFIG_MALI_DVFS
#ifdef CONFIG_CPU_THERMAL_IPA
	data = gpu_get_attrib_data(attrib, GPU_POWER_COEFF);
	platform->ipa_power_coeff_gpu = data == 0 ? 59 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_DVFS_TIME_INTERVAL);
	platform->gpu_dvfs_time_interval = data == 0 ? 5 : (u32) data;
#endif /* CONFIG_CPU_THERMAL_IPA */
	data = gpu_get_attrib_data(attrib, GPU_DEFAULT_WAKEUP_LOCK);
	platform->wakeup_lock = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_TYPE);
	platform->governor_type = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_START_CLOCK_DEFAULT);
	gpu_dvfs_update_start_clk(G3D_DVFS_GOVERNOR_DEFAULT, data == 0 ? 266 : (u32) data);
	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_TABLE_DEFAULT);
	gpu_dvfs_update_table(G3D_DVFS_GOVERNOR_DEFAULT, (gpu_dvfs_info *) data);
	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_TABLE_SIZE_DEFAULT);
	gpu_dvfs_update_table_size(G3D_DVFS_GOVERNOR_DEFAULT, (u32) data);

	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_START_CLOCK_STATIC);
	gpu_dvfs_update_start_clk(G3D_DVFS_GOVERNOR_STATIC, data == 0 ? 266 : (u32) data);
	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_TABLE_STATIC);
	gpu_dvfs_update_table(G3D_DVFS_GOVERNOR_STATIC, (gpu_dvfs_info *) data);
	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_TABLE_SIZE_STATIC);
	gpu_dvfs_update_table_size(G3D_DVFS_GOVERNOR_STATIC, (u32) data);

	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_START_CLOCK_BOOSTER);
	gpu_dvfs_update_start_clk(G3D_DVFS_GOVERNOR_BOOSTER, data == 0 ? 266 : (u32) data);
	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_TABLE_BOOSTER);
	gpu_dvfs_update_table(G3D_DVFS_GOVERNOR_BOOSTER, (gpu_dvfs_info *) data);
	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_TABLE_SIZE_BOOSTER);
	gpu_dvfs_update_table_size(G3D_DVFS_GOVERNOR_BOOSTER, (u32) data);

	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_START_CLOCK_INTERACTIVE);
	gpu_dvfs_update_start_clk(G3D_DVFS_GOVERNOR_INTERACTIVE, data == 0 ? 266 : (u32) data);
	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_TABLE_INTERACTIVE);
	gpu_dvfs_update_table(G3D_DVFS_GOVERNOR_INTERACTIVE, (gpu_dvfs_info *) data);
	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_TABLE_SIZE_INTERACTIVE);
	gpu_dvfs_update_table_size(G3D_DVFS_GOVERNOR_INTERACTIVE, (u32) data);
	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_INTERACTIVE_HIGHSPEED_CLOCK);
	platform->interactive.highspeed_clock = data == 0 ? 500 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_INTERACTIVE_HIGHSPEED_LOAD);
	platform->interactive.highspeed_load = data == 0 ? 100 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_GOVERNOR_INTERACTIVE_HIGHSPEED_DELAY);
	platform->interactive.highspeed_delay = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_DVFS_POLLING_TIME);
	platform->polling_speed = data == 0 ? 100 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_PMQOS_INT_DISABLE);
	platform->pmqos_int_disable = data == 0 ? 0 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_PMQOS_MIF_MAX_CLOCK);
	platform->pmqos_mif_max_clock = data == 0 ? 0 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_PMQOS_MIF_MAX_CLOCK_BASE);
	platform->pmqos_mif_max_clock_base = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_CL_DVFS_START_BASE);
	platform->cl_dvfs_start_base = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_TEMP_THROTTLING1);
	platform->tmu_lock_clk[THROTTLING1] = data == 0 ? 266 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_TEMP_THROTTLING2);
	platform->tmu_lock_clk[THROTTLING2] = data == 0 ? 266 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_TEMP_THROTTLING3);
	platform->tmu_lock_clk[THROTTLING3] = data == 0 ? 266 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_TEMP_THROTTLING4);
	platform->tmu_lock_clk[THROTTLING4] = data == 0 ? 266 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_TEMP_THROTTLING5);
	platform->tmu_lock_clk[THROTTLING5] = data == 0 ? 266 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_TEMP_TRIPPING);
	platform->tmu_lock_clk[TRIPPING] = data == 0 ? 266 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_BOOST_MIN_LOCK);
	platform->boost_gpu_min_lock = data == 0 ? 0 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_BOOST_EGL_MIN_LOCK);
	platform->boost_egl_min_lock = data == 0 ? 0 : (u32) data;
#endif /* CONFIG_MALI_DVFS */

	data = gpu_get_attrib_data(attrib, GPU_TMU_CONTROL);
	platform->tmu_status = data == 0 ? 0 : data;

	data = gpu_get_attrib_data(attrib, GPU_DEFAULT_VOLTAGE);
	platform->gpu_default_vol = data == 0 ? 0 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_COLD_MINIMUM_VOL);
	platform->cold_min_vol = data == 0 ? 0 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_VOLTAGE_OFFSET_MARGIN);
	platform->gpu_default_vol_margin = data == 0 ? 37500 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_BUS_DEVFREQ);
	platform->devfreq_status = data == 0 ? 1 : data;
	data = gpu_get_attrib_data(attrib, GPU_DYNAMIC_ABB);
	platform->dynamic_abb_status = data == 0 ? 0 : data;
	data = gpu_get_attrib_data(attrib, GPU_EARLY_CLK_GATING);
	platform->early_clk_gating_status = data == 0 ? 0 : data;
	data = gpu_get_attrib_data(attrib, GPU_DVS);
	platform->dvs_status = data == 0 ? 0 : data;

	data = gpu_get_attrib_data(attrib, GPU_PERF_GATHERING);
	platform->perf_gathering_status = data == 0 ? 0 : data;

#ifdef MALI_SEC_HWCNT
	data = gpu_get_attrib_data(attrib, GPU_HWCNT_GATHERING);
	platform->hwcnt_gathering_status = data == 0 ? 0 : data;

	data = gpu_get_attrib_data(attrib, GPU_HWCNT_GPR);
	platform->hwcnt_gpr_status = data == 0 ? 0 : data;

	data = gpu_get_attrib_data(attrib, GPU_HWCNT_POLLING_TIME);
	platform->hwcnt_polling_speed = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_HWCNT_UP_STEP);
	platform->hwcnt_up_step = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_HWCNT_DOWN_STEP);
	platform->hwcnt_down_step = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_HWCNT_DUMP_PERIOD);
	platform->hwcnt_dump_period = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_HWCNT_CHOOSE_JM);
	platform->hwcnt_choose_jm = data == 0 ? 0 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_HWCNT_CHOOSE_SHADER);
	platform->hwcnt_choose_shader = data == 0 ? 0 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_HWCNT_CHOOSE_TILER);
	platform->hwcnt_choose_tiler = data == 0 ? 0 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_HWCNT_CHOOSE_L3_CACHE);
	platform->hwcnt_choose_l3_cache = data == 0 ? 0 : (u32) data;
	data = gpu_get_attrib_data(attrib, GPU_HWCNT_CHOOSE_MMU_L2);
	platform->hwcnt_choose_mmu_l2 = data == 0 ? 0 : (u32) data;
#endif

	data = gpu_get_attrib_data(attrib, GPU_RUNTIME_PM_DELAY_TIME);
	platform->runtime_pm_delay_time = data == 0 ? 50 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_DEBUG_LEVEL);
	gpu_debug_level = data == 0 ? DVFS_WARNING : (u32) data;
#ifdef CONFIG_MALI_EXYNOS_TRACE
	data = gpu_get_attrib_data(attrib, GPU_TRACE_LEVEL);
	gpu_set_trace_level(data == 0 ? TRACE_ALL : (u32) data);
#endif /* CONFIG_MALI_EXYNOS_TRACE */
#ifdef CONFIG_MALI_DVFS_USER
	data = gpu_get_attrib_data(attrib, GPU_UDVFS_ENABLE);
	platform->udvfs_enable = data == 0 ? 0 : (u32) data;
#endif
	data = gpu_get_attrib_data(attrib, GPU_MO_MIN_CLOCK);
	platform->mo_min_clock = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_SUSTAINABLE_GPU_CLOCK);
	platform->sustainable.sustainable_gpu_clock = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_LOW_POWER_CPU_MAX_LOCK);
	platform->sustainable.low_power_cluster1_maxlock = data == 0 ? 0 : (u32) data;

	data = gpu_get_attrib_data(attrib, GPU_THRESHOLD_MAXLOCK);
	platform->sustainable.threshold = data == 0 ? 0 : (u32) data;
	return 0;
}

static int gpu_context_init(struct kbase_device *kbdev)
{
	struct exynos_context *platform;
	struct mali_base_gpu_core_props *core_props;

	platform = kmalloc(sizeof(struct exynos_context), GFP_KERNEL);

	if (platform == NULL)
		return -1;

	memset(platform, 0, sizeof(struct exynos_context));
	kbdev->platform_context = (void *) platform;
	pkbdev = kbdev;

	mutex_init(&platform->gpu_clock_lock);
	mutex_init(&platform->gpu_dvfs_handler_lock);
#ifdef CONFIG_MALI_DVFS_USER
	mutex_init(&platform->gpu_process_job_lock);
#endif
	spin_lock_init(&platform->gpu_dvfs_spinlock);

	gpu_validate_attrib_data(platform);

	core_props = &(kbdev->gpu_props.props.core_props);
	core_props->gpu_freq_khz_min = platform->gpu_min_clock * 1000;
	core_props->gpu_freq_khz_max = platform->gpu_max_clock * 1000;

	kbdev->vendor_callbacks = (struct kbase_vendor_callbacks *)gpu_get_callbacks();

#ifdef CONFIG_MALI_EXYNOS_TRACE
	if (gpu_trace_init(kbdev) != 0)
		return -1;
#endif
	return 0;
}

/**
 ** Exynos5 hardware specific initialization
 **/
static int kbase_platform_exynos5_init(struct kbase_device *kbdev)
{
	/* gpu context init */
	if (gpu_context_init(kbdev) < 0)
		goto init_fail;

#if defined(CONFIG_SOC_EXYNOS7420) || defined(CONFIG_SOC_EXYNOS7890)
	if(gpu_device_specific_init(kbdev) < 0)
		goto init_fail;
#endif
	/* gpu control module init */
	if (gpu_control_module_init(kbdev) < 0)
		goto init_fail;

	/* gpu notifier init */
	if (gpu_notifier_init(kbdev) < 0)
		goto init_fail;

#ifdef CONFIG_MALI_DVFS
	/* gpu utilization moduel init */
	gpu_dvfs_utilization_init(kbdev);

	/* dvfs governor init */
	gpu_dvfs_governor_init(kbdev);

	/* dvfs handler init */
	gpu_dvfs_handler_init(kbdev);
#endif /* CONFIG_MALI_DVFS */

#ifdef CONFIG_MALI_DEBUG_SYS
	/* gpu sysfs file init */
	if (gpu_create_sysfs_file(kbdev->dev) < 0)
		goto init_fail;
#endif /* CONFIG_MALI_DEBUG_SYS */

	return 0;

init_fail:
	kfree(kbdev->platform_context);

	return -1;
}

/**
 ** Exynos5 hardware specific termination
 **/
static void kbase_platform_exynos5_term(struct kbase_device *kbdev)
{
	struct exynos_context *platform;
	platform = (struct exynos_context *) kbdev->platform_context;

	gpu_notifier_term();

#ifdef CONFIG_MALI_DVFS
	gpu_dvfs_handler_deinit(kbdev);
#endif /* CONFIG_MALI_DVFS */

	gpu_dvfs_utilization_deinit(kbdev);

	gpu_control_module_term(kbdev);

	kfree(kbdev->platform_context);
	kbdev->platform_context = 0;

#ifdef CONFIG_MALI_DEBUG_SYS
	gpu_remove_sysfs_file(kbdev->dev);
#endif /* CONFIG_MALI_DEBUG_SYS */
}

struct kbase_platform_funcs_conf platform_funcs = {
	.platform_init_func = &kbase_platform_exynos5_init,
	.platform_term_func = &kbase_platform_exynos5_term,
};

/* MALI_SEC_SECURE_RENDERING */
static int exynos_secure_mode_enable(struct kbase_device *kbdev)
{
	/* enable secure mode : TZPC */
	int ret = 0;

	if (!kbdev)
		goto secure_out;

	if (!kbdev->secure_mode_support) {
		GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: wrong operation! DDK cannot support Secure Rendering\n", __func__);
		ret = -EINVAL;
		goto secure_out;
	}
#if defined(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
	gpu_cacheclean(kbdev);

#if MALI_SEC_ASP_SECURE_BUF_CTRL
	ret = exynos_smc(SMC_DRM_SECBUF_CFW_PROT,
                     kbdev->sec_sr_info.secure_crc_phys, kbdev->sec_sr_info.secure_crc_sizes,
                     PROT_G3D);

	if (ret != DRMDRV_OK) {
		GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: CRC : failed to set secure buffer region by err 0x%x, physical addr 0x%08x\n",
			__func__, ret, (unsigned int)kbdev->sec_sr_info.secure_crc_phys);
		goto secure_out;
	}
#endif

	ret = exynos_smc(SMC_PROTECTION_SET, 0,
                    PROT_G3D, SMC_PROTECTION_ENABLE);

	if (ret == SMC_TZPC_OK)
		ret = 0;

#endif // defined(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
secure_out:
	return ret;
}

static int exynos_secure_mode_disable(struct kbase_device *kbdev)
{
	/* Turn off secure mode and reset GPU : TZPC */
	int ret = 0;

	if (!kbdev)
		goto secure_out;

	if (!kbdev->secure_mode_support) {
		GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: wrong operation! DDK cannot support Secure Rendering\n", __func__);
		ret = -EINVAL;
		goto secure_out;
	}
#if defined(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
	gpu_cacheclean(kbdev);

#if MALI_SEC_ASP_SECURE_BUF_CTRL
	ret = exynos_smc(SMC_DRM_SECBUF_CFW_UNPROT,
                     kbdev->sec_sr_info.secure_crc_phys, kbdev->sec_sr_info.secure_crc_sizes,
                     PROT_G3D);

	if(ret != DRMDRV_OK) {
		GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: CRC : failed to unset secure buffer region by err 0x%x, physical addr 0x%08x\n",
			__func__, ret, (unsigned int)kbdev->sec_sr_info.secure_crc_phys);
		goto secure_out;
	}
#endif

	ret = exynos_smc(SMC_PROTECTION_SET, 0,
                     PROT_G3D, SMC_PROTECTION_DISABLE);

	if (ret == SMC_TZPC_OK)
		ret = 0;

#endif // defined(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
secure_out:
	return ret;
}

static int exynos_secure_mode_init(struct kbase_device *kbdev)
{
	int ret = -EINVAL;

#if defined(CONFIG_ION) && defined(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
#if MALI_SEC_ASP_SECURE_BUF_CTRL
	ret = ion_exynos_contig_heap_info(SMC_GPU_CRC_REGION_NUM,
		&kbdev->sec_sr_info.secure_crc_phys, &kbdev->sec_sr_info.secure_crc_sizes);

	if (!ret) {
		GPU_LOG(DVFS_WARNING, LSI_GPU_SECURE, 0u, 0u, "%s: supporting Secure Rendering : region - 0x%08x, sizes - 0x%x\n",
			__func__, (unsigned int)kbdev->sec_sr_info.secure_crc_phys, (unsigned int)kbdev->sec_sr_info.secure_crc_sizes);
	} else
#else
	ret = 0;
	kbdev->sec_sr_info.secure_crc_phys = 0;
	kbdev->sec_sr_info.secure_crc_sizes = 0;
	GPU_LOG(DVFS_WARNING, LSI_GPU_SECURE, 0u, 0u, "%s: supporting Secure Rendering, NO use ASP feature.\n", __func__);
#endif
#endif
	if (ret) {
		GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: can NOT support Secure Rendering, error %d\n", __func__, ret);
	}

	return ret;
}

static int exynos_secure_mem_enable(struct kbase_device *kbdev, int ion_fd, u64 flags, struct kbase_va_region *reg)
{
	/* enable secure world mode : TZASC */
	int ret = 0;

	if (!kbdev)
		goto secure_out;

	if (!kbdev->secure_mode_support) {
		GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: wrong operation! DDK cannot support Secure Rendering\n", __func__);
		ret = -EINVAL;
		goto secure_out;
	}

	if (!reg) {
		GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: wrong input argument, reg %p\n",
			__func__, reg);
		goto secure_out;
	}
#if defined(CONFIG_ION) && defined(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
#if MALI_SEC_ASP_SECURE_BUF_CTRL
	{
		struct ion_client *client;
		struct ion_handle *ion_handle;
		size_t len = 0;
		ion_phys_addr_t phys = 0;

		flush_all_cpu_caches();

		if ((flags & kbdev->sec_sr_info.secure_flags_crc_asp) == kbdev->sec_sr_info.secure_flags_crc_asp) {
			reg->flags |= KBASE_REG_SECURE_CRC | KBASE_REG_SECURE;
		} else {

			client = ion_client_create(ion_exynos, "G3D");
			if (IS_ERR(client)) {
				GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: Failed to get ion_client of G3D\n",
						__func__);
				goto secure_out;
			}

			ion_handle = ion_import_dma_buf(client, ion_fd);

			if (IS_ERR(ion_handle)) {
				GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: Failed to get ion_handle of G3D\n",
						__func__);
				ion_client_destroy(client);
				goto secure_out;
			}

			if (ion_phys(client, ion_handle, &phys, &len)) {
				GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: Failed to get phys. addr of G3D\n",
						__func__);
				ion_free(client, ion_handle);
				ion_client_destroy(client);
				goto secure_out;
			}

			ion_free(client, ion_handle);
			ion_client_destroy(client);

			ret = exynos_smc(SMC_DRM_SECBUF_CFW_PROT, phys, len, PROT_G3D);
			if (ret != DRMDRV_OK) {
				GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: failed to set secure buffer region of G3D buffer, phy 0x%08x, error 0x%x\n",
					__func__, (unsigned int)phys, ret);
				BUG();
			}

			reg->flags |= KBASE_REG_SECURE;
		}

		reg->phys_by_ion = phys;
		reg->len_by_ion = len;
	}
#else
	reg->flags |= KBASE_REG_SECURE;

	reg->phys_by_ion = 0;
	reg->len_by_ion = 0;
#endif
#else
	GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: wrong operation! DDK cannot support Secure Rendering\n", __func__);
	ret = -EINVAL;
#endif // defined(CONFIG_ION) && defined(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)

	return ret;
secure_out:
	ret = -EINVAL;
	return ret;
}
static int exynos_secure_mem_disable(struct kbase_device *kbdev, struct kbase_va_region *reg)
{
	/* Turn off secure world mode : TZASC */
	int ret = 0;

	if (!kbdev)
		goto secure_out;

	if (!kbdev->secure_mode_support) {
		GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: wrong operation! DDK cannot support Secure Rendering\n", __func__);
		ret = -EINVAL;
		goto secure_out;
	}

	if (!reg) {
		GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: wrong input argument, reg %p\n",
			__func__, reg);
		ret = -EINVAL;
		goto secure_out;
	}
#if defined(CONFIG_ION) && defined(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
#if MALI_SEC_ASP_SECURE_BUF_CTRL
	if ( (reg->flags & KBASE_REG_SECURE) &&
	    !(reg->flags & KBASE_REG_SECURE_CRC)) {
		int ret;

		ret = exynos_smc(SMC_DRM_SECBUF_CFW_UNPROT,
				reg->phys_by_ion, reg->len_by_ion, PROT_G3D);

		if (ret != DRMDRV_OK) {
			GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: failed to unset secure buffer region of G3D buffer, phys 0x%08x, error 0x%x\n",
				__func__, (unsigned int)reg->phys_by_ion, ret);
			BUG();
		}
	}
#endif
#else
	GPU_LOG(DVFS_ERROR, LSI_GPU_SECURE, 0u, 0u, "%s: wrong operation! DDK cannot support Secure Rendering\n", __func__);
	ret = -EINVAL;
#endif // defined(CONFIG_ION) && defined(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)

secure_out:
	return ret;
}

struct kbase_secure_ops exynos_secure_ops = {
	.secure_mode_enable  = exynos_secure_mode_enable,
	.secure_mode_disable = exynos_secure_mode_disable,
/* MALI_SEC_SECURE_RENDERING */
	.secure_mode_init    = exynos_secure_mode_init,
	.secure_mem_enable   = exynos_secure_mem_enable,
	.secure_mem_disable  = exynos_secure_mem_disable,
};

int kbase_platform_early_init(void)
{
	return 0;
}
