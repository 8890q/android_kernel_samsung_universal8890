#
# Exynos SoC Specific drivers
#
ccflags-y := $(KBUILD_FP_SENSOR_CFLAGS)

obj-$(CONFIG_ARCH_EXYNOS)	+= exynos-powermode.o
obj-$(CONFIG_ARCH_EXYNOS)	+= exynos-pm.o

obj-$(CONFIG_ARCH_EXYNOS)	+= exynos-smc.o
obj-$(CONFIG_ARCH_EXYNOS)	+= exynos-el3_mon.o
obj-$(CONFIG_ARCH_EXYNOS)	+= exynos-cpu_hotplug.o
obj-$(CONFIG_ARCH_EXYNOS)	+= exynos-cpumap.o
obj-$(CONFIG_ARCH_EXYNOS)	+= core_reg.o

# CAL
obj-$(CONFIG_PWRCAL)            += pwrcal/
obj-$(CONFIG_CAL_IF)		+= cal-if/
obj-$(CONFIG_EXYNOS_PMU)	+= exynos-pmu.o
obj-$(CONFIG_EXYNOS_CHIPID)	+= exynos-chipid.o
obj-$(CONFIG_EXYNOS_REBOOT)	+= exynos-reboot.o
obj-$(CONFIG_EXYNOS_PD)        += exynos-pd.o exynos-pd-dbg.o
obj-$(CONFIG_EXYNOS_RGT)        += exynos-rgt.o
obj-$(CONFIG_EXYNOS_PM_DVS)        += exynos-pm-dvs.o

obj-$(CONFIG_ECT)		+= ect_parser.o
obj-$(CONFIG_EXYNOS_BCM)	+= exynos-bcm.o
obj-$(CONFIG_EXYNOS_WD_DVFS)		+= pmu_count.o

obj-$(CONFIG_EXYNOS_HOTPLUG_GOVERNOR)	+= exynos-hotplug_governor.o
obj-$(CONFIG_ARM64_EXYNOS_CPUIDLE)	+= cpuidle_profiler.o

# USI
obj-$(CONFIG_USI) += usi.o

# ACPM
obj-$(CONFIG_EXYNOS_ACPM)       += acpm/

# CP
obj-$(CONFIG_SEC_SIPC_HIGGS_MODEM_IF) += pmu-cp.o
ifneq ($(CONFIG_SOC_EXYNOS8890),y)
obj-$(CONFIG_SEC_SIPC_MODEM_IF) += pmu-cp.o
endif
obj-$(CONFIG_SEC_MODEM_IF)  += pmu-cp.o

# Exynos Secure Log
obj-$(CONFIG_EXYNOS_SECURE_LOG)	+= exynos-seclog.o

# SDM
obj-$(CONFIG_EXYNOS_SDM) += exynos-sdm.o

# DVFS
obj-$(CONFIG_EXYNOS_DVFS_MANAGER)	+= exynos-dm.o

obj-$(CONFIG_EXYNOS_MCINFO)	+= exynos-mcinfo.o

# secmem
obj-$(CONFIG_ARCH_EXYNOS)	+= secmem.o

# HDCP driver
obj-$(CONFIG_EXYNOS_HDCP2)	+= exynos-hdcp/

# early tmu
obj-$(CONFIG_EXYNOS_EARLY_TMU)	+= exynos-earlytmu.o
