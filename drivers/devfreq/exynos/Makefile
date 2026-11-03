# Exynos DEVFREQ Drivers
ifeq ($(CONFIG_SOC_EXYNOS8890),y)
obj-$(CONFIG_ARM_EXYNOS_DEVFREQ) += exynos-devfreq8890.o
else
obj-$(CONFIG_ARM_EXYNOS_DEVFREQ)	+= exynos-devfreq.o
endif
obj-$(CONFIG_ARM_EXYNOS4_BUS_DEVFREQ)	+= exynos_ppmu.o exynos4_bus.o
obj-$(CONFIG_ARM_EXYNOS5_BUS_DEVFREQ)	+= exynos_ppmu.o exynos5_bus.o
obj-$(CONFIG_ARM_EXYNOS8895_BUS_DEVFREQ)+= exynos8895_bus_mif.o exynos8895_bus_int.o exynos8895_bus_disp.o exynos8895_bus_cam.o exynos8895_bus_intcam.o
obj-$(CONFIG_EXYNOS_WD_DVFS)	+= exynos_ppmu.o

obj-$(CONFIG_ARM_EXYNOS8890_BUS_DEVFREQ) += exynos8890_bus_mif.o exynos8890_bus_int.o exynos8890_bus_disp.o exynos8890_bus_cam.o
