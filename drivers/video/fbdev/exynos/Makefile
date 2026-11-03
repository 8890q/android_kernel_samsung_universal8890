#
# Makefile for the exynos video drivers.
#

ifneq ($(CONFIG_SOC_EXYNOS8890),y)
obj-$(CONFIG_EXYNOS_MIPI_DSI)		+= exynos_mipi_dsi.o exynos_mipi_dsi_common.o \
				     	exynos_mipi_dsi_lowlevel.o
obj-$(CONFIG_EXYNOS_LCD_S6E8AX0)	+= s6e8ax0.o
endif

obj-$(CONFIG_EXYNOS_DECON_8890)	+= decon_8890/

ifeq ($(CONFIG_EXYNOS_DUAL_DISPLAY),y)
obj-$(CONFIG_EXYNOS_DECON_8895) += dual_dpu/
obj-$(CONFIG_EXYNOS_DECON_8895) += dual_panel/
endif

ifeq ($(CONFIG_EXYNOS_SINGLE_DISPLAY),y)
obj-$(CONFIG_EXYNOS_DECON_8895)	+= dpu/
obj-$(CONFIG_EXYNOS_DECON_8895)	+= panel/
endif
