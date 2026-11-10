# SPDX-License-Identifier: GPL-2.0
dtb-$(CONFIG_MACH_EXYNOS8890_HEROLTE_EUR_OPEN) += \
    exynos8890-herolte_eur_open_04.dtb \
    exynos8890-herolte_eur_open_08.dtb \
    exynos8890-herolte_eur_open_09.dtb

dtb-$(CONFIG_MACH_EXYNOS8890_HERO2LTE_EUR_OPEN) += \
    exynos8890-hero2lte_eur_open_04.dtb \
    exynos8890-hero2lte_eur_open_08.dtb

dts-dirs += exynos

subdir-y          := $(dts-dirs)

always            := $(dtb-y)

targets += dtbs
dtbs: $(addprefix $(obj)/, $(dtb-y))

clean-files       := exynos/*.dtb *.dtb*
