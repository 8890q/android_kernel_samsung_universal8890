# SPDX-License-Identifier: GPL-2.0
dtb-$(CONFIG_MACH_EXYNOS8890_HEROLTE_EUR_OPEN) += \
    exynos8890-herolte_eur_open_04.dtb \
    exynos8890-herolte_eur_open_08.dtb \
    exynos8890-herolte_eur_open_09.dtb

dts-dirs += exynos

subdir-y          := $(dts-dirs)

always            := $(DTB_LIST)

targets += dtbs
dtbs: $(addprefix $(obj)/, $(DTB_LIST))

clean-files       := exynos/*.dtb *.dtb*
