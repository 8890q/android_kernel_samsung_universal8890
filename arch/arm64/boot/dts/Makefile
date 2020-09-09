# SPDX-License-Identifier: GPL-2.0
dtb-$(CONFIG_MODEL_GRACELTE) += exynos8890-gracelte_eur_open_11.dtb
dtb-$(CONFIG_MODEL_GRACELTEKOR) += exynos8890-gracelte_kor_all_12.dts
dtb-$(CONFIG_MODEL_HERO2LTE) += exynos8890-hero2lte_eur_open_04.dtb exynos8890-hero2lte_eur_open_08.dtb
dtb-$(CONFIG_MODEL_HEROLTE) += exynos8890-herolte_eur_open_04.dtb exynos8890-herolte_eur_open_08.dtb exynos8890-herolte_eur_open_09.dtb

targets += dtbs
DTB_LIST  := $(dtb-y) $(dtbo-y)

dtbs: $(addprefix $(obj)/, $(DTB_LIST))

clean-files := *.dtb*
