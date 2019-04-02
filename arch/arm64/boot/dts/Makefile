# SPDX-License-Identifier: GPL-2.0
# dtb-y +=  exynos8890-gracelte_eur_open_00.dtb
# dtb-y +=  exynos8890-gracelte_kor_all_01.dtb
# dtb-y +=  exynos8890-gracelte_kor_all_02.dtb
# dtb-y +=  exynos8890-gracelte_kor_all_03.dtb
# dtb-y +=  exynos8890-gracelte_kor_all_05.dtb
# dtb-y +=  exynos8890-gracelte_kor_all_07.dtb
# dtb-y +=  exynos8890-gracelte_kor_all_09.dtb
# dtb-y +=  exynos8890-gracelte_kor_all_11.dtb
# dtb-y +=  exynos8890-gracelte_kor_all_12.dtb

dtb-$(CONFIG_MODEL_HERO2LTE) += exynos8890-hero2lte_eur_open_04.dtb exynos8890-hero2lte_eur_open_08.dtb
dtb-$(CONFIG_MODEL_HEROLTE) += exynos8890-herolte_eur_open_04.dtb exynos8890-herolte_eur_open_08.dtb exynos8890-herolte_eur_open_09.dtb

targets += dtbs
DTB_LIST  := $(dtb-y) $(dtbo-y)

dtbs: $(addprefix $(obj)/, $(DTB_LIST))

clean-files := *.dtb*
