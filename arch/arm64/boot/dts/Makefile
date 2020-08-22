# SPDX-License-Identifier: GPL-2.0
dtb-y +=  exynos8890-gracelte_eur_open_00.dtb
dtb-y +=  exynos8890-gracelte_eur_open_01.dtb
dtb-y +=  exynos8890-gracelte_eur_open_02.dtb
dtb-y +=  exynos8890-gracelte_eur_open_03.dtb
dtb-y +=  exynos8890-gracelte_eur_open_05.dtb
dtb-y +=  exynos8890-gracelte_eur_open_07.dtb
dtb-y +=  exynos8890-gracelte_eur_open_09.dtb
dtb-y +=  exynos8890-gracelte_eur_open_11.dtb

targets += dtbs
DTB_LIST  := $(dtb-y) $(dtbo-y)

dtbs: $(addprefix $(obj)/, $(DTB_LIST))

clean-files := *.dtb*
