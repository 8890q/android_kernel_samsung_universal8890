#ifndef __PMUCAL_SYSTEM_H__
#define __PMUCAL_SYSTEM_H__
#include "pmucal_common.h"
#include <soc/samsung/exynos-powerdown.h>

struct pmucal_lpm {
	u32 id;
	struct pmucal_seq *enter;
	struct pmucal_seq *save;
	struct pmucal_seq *exit;
	struct pmucal_seq *early_wakeup;
	u32 num_enter;
	u32 num_save;
	u32 num_exit;
	u32 num_early_wakeup;
};


/* APIs to be supported to PWRCAL interface */
extern int pmucal_system_enter(int mode);
extern int pmucal_system_exit(int mode);
extern int pmucal_system_earlywakeup(int mode);
extern int pmucal_system_init(void);

extern struct pmucal_seq pmucal_lpm_init[];
extern struct pmucal_lpm pmucal_lpm_list[];
extern unsigned int pmucal_lpm_init_size;
extern unsigned int pmucal_lpm_list_size;
#endif
