/*
 *  Copyright (C) 1994  Linus Torvalds
 *
 *  Cyrix stuff, June 1998 by:
 *	- Rafael R. Reilova (moved everything from head.S),
 *        <rreilova@ececs.uc.edu>
 *	- Channing Corn (tests & fixes),
 *	- Andrew D. Balsa (code cleanup).
 */
#include <linux/init.h>
#include <linux/utsname.h>
#include <linux/cpu.h>
#include <linux/module.h>

#include <asm/spec-ctrl.h>
#include <asm/cmdline.h>
#include <asm/bugs.h>
#include <asm/processor.h>
#include <asm/processor-flags.h>
#include <asm/i387.h>
#include <asm/msr.h>
#include <asm/paravirt.h>
#include <asm/alternative.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/intel-family.h>

static void __init spectre_v2_select_mitigation(void);

#ifdef CONFIG_X86_32
static double __initdata x = 4195835.0;
static double __initdata y = 3145727.0;

/*
 * This used to check for exceptions..
 * However, it turns out that to support that,
 * the XMM trap handlers basically had to
 * be buggy. So let's have a correct XMM trap
 * handler, and forget about printing out
 * some status at boot.
 *
 * We should really only care about bugs here
 * anyway. Not features.
 */
static void __init check_fpu(void)
{
	s32 fdiv_bug;

	kernel_fpu_begin();

	/*
	 * trap_init() enabled FXSR and company _before_ testing for FP
	 * problems here.
	 *
	 * Test for the divl bug: http://en.wikipedia.org/wiki/Fdiv_bug
	 */
	__asm__("fninit\n\t"
		"fldl %1\n\t"
		"fdivl %2\n\t"
		"fmull %2\n\t"
		"fldl %1\n\t"
		"fsubp %%st,%%st(1)\n\t"
		"fistpl %0\n\t"
		"fwait\n\t"
		"fninit"
		: "=m" (*&fdiv_bug)
		: "m" (*&x), "m" (*&y));

	kernel_fpu_end();

	if (fdiv_bug) {
		set_cpu_bug(&boot_cpu_data, X86_BUG_FDIV);
		pr_warn("Hmm, FPU with FDIV bug\n");
	}
}
#endif /* CONFIG_X86_32 */

void __init check_bugs(void)
{
	identify_boot_cpu();

	if (!IS_ENABLED(CONFIG_SMP)) {
		pr_info("CPU: ");
		print_cpu_info(&boot_cpu_data);
	}

	/* Select the proper spectre mitigation before patching alternatives */
	spectre_v2_select_mitigation();

#ifdef CONFIG_X86_32
	/*
	 * Check whether we are able to run this kernel safely on SMP.
	 *
	 * - i386 is no longer supported.
	 * - In order to run on anything without a TSC, we need to be
	 *   compiled for a i486.
	 */
	if (boot_cpu_data.x86 < 4)
		panic("Kernel requires i486+ for 'invlpg' and other features");

	init_utsname()->machine[1] =
		'0' + (boot_cpu_data.x86 > 6 ? 6 : boot_cpu_data.x86);
	alternative_instructions();

	/*
	 * kernel_fpu_begin/end() in check_fpu() relies on the patched
	 * alternative instructions.
	 */
	if (cpu_has_fpu)
		check_fpu();
#else /* CONFIG_X86_64 */
	alternative_instructions();

	/*
	 * Make sure the first 2MB area is not mapped by huge pages
	 * There are typically fixed size MTRRs in there and overlapping
	 * MTRRs into large pages causes slow downs.
	 *
	 * Right now we don't do that with gbpages because there seems
	 * very little benefit for that case.
	 */
	if (!direct_gbpages)
		set_memory_4k((unsigned long)__va(0), 1);
#endif
}

/* The kernel command line selection */
enum spectre_v2_mitigation_cmd {
	SPECTRE_V2_CMD_NONE,
	SPECTRE_V2_CMD_AUTO,
	SPECTRE_V2_CMD_FORCE,
	SPECTRE_V2_CMD_RETPOLINE,
	SPECTRE_V2_CMD_RETPOLINE_GENERIC,
	SPECTRE_V2_CMD_RETPOLINE_AMD,
};

static const char *spectre_v2_strings[] = {
	[SPECTRE_V2_NONE]			= "Vulnerable",
	[SPECTRE_V2_RETPOLINE_MINIMAL]		= "Vulnerable: Minimal generic ASM retpoline",
	[SPECTRE_V2_RETPOLINE_MINIMAL_AMD]	= "Vulnerable: Minimal AMD ASM retpoline",
	[SPECTRE_V2_RETPOLINE_GENERIC]		= "Mitigation: Full generic retpoline",
	[SPECTRE_V2_RETPOLINE_AMD]		= "Mitigation: Full AMD retpoline",
};

#undef pr_fmt
#define pr_fmt(fmt)     "Spectre V2 : " fmt

static enum spectre_v2_mitigation spectre_v2_enabled = SPECTRE_V2_NONE;


#ifdef RETPOLINE
static bool spectre_v2_bad_module;

bool retpoline_module_ok(bool has_retpoline)
{
	if (spectre_v2_enabled == SPECTRE_V2_NONE || has_retpoline)
		return true;

	pr_err("System may be vulnerable to spectre v2\n");
	spectre_v2_bad_module = true;
	return false;
}

static inline const char *spectre_v2_module_string(void)
{
	return spectre_v2_bad_module ? " - vulnerable module loaded" : "";
}
#else
static inline const char *spectre_v2_module_string(void) { return ""; }
#endif

static void __init spec2_print_if_insecure(const char *reason)
{
	if (boot_cpu_has_bug(X86_BUG_SPECTRE_V2))
		pr_info("%s selected on command line.\n", reason);
}

static void __init spec2_print_if_secure(const char *reason)
{
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2))
		pr_info("%s selected on command line.\n", reason);
}

static inline bool retp_compiler(void)
{
	return __is_defined(RETPOLINE);
}

static inline bool match_option(const char *arg, int arglen, const char *opt)
{
	int len = strlen(opt);

	return len == arglen && !strncmp(arg, opt, len);
}

static const struct {
	const char *option;
	enum spectre_v2_mitigation_cmd cmd;
	bool secure;
} mitigation_options[] = {
	{ "off",               SPECTRE_V2_CMD_NONE,              false },
	{ "on",                SPECTRE_V2_CMD_FORCE,             true },
	{ "retpoline",         SPECTRE_V2_CMD_RETPOLINE,         false },
	{ "retpoline,amd",     SPECTRE_V2_CMD_RETPOLINE_AMD,     false },
	{ "retpoline,generic", SPECTRE_V2_CMD_RETPOLINE_GENERIC, false },
	{ "auto",              SPECTRE_V2_CMD_AUTO,              false },
};

static enum spectre_v2_mitigation_cmd __init spectre_v2_parse_cmdline(void)
{
	char arg[20];
	int ret, i;
	enum spectre_v2_mitigation_cmd cmd = SPECTRE_V2_CMD_AUTO;

	if (cmdline_find_option_bool(boot_command_line, "nospectre_v2"))
		return SPECTRE_V2_CMD_NONE;
	else {
		ret = cmdline_find_option(boot_command_line, "spectre_v2", arg, sizeof(arg));
		if (ret < 0)
			return SPECTRE_V2_CMD_AUTO;

		for (i = 0; i < ARRAY_SIZE(mitigation_options); i++) {
			if (!match_option(arg, ret, mitigation_options[i].option))
				continue;
			cmd = mitigation_options[i].cmd;
			break;
		}

		if (i >= ARRAY_SIZE(mitigation_options)) {
			pr_err("unknown option (%s). Switching to AUTO select\n", arg);
			return SPECTRE_V2_CMD_AUTO;
		}
	}

	if ((cmd == SPECTRE_V2_CMD_RETPOLINE ||
	     cmd == SPECTRE_V2_CMD_RETPOLINE_AMD ||
	     cmd == SPECTRE_V2_CMD_RETPOLINE_GENERIC) &&
	    !IS_ENABLED(CONFIG_RETPOLINE)) {
		pr_err("%s selected but not compiled in. Switching to AUTO select\n", mitigation_options[i].option);
		return SPECTRE_V2_CMD_AUTO;
	}

	if (cmd == SPECTRE_V2_CMD_RETPOLINE_AMD &&
	    boot_cpu_data.x86_vendor != X86_VENDOR_AMD) {
		pr_err("retpoline,amd selected but CPU is not AMD. Switching to AUTO select\n");
		return SPECTRE_V2_CMD_AUTO;
	}

	if (mitigation_options[i].secure)
		spec2_print_if_secure(mitigation_options[i].option);
	else
		spec2_print_if_insecure(mitigation_options[i].option);

	return cmd;
}

static void __init spectre_v2_select_mitigation(void)
{
	enum spectre_v2_mitigation_cmd cmd = spectre_v2_parse_cmdline();
	enum spectre_v2_mitigation mode = SPECTRE_V2_NONE;

	/*
	 * If the CPU is not affected and the command line mode is NONE or AUTO
	 * then nothing to do.
	 */
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2) &&
	    (cmd == SPECTRE_V2_CMD_NONE || cmd == SPECTRE_V2_CMD_AUTO))
		return;

	switch (cmd) {
	case SPECTRE_V2_CMD_NONE:
		return;

	case SPECTRE_V2_CMD_FORCE:
	case SPECTRE_V2_CMD_AUTO:
		if (IS_ENABLED(CONFIG_RETPOLINE))
			goto retpoline_auto;
		break;
	case SPECTRE_V2_CMD_RETPOLINE_AMD:
		if (IS_ENABLED(CONFIG_RETPOLINE))
			goto retpoline_amd;
		break;
	case SPECTRE_V2_CMD_RETPOLINE_GENERIC:
		if (IS_ENABLED(CONFIG_RETPOLINE))
			goto retpoline_generic;
		break;
	case SPECTRE_V2_CMD_RETPOLINE:
		if (IS_ENABLED(CONFIG_RETPOLINE))
			goto retpoline_auto;
		break;
	}
	pr_err("Spectre mitigation: kernel not compiled with retpoline; no mitigation available!");
	return;

retpoline_auto:
	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) {
	retpoline_amd:
		if (!boot_cpu_has(X86_FEATURE_LFENCE_RDTSC)) {
			pr_err("Spectre mitigation: LFENCE not serializing, switching to generic retpoline\n");
			goto retpoline_generic;
		}
		mode = retp_compiler() ? SPECTRE_V2_RETPOLINE_AMD :
					 SPECTRE_V2_RETPOLINE_MINIMAL_AMD;
		setup_force_cpu_cap(X86_FEATURE_RETPOLINE_AMD);
		setup_force_cpu_cap(X86_FEATURE_RETPOLINE);
	} else {
	retpoline_generic:
		mode = retp_compiler() ? SPECTRE_V2_RETPOLINE_GENERIC :
					 SPECTRE_V2_RETPOLINE_MINIMAL;
		setup_force_cpu_cap(X86_FEATURE_RETPOLINE);
	}

	spectre_v2_enabled = mode;
	pr_info("%s\n", spectre_v2_strings[mode]);
}

#undef pr_fmt

#ifdef CONFIG_SYSFS
ssize_t cpu_show_meltdown(struct device *dev, struct device_attribute *attr, char *buf)
{
	if (!boot_cpu_has_bug(X86_BUG_CPU_MELTDOWN))
		return sprintf(buf, "Not affected\n");
	return sprintf(buf, "Vulnerable\n");
}

ssize_t cpu_show_spectre_v1(struct device *dev, struct device_attribute *attr, char *buf)
{
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V1))
		return sprintf(buf, "Not affected\n");
	return sprintf(buf, "Mitigation: __user pointer sanitization\n");
}

ssize_t cpu_show_spectre_v2(struct device *dev, struct device_attribute *attr, char *buf)
{
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2))
		return sprintf(buf, "Not affected\n");

	return sprintf(buf, "%s%s\n", spectre_v2_strings[spectre_v2_enabled],
		       spectre_v2_module_string());
}
#endif
