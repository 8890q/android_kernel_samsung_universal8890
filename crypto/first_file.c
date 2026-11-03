#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#ifdef CONFIG_RELOCATABLE_KERNEL
#include <asm/page.h>
#endif

/* Keep this on top */
#ifdef CONFIG_RELOCATABLE_KERNEL
static const char
builtime_crypto_hmac[128][32] __attribute__((aligned(PAGE_SIZE))) = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}};
#else
static const char
builtime_crypto_hmac[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
#endif

const int first_crypto_rodata = 10;
int       first_crypto_data   = 20;


void first_crypto_text (void) __attribute__((unused));
void first_crypto_text (void)
{
}

#ifdef CONFIG_RELOCATABLE_KERNEL

#define KERNEL_KASLR_16K_ALGIN
#define DDR_START_FIRST		(0x80000000)
#define DDR_START_SECOND	(0x40000000) // Used only for MSM8998 6GB RAM

#ifdef  KERNEL_KASLR_16K_ALGIN
#define KASLR_FIRST_SLOT	(0x80000)
#define KASLR_ALIGN			(0x4000)
#else
#define KASLR_FIRST_SLOT	(0x5000000)
#define KASLR_ALIGN			(0x200000)
#endif

const char *
get_builtime_crypto_hmac (void)
{
	extern u64 *__boot_kernel_offset;
	u64 *kernel_addr = (u64 *) &__boot_kernel_offset;
	u64 offset = 0;
	u64 idx = 0;
	if (ddr_start_type) { // This value is set only for MSM8998
		if (ddr_start_type == 1)
			offset = (u64)((u64)kernel_addr[1] + (u64)kernel_addr[0] - (u64)KASLR_FIRST_SLOT - (u64)DDR_START_FIRST);
		else
			offset = (u64)((u64)kernel_addr[1] + (u64)kernel_addr[0] - (u64)KASLR_FIRST_SLOT - (u64)DDR_START_SECOND);
	} else {
		offset = (u64)((u64)kernel_addr[1] + (u64)kernel_addr[0] - (u64)KASLR_FIRST_SLOT - (u64)DDR_START_FIRST);
	}

	idx = (offset / KASLR_ALIGN);
	if (WARN_ON_ONCE(idx >= ARRAY_SIZE(builtime_crypto_hmac)))
		return NULL;
	/* head.S stores these shared boot values in read-only kernel text. */
	return builtime_crypto_hmac[idx];
}
#else
const char *
get_builtime_crypto_hmac (void)
{
	return builtime_crypto_hmac;
}
#endif

void __init first_crypto_init(void) __attribute__((unused));
void __init first_crypto_init(void)
{
}

void __exit first_crypto_exit(void) __attribute__((unused));
void __exit first_crypto_exit(void)
{
}
