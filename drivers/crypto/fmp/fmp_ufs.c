/*
 * Exynos FMP UFS driver for H/W AES
 *
 * Copyright (C) 2014 Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/syscalls.h>
#include <linux/smc.h>
#include <ufshcd.h>
#include <ufs-exynos.h>

#include <crypto/fmp.h>

#if defined(CONFIG_UFS_FMP_ECRYPT_FS) || defined(CONFIG_UFS_FMP_EXT4CRYPT_FS)
#include <linux/pagemap.h>
#include "fmp_derive_iv.h"
#endif

#if defined(CONFIG_FIPS_FMP)
#include "fmpdev_info.h"
#endif

#include "fmpdev_int.h" //For FIPS_FMP_FUNC_TEST macro

extern bool in_fmp_fips_err(void);
extern volatile unsigned int disk_key_flag;
extern spinlock_t disk_key_lock;
extern void exynos_ufs_ctrl_auto_hci_clk(struct exynos_ufs *ufs, bool en);

#define byte2word(b0, b1, b2, b3) 	\
		((unsigned int)(b0) << 24) | ((unsigned int)(b1) << 16) | ((unsigned int)(b2) << 8) | (b3)
#define word_in(x, c)           byte2word(((unsigned char *)(x) + 4 * (c))[0], ((unsigned char *)(x) + 4 * (c))[1], \
					((unsigned char *)(x) + 4 * (c))[2], ((unsigned char *)(x) + 4 * (c))[3])

#define FMP_KEY_SIZE	32

#if defined(CONFIG_FIPS_FMP)
static int fmp_xts_check_key(uint8_t *enckey, uint8_t *twkey, uint32_t len)
{
	if (!enckey | !twkey | !len) {
		printk(KERN_ERR "FMP key buffer is NULL or length is 0.\n");
		return -1;
	}

	if (!memcmp(enckey, twkey, len))
		return -1;      /* enckey and twkey are same */
	else
		return 0;       /* enckey and twkey are different */
}
#endif

static int configure_fmp_disk_enc(struct ufshcd_sg_entry *prd_table,
				uint32_t enc_mode, uint32_t idx,
				uint32_t sector, struct bio *bio,
				uint32_t size)
{
	/* Disk Encryption */
	if (!(enc_mode & UFS_DISK_ENC_MODE))
		return 0;

#if defined(CONFIG_FIPS_FMP)
	/* The length of XTS AES must be smaller than 4KB */
	if (size > 0x1000) {
		printk(KERN_ERR "Fail to FMP XTS due to invalid size(%x)\n",
				size);
		return -EINVAL;
	}
#endif
	/* algorithm */
	SET_DAS(&prd_table[idx], AES_XTS);
	prd_table[idx].size |= DKL;

	/* disk IV */
	prd_table[idx].disk_iv0 = 0;
	prd_table[idx].disk_iv1 = 0;
	prd_table[idx].disk_iv2 = 0;
	prd_table[idx].disk_iv3 = htonl(sector);

	if (disk_key_flag) {
		int ret;

#if defined(CONFIG_FIPS_FMP)
		if (!bio) {
			printk(KERN_ERR "Fail to check xts key due to bio\n");
			return -EINVAL;
		}

		if (fmp_xts_check_key(bio->key,
				(uint8_t *)((uint64_t)bio->key + FMP_KEY_SIZE), FMP_KEY_SIZE)) {
			printk(KERN_ERR "Fail to FMP XTS because enckey and twkey is the same\n");
			return -EINVAL;
		}
#endif
		if (disk_key_flag == 1)
			printk(KERN_INFO "FMP disk encryption key is set\n");
		else if (disk_key_flag == 2)
			printk(KERN_INFO "FMP disk encryption key is set after clear\n");
#ifdef CONFIG_SOC_EXYNOS8890
		ret = exynos_smc(SMC_CMD_FMP, FMP_KEY_SET, UFS_FMP, 0);
#else
		ret = exynos_smc(SMC_CMD_FMP_DISKENC, FMP_DISKKEY_SET, ID_FMP_UFS_MMC, 0);
#endif
		if (ret < 0)
			panic("Fail to load FMP loadable firmware\n");
		else if (ret) {
			printk(KERN_ERR "Fail to smc call for FMP key setting(%x)\n", ret);
			return ret;
		}

		spin_lock(&disk_key_lock);
		disk_key_flag = 0;
		spin_unlock(&disk_key_lock);
	}
	return 0;
}

#if defined(CONFIG_UFS_FMP_ECRYPT_FS) || defined(CONFIG_UFS_FMP_EXT4CRYPT_FS)
static int configure_fmp_file_algo_mode(struct ufshcd_sg_entry *prd_table,
				uint32_t idx, int algo_mode, uint32_t size)
{
	switch (algo_mode) {
	case FMP_XTS_ALGO_MODE:
#if defined(CONFIG_FIPS_FMP)
		/* The length of XTS AES must be smaller than 4KB */
		if (size > 0x1000) {
			printk(KERN_ERR "Fail to FMP XTS due to invalid size(%x)\n",
						size);
			return -EINVAL;
		}
#endif
		SET_FAS(&prd_table[idx], AES_XTS);
		break;
	case FMP_CBC_ALGO_MODE:
		SET_FAS(&prd_table[idx], AES_CBC);
		break;
	default:
		SET_FAS(&prd_table[idx], 0);
		return 0;
	}

	return 0;
}

static int configure_fmp_file_key_length(struct ufshcd_sg_entry *prd_table,
				uint32_t idx, unsigned long key_length)
{
	/* file encryption key size */
	switch (key_length) {
	case 16:
		prd_table[idx].size &= ~FKL;
		break;
	case 32:
	case 64:
		prd_table[idx].size |= FKL;
		break;
	default:
		printk(KERN_ERR "Invalid file key length(%lx)\n", key_length);
		return -EINVAL;
	}

	return 0;
}

static int configure_fmp_file_iv(struct ufshcd_sg_entry *prd_table,
				int algo_mode, struct scatterlist *sg,
				uint32_t idx, uint32_t sector)
{
	int ret;
	struct page *page = sg_page(sg);
#ifdef CONFIG_CRYPTO_FIPS
	char extent_iv[SHA256_HASH_SIZE];
#else
	char extent_iv[MD5_DIGEST_SIZE];
#endif
	loff_t index;

	switch (algo_mode) {
	case FMP_XTS_ALGO_MODE:
		prd_table[idx].file_iv0 = 0;
		prd_table[idx].file_iv1 = 0;
		prd_table[idx].file_iv2 = 0;
		prd_table[idx].file_iv3 = htonl(sector);
		break;
	case FMP_CBC_ALGO_MODE:
		index = page->index;
		index = index - page->mapping->sensitive_data_index;
		ret = file_enc_derive_iv(page->mapping, index, extent_iv);
		if (ret) {
			printk(KERN_ERR "Error attemping to derive IV. ret = %c\n", ret);
			return -EINVAL;
		}

		prd_table[idx].file_iv0 = word_in(extent_iv, 3);
		prd_table[idx].file_iv1 = word_in(extent_iv, 2);
		prd_table[idx].file_iv2 = word_in(extent_iv, 1);
		prd_table[idx].file_iv3 = word_in(extent_iv, 0);
		break;
	default:
		printk(KERN_ERR "Invalid file algorithm(%d)\n", algo_mode);
		return -EINVAL;
	}

	return 0;
}

static void configure_fmp_file_key(struct ufshcd_sg_entry *prd_table,
				uint32_t idx, unsigned char *key,
				unsigned long key_length)
{
	int i;

	/* File Enc key */
	for (i = 0; i < key_length >> 2; i++) {
		*(&prd_table[idx].file_enckey0 + i) =
			word_in(key, (key_length >> 2) - (i + 1));
	}

	return;
}

static int configure_fmp_file_enc(struct ufshcd_sg_entry *prd_table,
				uint32_t enc_mode, uint32_t idx,
				uint32_t sector, struct scatterlist *sg,
				uint32_t size)
{
	int ret, algo_mode;
	struct page *page = sg_page(sg);

	/* File Encryption */
	if (!(enc_mode & UFS_FILE_ENC_MODE))
		return 0;

	/* algorithm mode */
	algo_mode = page->mapping->private_algo_mode;
	ret = configure_fmp_file_algo_mode(prd_table, idx, algo_mode, size);
	if (ret) {
		printk(KERN_ERR "Fail to configure algo mode(%d)\n", ret);
		return ret;
	}

	ret = configure_fmp_file_key_length(prd_table, idx, page->mapping->key_length);
	if (ret) {
		printk(KERN_ERR "Fail to configure key length(%d)\n", ret);
		return ret;
	}

	ret = configure_fmp_file_iv(prd_table, algo_mode, sg, idx, sector);
	if (ret) {
		printk(KERN_ERR "Fail to configure key length(%d)\n", ret);
		return ret;
	}

	configure_fmp_file_key(prd_table, idx, page->mapping->key, page->mapping->key_length);

#if defined(CONFIG_FIPS_FMP)
	if (algo_mode == AES_XTS) {
		if (fmp_xts_check_key((uint8_t *)&prd_table[idx].file_enckey0,
				(uint8_t *)&prd_table[idx].file_twkey0,
				page->mapping->key_length)) {
			printk(KERN_ERR "Fail to FMP XTS because enckey and twkey is the same\n");
			return -EINVAL;
		}
	}
#endif

	return 0;
}

static int configure_fmp_file_enc_direct_io(struct ufshcd_sg_entry *prd_table,
				uint32_t enc_mode, uint32_t idx,
				uint32_t sector, struct bio *bio,
				struct scatterlist *sg, uint32_t size)
{
	int ret, algo_mode;

	/* algorithm mode */
	algo_mode = bio->private_algo_mode;
	ret = configure_fmp_file_algo_mode(prd_table, idx, algo_mode, size);
	if (ret) {
		printk(KERN_ERR "Fail to configure algo mode(%d)\n", ret);
		return ret;
	}

	ret = configure_fmp_file_key_length(prd_table, idx, bio->key_length);
	if (ret) {
		printk(KERN_ERR "Fail to configure key length(%d)\n", ret);
		return ret;
	}

	ret = configure_fmp_file_iv(prd_table, algo_mode, sg, idx, sector);
	if (ret) {
		printk(KERN_ERR "Fail to configure key length(%d)\n", ret);
		return ret;
	}

	configure_fmp_file_key(prd_table, idx, bio->key, bio->key_length);

#if defined(CONFIG_FIPS_FMP)
	if (algo_mode == FMP_XTS_ALGO_MODE) {
		if (fmp_xts_check_key((uint8_t *)&prd_table[idx].file_enckey0,
				(uint8_t *)&prd_table[idx].file_twkey0,
				bio->key_length)) {
			printk(KERN_ERR "Fail to FMP XTS because enckey and twkey is the same\n");
			return -EINVAL;
		}
	}
#endif

	return 0;
}

#endif

int fmp_ufs_map_sg(struct ufshcd_sg_entry *prd_table, struct scatterlist *sg,
					uint32_t enc_mode, uint32_t idx,
					uint32_t sector, struct bio *bio)
{
	int ret;
	uint32_t size;

	if (!prd_table || !sg || !bio)
		return 0;

	size = prd_table[idx].size;
#if defined(CONFIG_FIPS_FMP)
	if (unlikely(in_fmp_fips_err())) {
		printk(KERN_ERR "Fail to work fmp due to fips in error\n");
		return -EPERM;
	}
#endif
	ret = configure_fmp_disk_enc(prd_table, enc_mode, idx, sector, bio, size);
	if (ret) {
		printk(KERN_ERR "Fail to confgure fmp disk enc mode\n");
		return ret;
	}

#if defined(CONFIG_UFS_FMP_ECRYPT_FS) || defined(CONFIG_UFS_FMP_EXT4CRYPT_FS)
	if (bio->private_enc_mode == FMP_FILE_ENC_MODE) {
		ret = configure_fmp_file_enc_direct_io(prd_table, enc_mode,
						idx, sector, bio, sg, size);
		if (ret) {
			printk(KERN_ERR "Fail to confgure fmp file enc mode\n");
			return ret;
		}
		return 0;
	}

	ret = configure_fmp_file_enc(prd_table, enc_mode, idx, sector,
							sg, size);
	if (ret) {
		printk(KERN_ERR "Fail to confgure fmp file enc mode\n");
		return ret;
	}

#else
	if (enc_mode & UFS_FILE_ENC_MODE)
		return -EOPNOTSUPP;
#endif

	return 0;
}
EXPORT_SYMBOL_GPL(fmp_ufs_map_sg);

#if defined(CONFIG_FIPS_FMP)
#if defined(CONFIG_UFS_FMP_ECRYPT_FS) || defined(CONFIG_UFS_FMP_EXT4CRYPT_FS)
void fmp_clear_sg(struct ufshcd_lrb *lrbp)
{
	struct scatterlist *sg;
	int sg_segments;
	struct ufshcd_sg_entry *prd_table;
	struct scsi_cmnd *cmd = lrbp->cmd;
	int i;

	sg_segments = scsi_sg_count(cmd);
	if (sg_segments) {
		prd_table = (struct ufshcd_sg_entry *)lrbp->ucd_prdt_ptr;
		scsi_for_each_sg(cmd, sg, sg_segments, i) {
			if (!GET_FAS(&prd_table[i]))
				continue;

#if FIPS_FMP_FUNC_TEST == 6 /* Key Zeroization */
			print_hex_dump(KERN_ERR, "FIPS FMP descriptor before zeroize:",
					DUMP_PREFIX_NONE, 16, 1, &prd_table[i].file_iv0,
					sizeof(__le32)*20, false);
#endif
			memset(&prd_table[i].file_iv0, 0x0, sizeof(__le32)*20);
#if FIPS_FMP_FUNC_TEST == 6 /* Key Zeroization */
			print_hex_dump(KERN_ERR, "FIPS FMP descriptor after zeroize:",
					DUMP_PREFIX_NONE, 16, 1, &prd_table[i].file_iv0,
					sizeof(__le32)*20, false);
#endif
		}
	}
	return;
}
#endif
#endif

#if defined(CONFIG_FIPS_FMP)
int fmp_map_sg_st(struct ufs_hba *hba, struct ufshcd_sg_entry *prd_table,
					struct scatterlist *sg, uint32_t enc_mode,
					uint32_t idx, uint32_t sector)
{
	struct ufshcd_sg_entry *prd_table_st = hba->ucd_prdt_ptr_st;

	if (!enc_mode) {
		SET_FAS(&prd_table[idx], CLEAR);
		SET_DAS(&prd_table[idx], CLEAR);
		return 0;
	}

	/* algorithm */
	if (hba->self_test_mode == XTS_MODE) {
		if (prd_table[idx].size > 0x1000) {
			printk(KERN_ERR "Fail to FMP XTS due to invalid size \
					for File Encrytion. size = 0x%x\n", prd_table[idx].size);
			return -EINVAL;
		}

		if (fmp_xts_check_key((uint8_t *)&prd_table_st->file_enckey0,
							(uint8_t *)&prd_table_st->file_twkey0, prd_table_st->size)) {
			printk(KERN_ERR "Fail to FMP XTS because enckey and twkey is the same\n");
			return -EINVAL;
		}

		SET_FAS(&prd_table[idx], AES_XTS);
	} else if (hba->self_test_mode == CBC_MODE)
		SET_FAS(&prd_table[idx], AES_CBC);
	else {
		printk(KERN_ERR "Invalid algorithm for FMP FIPS validation. mode = %d\n", hba->self_test_mode);
		return -EINVAL;
	}

	if (prd_table_st->size == 32)
		prd_table[idx].size |= FKL;

	/* File IV */
	prd_table[idx].file_iv0 = prd_table_st->file_iv0;
	prd_table[idx].file_iv1 = prd_table_st->file_iv1;
	prd_table[idx].file_iv2 = prd_table_st->file_iv2;
	prd_table[idx].file_iv3 = prd_table_st->file_iv3;

	/* enc key */
	prd_table[idx].file_enckey0 = prd_table_st->file_enckey0;
	prd_table[idx].file_enckey1 = prd_table_st->file_enckey1;
	prd_table[idx].file_enckey2 = prd_table_st->file_enckey2;
	prd_table[idx].file_enckey3 = prd_table_st->file_enckey3;
	prd_table[idx].file_enckey4 = prd_table_st->file_enckey4;
	prd_table[idx].file_enckey5 = prd_table_st->file_enckey5;
	prd_table[idx].file_enckey6 = prd_table_st->file_enckey6;
	prd_table[idx].file_enckey7 = prd_table_st->file_enckey7;

	/* tweak key */
	prd_table[idx].file_twkey0 = prd_table_st->file_twkey0;
	prd_table[idx].file_twkey1 = prd_table_st->file_twkey1;
	prd_table[idx].file_twkey2 = prd_table_st->file_twkey2;
	prd_table[idx].file_twkey3 = prd_table_st->file_twkey3;
	prd_table[idx].file_twkey4 = prd_table_st->file_twkey4;
	prd_table[idx].file_twkey5 = prd_table_st->file_twkey5;
	prd_table[idx].file_twkey6 = prd_table_st->file_twkey6;
	prd_table[idx].file_twkey7 = prd_table_st->file_twkey7;

	return 0;
}
EXPORT_SYMBOL_GPL(fmp_map_sg_st);
#endif

#if defined(CONFIG_UFS_FMP_DM_CRYPT) && defined(CONFIG_FIPS_FMP)
int fmp_clear_disk_key(void)
{
	struct device_node *dev_node;
	struct platform_device *pdev;
	struct device *dev;
	struct ufs_hba *hba;

	dev_node = of_find_compatible_node(NULL, NULL, "samsung,exynos-ufs");
	if (!dev_node) {
		printk(KERN_ERR "Fail to find exynos ufs device node\n");
		return -ENODEV;
	}

	pdev = of_find_device_by_node(dev_node);
	if (!pdev) {
		printk(KERN_ERR "Fail to find exynos ufs pdev\n");
		return -ENODEV;
	}

	dev = &pdev->dev;
	hba = dev_get_drvdata(dev);
	if (!hba) {
		printk(KERN_ERR "Fail to find hba from dev\n");
		return -ENODEV;
	}

	spin_lock(&disk_key_lock);
	disk_key_flag = 2;
	spin_unlock(&disk_key_lock);

	printk(KERN_INFO "FMP disk encryption key is clear\n");
	exynos_ufs_ctrl_auto_hci_clk(dev_get_platdata(hba->dev), false);
#ifdef CONFIG_SOC_EXYNOS8890
	return exynos_smc(SMC_CMD_FMP, FMP_KEY_CLEAR, 0, 0);
#else
	return exynos_smc(SMC_CMD_FMP_DISKENC, FMP_DISKKEY_CLEAR, ID_FMP_UFS_MMC, 0);
#endif
}
#endif
