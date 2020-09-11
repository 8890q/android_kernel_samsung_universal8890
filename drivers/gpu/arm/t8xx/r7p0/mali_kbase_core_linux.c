
/*
 *
 * (C) COPYRIGHT 2010-2015 ARM Limited. All rights reserved.
 *
 * This program is free software and is provided to you under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms
 * of such GNU licence.
 *
 * A copy of the licence is included with the program, and can also be obtained
 * from Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 */



#include <mali_kbase.h>
#include <mali_kbase_hwaccess_gpuprops.h>
#include <mali_kbase_config_defaults.h>
#include <mali_kbase_uku.h>
#include <mali_midg_regmap.h>
#include <mali_kbase_instr.h>
#include <mali_kbase_gator.h>
#include <backend/gpu/mali_kbase_js_affinity.h>
#include <mali_kbase_mem_linux.h>
#ifdef CONFIG_MALI_DEVFREQ
#include <backend/gpu/mali_kbase_devfreq.h>
#endif /* CONFIG_MALI_DEVFREQ */
#ifdef CONFIG_MALI_NO_MALI
#include "mali_kbase_model_linux.h"
#endif /* CONFIG_MALI_NO_MALI */
#include "mali_kbase_mem_profile_debugfs_buf_size.h"
#include "mali_kbase_debug_mem_view.h"
#include "mali_kbase_mem.h"
#include "mali_kbase_mem_pool_debugfs.h"
#include <mali_kbase_hwaccess_backend.h>
#include <mali_kbase_hwaccess_jm.h>
#include <backend/gpu/mali_kbase_device_internal.h>

#ifdef CONFIG_KDS
#include <linux/kds.h>
#include <linux/anon_inodes.h>
#include <linux/syscalls.h>
#endif /* CONFIG_KDS */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/list.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/compat.h>	/* is_compat_task */
#include <linux/version.h>
#ifdef CONFIG_MALI_PLATFORM_DEVICETREE
#include <linux/pm_runtime.h>
#endif /* CONFIG_MALI_PLATFORM_DEVICETREE */
#include <mali_kbase_hw.h>
#include <platform/mali_kbase_platform_common.h>
#ifdef CONFIG_MALI_PLATFORM_FAKE
#include <platform/mali_kbase_platform_fake.h>
#endif /*CONFIG_MALI_PLATFORM_FAKE */
#ifdef CONFIG_SYNC
#include <mali_kbase_sync.h>
#endif /* CONFIG_SYNC */
#ifdef CONFIG_PM_DEVFREQ
#include <linux/devfreq.h>
#endif /* CONFIG_PM_DEVFREQ */
#include <linux/clk.h>
#include <linux/delay.h>

#include <mali_kbase_config.h>

#ifdef CONFIG_MACH_MANTA
#include <plat/devs.h>
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0))
#include <linux/pm_opp.h>
#else
#include <linux/opp.h>
#endif

#if defined(CONFIG_MALI_MIPE_ENABLED)
#include <mali_kbase_tlstream.h>
#endif

/* GPU IRQ Tags */
#define	JOB_IRQ_TAG	0
#define MMU_IRQ_TAG	1
#define GPU_IRQ_TAG	2

#if MALI_UNIT_TEST
static struct kbase_exported_test_data shared_kernel_test_data;
EXPORT_SYMBOL(shared_kernel_test_data);
#endif /* MALI_UNIT_TEST */

#define KBASE_DRV_NAME "mali"

static const char kbase_drv_name[] = KBASE_DRV_NAME;

static int kbase_dev_nr;

static DEFINE_MUTEX(kbase_dev_list_lock);
static LIST_HEAD(kbase_dev_list);

#define KERNEL_SIDE_DDK_VERSION_STRING "K:" MALI_RELEASE_NAME "(GPL)"
static inline void __compile_time_asserts(void)
{
	CSTD_COMPILE_TIME_ASSERT(sizeof(KERNEL_SIDE_DDK_VERSION_STRING) <= KBASE_GET_VERSION_BUFFER_SIZE);
}

#ifdef CONFIG_KDS

struct kbasep_kds_resource_set_file_data {
	struct kds_resource_set *lock;
};

static int kds_resource_release(struct inode *inode, struct file *file);

static const struct file_operations kds_resource_fops = {
	.release = kds_resource_release
};

struct kbase_kds_resource_list_data {
	struct kds_resource **kds_resources;
	unsigned long *kds_access_bitmap;
	int num_elems;
};

static int kds_resource_release(struct inode *inode, struct file *file)
{
	struct kbasep_kds_resource_set_file_data *data;

	data = (struct kbasep_kds_resource_set_file_data *)file->private_data;
	if (NULL != data) {
		if (NULL != data->lock)
			kds_resource_set_release(&data->lock);

		kfree(data);
	}
	return 0;
}

static int kbasep_kds_allocate_resource_list_data(struct kbase_context *kctx, struct base_external_resource *ext_res, int num_elems, struct kbase_kds_resource_list_data *resources_list)
{
	struct base_external_resource *res = ext_res;
	int res_id;

	/* assume we have to wait for all */

	KBASE_DEBUG_ASSERT(0 != num_elems);
	resources_list->kds_resources = kmalloc_array(num_elems,
			sizeof(struct kds_resource *), GFP_KERNEL);

	if (NULL == resources_list->kds_resources)
		return -ENOMEM;

	KBASE_DEBUG_ASSERT(0 != num_elems);
	resources_list->kds_access_bitmap = kzalloc(
			sizeof(unsigned long) *
			((num_elems + BITS_PER_LONG - 1) / BITS_PER_LONG),
			GFP_KERNEL);

	if (NULL == resources_list->kds_access_bitmap) {
		kfree(resources_list->kds_access_bitmap);
		return -ENOMEM;
	}

	kbase_gpu_vm_lock(kctx);
	for (res_id = 0; res_id < num_elems; res_id++, res++) {
		int exclusive;
		struct kbase_va_region *reg;
		struct kds_resource *kds_res = NULL;

		exclusive = res->ext_resource & BASE_EXT_RES_ACCESS_EXCLUSIVE;
		reg = kbase_region_tracker_find_region_enclosing_address(kctx, res->ext_resource & ~BASE_EXT_RES_ACCESS_EXCLUSIVE);

		/* did we find a matching region object? */
		if (NULL == reg || (reg->flags & KBASE_REG_FREE))
			break;

		/* no need to check reg->alloc as only regions with an alloc has
		 * a size, and kbase_region_tracker_find_region_enclosing_address
		 * only returns regions with size > 0 */
		switch (reg->gpu_alloc->type) {
#if defined(CONFIG_UMP) && defined(CONFIG_KDS)
		case KBASE_MEM_TYPE_IMPORTED_UMP:
			kds_res = ump_dd_kds_resource_get(reg->gpu_alloc->imported.ump_handle);
			break;
#endif /* defined(CONFIG_UMP) && defined(CONFIG_KDS) */
		default:
			break;
		}

		/* no kds resource for the region ? */
		if (!kds_res)
			break;

		resources_list->kds_resources[res_id] = kds_res;

		if (exclusive)
			set_bit(res_id, resources_list->kds_access_bitmap);
	}
	kbase_gpu_vm_unlock(kctx);

	/* did the loop run to completion? */
	if (res_id == num_elems)
		return 0;

	/* Clean up as the resource list is not valid. */
	kfree(resources_list->kds_resources);
	kfree(resources_list->kds_access_bitmap);

	return -EINVAL;
}

static bool kbasep_validate_kbase_pointer(
		struct kbase_context *kctx, union kbase_pointer *p)
{
	if (kctx->is_compat) {
		if (p->compat_value == 0)
			return false;
	} else {
		if (NULL == p->value)
			return false;
	}
	return true;
}

static int kbase_external_buffer_lock(struct kbase_context *kctx,
		struct kbase_uk_ext_buff_kds_data *args, u32 args_size)
{
	struct base_external_resource *ext_res_copy;
	size_t ext_resource_size;
	int ret = -EINVAL;
	int fd = -EBADF;
	struct base_external_resource __user *ext_res_user;
	int __user *file_desc_usr;
	struct kbasep_kds_resource_set_file_data *fdata;
	struct kbase_kds_resource_list_data resource_list_data;

	if (args_size != sizeof(struct kbase_uk_ext_buff_kds_data))
		return -EINVAL;

	/* Check user space has provided valid data */
	if (!kbasep_validate_kbase_pointer(kctx, &args->external_resource) ||
			!kbasep_validate_kbase_pointer(kctx, &args->file_descriptor) ||
			(0 == args->num_res) ||
			(args->num_res > KBASE_MAXIMUM_EXT_RESOURCES))
		return -EINVAL;

	ext_resource_size = sizeof(struct base_external_resource) * args->num_res;

	KBASE_DEBUG_ASSERT(0 != ext_resource_size);
	ext_res_copy = kmalloc(ext_resource_size, GFP_KERNEL);

	if (!ext_res_copy)
		return -EINVAL;
#ifdef CONFIG_COMPAT
	if (kctx->is_compat) {
		ext_res_user = compat_ptr(args->external_resource.compat_value);
		file_desc_usr = compat_ptr(args->file_descriptor.compat_value);
	} else {
#endif /* CONFIG_COMPAT */
		ext_res_user = args->external_resource.value;
		file_desc_usr = args->file_descriptor.value;
#ifdef CONFIG_COMPAT
	}
#endif /* CONFIG_COMPAT */

	/* Copy the external resources to lock from user space */
	if (copy_from_user(ext_res_copy, ext_res_user, ext_resource_size))
		goto out;

	/* Allocate data to be stored in the file */
	fdata = kmalloc(sizeof(*fdata), GFP_KERNEL);

	if (!fdata) {
		ret = -ENOMEM;
		goto out;
	}

	/* Parse given elements and create resource and access lists */
	ret = kbasep_kds_allocate_resource_list_data(kctx,
			ext_res_copy, args->num_res, &resource_list_data);
	if (!ret) {
		long err;

		fdata->lock = NULL;

		fd = anon_inode_getfd("kds_ext", &kds_resource_fops, fdata, 0);

		err = copy_to_user(file_desc_usr, &fd, sizeof(fd));

		/* If the file descriptor was valid and we successfully copied
		 * it to user space, then we can try and lock the requested
		 * kds resources.
		 */
		if ((fd >= 0) && (0 == err)) {
			struct kds_resource_set *lock;

			lock = kds_waitall(args->num_res,
					resource_list_data.kds_access_bitmap,
					resource_list_data.kds_resources,
					KDS_WAIT_BLOCKING);

			if (IS_ERR_OR_NULL(lock)) {
				ret = -EINVAL;
			} else {
				ret = 0;
				fdata->lock = lock;
			}
		} else {
			ret = -EINVAL;
		}

		kfree(resource_list_data.kds_resources);
		kfree(resource_list_data.kds_access_bitmap);
	}

	if (ret) {
		/* If the file was opened successfully then close it which will
		 * clean up the file data, otherwise we clean up the file data
		 * ourself.
		 */
		if (fd >= 0)
			sys_close(fd);
		else
			kfree(fdata);
	}
out:
	kfree(ext_res_copy);

	return ret;
}
#endif /* CONFIG_KDS */

#ifdef CONFIG_MALI_MIPE_ENABLED
static void kbase_create_timeline_objects(struct kbase_context *kctx)
{
	struct kbase_device             *kbdev = kctx->kbdev;
	unsigned int                    lpu_id;
	unsigned int                    as_nr;
	struct kbasep_kctx_list_element *element;

	/* Create LPU objects. */
	for (lpu_id = 0; lpu_id < kbdev->gpu_props.num_job_slots; lpu_id++) {
		u32 *lpu =
			&kbdev->gpu_props.props.raw_props.js_features[lpu_id];
		kbase_tlstream_tl_summary_new_lpu(lpu, lpu_id, *lpu);
	}

	/* Create Address Space objects. */
	for (as_nr = 0; as_nr < kbdev->nr_hw_address_spaces; as_nr++)
		kbase_tlstream_tl_summary_new_as(&kbdev->as[as_nr], as_nr);

	/* Create GPU object and make it retain all LPUs and address spaces. */
	kbase_tlstream_tl_summary_new_gpu(
			kbdev,
			kbdev->gpu_props.props.raw_props.gpu_id,
			kbdev->gpu_props.num_cores);

	for (lpu_id = 0; lpu_id < kbdev->gpu_props.num_job_slots; lpu_id++) {
		void *lpu =
			&kbdev->gpu_props.props.raw_props.js_features[lpu_id];
		kbase_tlstream_tl_summary_lifelink_lpu_gpu(lpu, kbdev);
	}
	for (as_nr = 0; as_nr < kbdev->nr_hw_address_spaces; as_nr++)
		kbase_tlstream_tl_summary_lifelink_as_gpu(
				&kbdev->as[as_nr],
				kbdev);

	/* Create object for each known context. */
	mutex_lock(&kbdev->kctx_list_lock);
	list_for_each_entry(element, &kbdev->kctx_list, link) {
		kbase_tlstream_tl_summary_new_ctx(
				element->kctx,
				(u32)(element->kctx->id));
	}
	/* Before releasing the lock, reset body stream buffers.
	 * This will prevent context creation message to be directed to both
	 * summary and body stream. */
	kbase_tlstream_reset_body_streams();
	mutex_unlock(&kbdev->kctx_list_lock);
	/* Static object are placed into summary packet that needs to be
	 * transmitted first. Flush all streams to make it available to
	 * user space. */
	kbase_tlstream_flush_streams();
}
#endif

static void kbase_api_handshake(struct uku_version_check_args *version)
{
	switch (version->major) {
#ifdef BASE_LEGACY_UK6_SUPPORT
	case 6:
		/* We are backwards compatible with version 6,
		 * so pretend to be the old version */
		version->major = 6;
		version->minor = 1;
		break;
#endif /* BASE_LEGACY_UK6_SUPPORT */
#ifdef BASE_LEGACY_UK7_SUPPORT
	case 7:
		/* We are backwards compatible with version 7,
		 * so pretend to be the old version */
		version->major = 7;
		version->minor = 1;
		break;
#endif /* BASE_LEGACY_UK7_SUPPORT */
#ifdef BASE_LEGACY_UK8_SUPPORT
	case 8:
		/* We are backwards compatible with version 8,
		 * so pretend to be the old version */
		version->major = 8;
		version->minor = 4;
		break;
#endif /* BASE_LEGACY_UK8_SUPPORT */
#ifdef BASE_LEGACY_UK9_SUPPORT
	case 9:
		/* We are backwards compatible with version 9,
		 * so pretend to be the old version */
		version->major = 9;
		version->minor = 0;
		break;
#endif /* BASE_LEGACY_UK8_SUPPORT */
	case BASE_UK_VERSION_MAJOR:
		/* set minor to be the lowest common */
		version->minor = min_t(int, BASE_UK_VERSION_MINOR,
				(int)version->minor);
		break;
	default:
		/* We return our actual version regardless if it
		 * matches the version returned by userspace -
		 * userspace can bail if it can't handle this
		 * version */
		version->major = BASE_UK_VERSION_MAJOR;
		version->minor = BASE_UK_VERSION_MINOR;
		break;
	}
}

/**
 * enum mali_error - Mali error codes shared with userspace
 *
 * This is subset of those common Mali errors that can be returned to userspace.
 * Values of matching user and kernel space enumerators MUST be the same.
 * MALI_ERROR_NONE is guaranteed to be 0.
 */
enum mali_error {
	MALI_ERROR_NONE = 0,
	MALI_ERROR_OUT_OF_GPU_MEMORY,
	MALI_ERROR_OUT_OF_MEMORY,
	MALI_ERROR_FUNCTION_FAILED,
};

#ifdef CONFIG_MALI_DEBUG
#define INACTIVE_WAIT_MS (5000)

void kbase_set_driver_inactive(struct kbase_device *kbdev, bool inactive)
{
	kbdev->driver_inactive = inactive;
	wake_up(&kbdev->driver_inactive_wait);

	/* Wait for any running IOCTLs to complete */
	if (inactive)
		msleep(INACTIVE_WAIT_MS);
}
KBASE_EXPORT_TEST_API(kbase_set_driver_inactive);
#endif /* CONFIG_MALI_DEBUG */

static int kbase_dispatch(struct kbase_context *kctx, void * const args, u32 args_size)
{
	struct kbase_device *kbdev;
	union uk_header *ukh = args;
	u32 id;

	KBASE_DEBUG_ASSERT(ukh != NULL);

	kbdev = kctx->kbdev;
	id = ukh->id;
	ukh->ret = MALI_ERROR_NONE; /* Be optimistic */

#ifdef CONFIG_MALI_DEBUG
	wait_event(kbdev->driver_inactive_wait,
			kbdev->driver_inactive == false);
#endif /* CONFIG_MALI_DEBUG */

	if (UKP_FUNC_ID_CHECK_VERSION == id) {
		struct uku_version_check_args *version_check;

		if (args_size != sizeof(struct uku_version_check_args)) {
			ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			return 0;
		}
		version_check = (struct uku_version_check_args *)args;
		kbase_api_handshake(version_check);
		/* save the proposed version number for later use */
		kctx->api_version = KBASE_API_VERSION(version_check->major,
				version_check->minor);
		ukh->ret = MALI_ERROR_NONE;
		return 0;
	}

	/* block calls until version handshake */
	if (kctx->api_version == 0)
		return -EINVAL;

	if (!atomic_read(&kctx->setup_complete)) {
		struct kbase_uk_set_flags *kbase_set_flags;

		/* setup pending, try to signal that we'll do the setup,
		 * if setup was already in progress, err this call
		 */
		if (atomic_cmpxchg(&kctx->setup_in_progress, 0, 1) != 0)
			return -EINVAL;

		/* if unexpected call, will stay stuck in setup mode
		 * (is it the only call we accept?)
		 */
		if (id != KBASE_FUNC_SET_FLAGS)
			return -EINVAL;

		kbase_set_flags = (struct kbase_uk_set_flags *)args;

		/* if not matching the expected call, stay in setup mode */
		if (sizeof(*kbase_set_flags) != args_size)
			goto bad_size;

		/* if bad flags, will stay stuck in setup mode */
		if (kbase_context_set_create_flags(kctx,
				kbase_set_flags->create_flags) != 0)
			ukh->ret = MALI_ERROR_FUNCTION_FAILED;

		atomic_set(&kctx->setup_complete, 1);
		return 0;
	}

	/* setup complete, perform normal operation */
	switch (id) {
	case KBASE_FUNC_MEM_ALLOC:
		{
			struct kbase_uk_mem_alloc *mem = args;
			struct kbase_va_region *reg;

			if (sizeof(*mem) != args_size)
				goto bad_size;

			reg = kbase_mem_alloc(kctx, mem->va_pages,
					mem->commit_pages, mem->extent,
					&mem->flags, &mem->gpu_va,
					&mem->va_alignment);
			if (!reg)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			break;
		}
	case KBASE_FUNC_MEM_IMPORT:
		{
			struct kbase_uk_mem_import *mem_import = args;
			int __user *phandle;
			int handle;

			if (sizeof(*mem_import) != args_size)
				goto bad_size;
#ifdef CONFIG_COMPAT
			if (kctx->is_compat)
				phandle = compat_ptr(mem_import->phandle.compat_value);
			else
#endif
				phandle = mem_import->phandle.value;

			switch (mem_import->type) {
			case BASE_MEM_IMPORT_TYPE_UMP:
				get_user(handle, phandle);
				break;
			case BASE_MEM_IMPORT_TYPE_UMM:
				get_user(handle, phandle);
				break;
			default:
				mem_import->type = BASE_MEM_IMPORT_TYPE_INVALID;
				break;
			}

			if (mem_import->type == BASE_MEM_IMPORT_TYPE_INVALID ||
					kbase_mem_import(kctx, mem_import->type,
					handle, &mem_import->gpu_va,
					&mem_import->va_pages,
					&mem_import->flags))
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			break;
		}
	case KBASE_FUNC_MEM_ALIAS: {
			struct kbase_uk_mem_alias *alias = args;
			struct base_mem_aliasing_info __user *user_ai;
			struct base_mem_aliasing_info *ai;

			if (sizeof(*alias) != args_size)
				goto bad_size;

			if (alias->nents > 2048) {
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				break;
			}
			if (!alias->nents) {
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				break;
			}

#ifdef CONFIG_COMPAT
			if (kctx->is_compat)
				user_ai = compat_ptr(alias->ai.compat_value);
			else
#endif
				user_ai = alias->ai.value;

			ai = vmalloc(sizeof(*ai) * alias->nents);

			if (!ai) {
				ukh->ret = MALI_ERROR_OUT_OF_MEMORY;
				break;
			}

			if (copy_from_user(ai, user_ai,
					   sizeof(*ai) * alias->nents)) {
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				goto copy_failed;
			}

			alias->gpu_va = kbase_mem_alias(kctx, &alias->flags,
							alias->stride,
							alias->nents, ai,
							&alias->va_pages);
			if (!alias->gpu_va) {
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				goto no_alias;
			}
no_alias:
copy_failed:
			vfree(ai);
			break;
		}
	case KBASE_FUNC_MEM_COMMIT:
		{
			struct kbase_uk_mem_commit *commit = args;

			if (sizeof(*commit) != args_size)
				goto bad_size;

			if (commit->gpu_addr & ~PAGE_MASK) {
				dev_warn(kbdev->dev, "kbase_dispatch case KBASE_FUNC_MEM_COMMIT: commit->gpu_addr: passed parameter is invalid");
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				break;
			}

			if (kbase_mem_commit(kctx, commit->gpu_addr,
					commit->pages,
					(base_backing_threshold_status *)
					&commit->result_subcode) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;

			break;
		}

	case KBASE_FUNC_MEM_QUERY:
		{
			struct kbase_uk_mem_query *query = args;

			if (sizeof(*query) != args_size)
				goto bad_size;

			if (query->gpu_addr & ~PAGE_MASK) {
				dev_warn(kbdev->dev, "kbase_dispatch case KBASE_FUNC_MEM_QUERY: query->gpu_addr: passed parameter is invalid");
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				break;
			}
			if (query->query != KBASE_MEM_QUERY_COMMIT_SIZE &&
			    query->query != KBASE_MEM_QUERY_VA_SIZE &&
				query->query != KBASE_MEM_QUERY_FLAGS) {
				dev_warn(kbdev->dev, "kbase_dispatch case KBASE_FUNC_MEM_QUERY: query->query = %lld unknown", (unsigned long long)query->query);
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				break;
			}

			if (kbase_mem_query(kctx, query->gpu_addr,
					query->query, &query->value) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			else
				ukh->ret = MALI_ERROR_NONE;
			break;
		}
		break;

	case KBASE_FUNC_MEM_FLAGS_CHANGE:
		{
			struct kbase_uk_mem_flags_change *fc = args;

			if (sizeof(*fc) != args_size)
				goto bad_size;

			if ((fc->gpu_va & ~PAGE_MASK) && (fc->gpu_va >= PAGE_SIZE)) {
				dev_warn(kbdev->dev, "kbase_dispatch case KBASE_FUNC_MEM_FLAGS_CHANGE: mem->gpu_va: passed parameter is invalid");
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				break;
			}

			if (kbase_mem_flags_change(kctx, fc->gpu_va,
					fc->flags, fc->mask) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;

			break;
		}
	case KBASE_FUNC_MEM_FREE:
		{
			struct kbase_uk_mem_free *mem = args;

			if (sizeof(*mem) != args_size)
				goto bad_size;

			if ((mem->gpu_addr & ~PAGE_MASK) && (mem->gpu_addr >= PAGE_SIZE)) {
				dev_warn(kbdev->dev, "kbase_dispatch case KBASE_FUNC_MEM_FREE: mem->gpu_addr: passed parameter is invalid");
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				break;
			}

			if (kbase_mem_free(kctx, mem->gpu_addr) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			break;
		}

	case KBASE_FUNC_JOB_SUBMIT:
		{
			struct kbase_uk_job_submit *job = args;

			if (sizeof(*job) != args_size)
				goto bad_size;

#ifdef BASE_LEGACY_UK6_SUPPORT
			if (kbase_jd_submit(kctx, job, 0) != 0)
#else
			if (kbase_jd_submit(kctx, job) != 0)
#endif /* BASE_LEGACY_UK6_SUPPORT */
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			break;
		}

#ifdef BASE_LEGACY_UK6_SUPPORT
	case KBASE_FUNC_JOB_SUBMIT_UK6:
		{
			struct kbase_uk_job_submit *job = args;

			if (sizeof(*job) != args_size)
				goto bad_size;

			if (kbase_jd_submit(kctx, job, 1) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			break;
		}
#endif

	case KBASE_FUNC_SYNC:
		{
			struct kbase_uk_sync_now *sn = args;

			if (sizeof(*sn) != args_size)
				goto bad_size;

			if (sn->sset.basep_sset.mem_handle & ~PAGE_MASK) {
				dev_warn(kbdev->dev, "kbase_dispatch case KBASE_FUNC_SYNC: sn->sset.basep_sset.mem_handle: passed parameter is invalid");
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				break;
			}

#ifndef CONFIG_MALI_COH_USER
			if (kbase_sync_now(kctx, &sn->sset) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
#endif
			break;
		}

	case KBASE_FUNC_DISJOINT_QUERY:
		{
			struct kbase_uk_disjoint_query *dquery = args;

			if (sizeof(*dquery) != args_size)
				goto bad_size;

			/* Get the disjointness counter value. */
			dquery->counter = kbase_disjoint_event_get(kctx->kbdev);
			break;
		}

	case KBASE_FUNC_POST_TERM:
		{
			kbase_event_close(kctx);
			break;
		}

	case KBASE_FUNC_HWCNT_SETUP:
		{
			struct kbase_uk_hwcnt_setup *setup = args;
			bool access_allowed;

			if (sizeof(*setup) != args_size)
				goto bad_size;

			access_allowed = kbase_security_has_capability(
					kctx,
					KBASE_SEC_INSTR_HW_COUNTERS_COLLECT,
					KBASE_SEC_FLAG_NOAUDIT);
			if (!access_allowed)
				goto out_bad;

			mutex_lock(&kctx->vinstr_cli_lock);
			if (kbase_vinstr_legacy_hwc_setup(kbdev->vinstr_ctx,
					&kctx->vinstr_cli, setup) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			mutex_unlock(&kctx->vinstr_cli_lock);
			break;
		}

	case KBASE_FUNC_HWCNT_DUMP:
		{
			/* args ignored */
			mutex_lock(&kctx->vinstr_cli_lock);
			if (kbase_vinstr_hwc_dump(kctx->vinstr_cli,
					BASE_HWCNT_READER_EVENT_MANUAL) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			mutex_unlock(&kctx->vinstr_cli_lock);
			break;
		}

	case KBASE_FUNC_HWCNT_CLEAR:
		{
			/* args ignored */
			mutex_lock(&kctx->vinstr_cli_lock);
			if (kbase_vinstr_hwc_clear(kctx->vinstr_cli) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			mutex_unlock(&kctx->vinstr_cli_lock);
			break;
		}

	case KBASE_FUNC_HWCNT_READER_SETUP:
		{
			struct kbase_uk_hwcnt_reader_setup *setup = args;
			bool access_allowed;

			if (sizeof(*setup) != args_size)
				goto bad_size;

			access_allowed = kbase_security_has_capability(
					kctx,
					KBASE_SEC_INSTR_HW_COUNTERS_COLLECT,
					KBASE_SEC_FLAG_NOAUDIT);
			if (!access_allowed)
				goto out_bad;

			mutex_lock(&kctx->vinstr_cli_lock);
			if (kbase_vinstr_hwcnt_reader_setup(kbdev->vinstr_ctx,
					setup) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			mutex_unlock(&kctx->vinstr_cli_lock);
			break;
		}

	case KBASE_FUNC_GPU_PROPS_REG_DUMP:
		{
			struct kbase_uk_gpuprops *setup = args;

			if (sizeof(*setup) != args_size)
				goto bad_size;

			if (kbase_gpuprops_uk_get_props(kctx, setup) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			break;
		}
	case KBASE_FUNC_FIND_CPU_OFFSET:
		{
			struct kbase_uk_find_cpu_offset *find = args;

			if (sizeof(*find) != args_size)
				goto bad_size;

			if (find->gpu_addr & ~PAGE_MASK) {
				dev_warn(kbdev->dev, "kbase_dispatch case KBASE_FUNC_FIND_CPU_OFFSET: find->gpu_addr: passed parameter is invalid");
				goto out_bad;
			}

			if (find->size > SIZE_MAX || find->cpu_addr > ULONG_MAX) {
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			} else {
				int err;

				err = kbasep_find_enclosing_cpu_mapping_offset(
						kctx,
						find->gpu_addr,
						(uintptr_t) find->cpu_addr,
						(size_t) find->size,
						&find->offset);

				if (err)
					ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			}
			break;
		}
	case KBASE_FUNC_GET_VERSION:
		{
			struct kbase_uk_get_ddk_version *get_version = (struct kbase_uk_get_ddk_version *)args;

			if (sizeof(*get_version) != args_size)
				goto bad_size;

			/* version buffer size check is made in compile time assert */
			memcpy(get_version->version_buffer, KERNEL_SIDE_DDK_VERSION_STRING, sizeof(KERNEL_SIDE_DDK_VERSION_STRING));
			get_version->version_string_size = sizeof(KERNEL_SIDE_DDK_VERSION_STRING);
			break;
		}

	case KBASE_FUNC_STREAM_CREATE:
		{
#ifdef CONFIG_SYNC
			struct kbase_uk_stream_create *screate = (struct kbase_uk_stream_create *)args;

			if (sizeof(*screate) != args_size)
				goto bad_size;

			if (strnlen(screate->name, sizeof(screate->name)) >= sizeof(screate->name)) {
				/* not NULL terminated */
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				break;
			}

			if (kbase_stream_create(screate->name, &screate->fd) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			else
				ukh->ret = MALI_ERROR_NONE;
#else /* CONFIG_SYNC */
			ukh->ret = MALI_ERROR_FUNCTION_FAILED;
#endif /* CONFIG_SYNC */
			break;
		}
	case KBASE_FUNC_FENCE_VALIDATE:
		{
#ifdef CONFIG_SYNC
			struct kbase_uk_fence_validate *fence_validate = (struct kbase_uk_fence_validate *)args;

			if (sizeof(*fence_validate) != args_size)
				goto bad_size;

			if (kbase_fence_validate(fence_validate->fd) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			else
				ukh->ret = MALI_ERROR_NONE;
#endif /* CONFIG_SYNC */
			break;
		}

	case KBASE_FUNC_EXT_BUFFER_LOCK:
		{
#ifdef CONFIG_KDS
			switch (kbase_external_buffer_lock(kctx,
				(struct kbase_uk_ext_buff_kds_data *)args,
				args_size)) {
			case 0:
				ukh->ret = MALI_ERROR_NONE;
				break;
			case -ENOMEM:
				ukh->ret = MALI_ERROR_OUT_OF_MEMORY;
				break;
			default:
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			}
#endif /* CONFIG_KDS */
			break;
		}

	case KBASE_FUNC_SET_TEST_DATA:
		{
#if MALI_UNIT_TEST
			struct kbase_uk_set_test_data *set_data = args;

			shared_kernel_test_data = set_data->test_data;
			shared_kernel_test_data.kctx.value = (void __user *)kctx;
			shared_kernel_test_data.mm.value = (void __user *)current->mm;
			ukh->ret = MALI_ERROR_NONE;
#endif /* MALI_UNIT_TEST */
			break;
		}

	case KBASE_FUNC_INJECT_ERROR:
		{
#ifdef CONFIG_MALI_ERROR_INJECT
			unsigned long flags;
			struct kbase_error_params params = ((struct kbase_uk_error_params *)args)->params;

			/*mutex lock */
			spin_lock_irqsave(&kbdev->reg_op_lock, flags);
			if (job_atom_inject_error(&params) != 0)
				ukh->ret = MALI_ERROR_OUT_OF_MEMORY;
			else
				ukh->ret = MALI_ERROR_NONE;
			spin_unlock_irqrestore(&kbdev->reg_op_lock, flags);
			/*mutex unlock */
#endif /* CONFIG_MALI_ERROR_INJECT */
			break;
		}

	case KBASE_FUNC_MODEL_CONTROL:
		{
#ifdef CONFIG_MALI_NO_MALI
			unsigned long flags;
			struct kbase_model_control_params params =
					((struct kbase_uk_model_control_params *)args)->params;

			/*mutex lock */
			spin_lock_irqsave(&kbdev->reg_op_lock, flags);
			if (gpu_model_control(kbdev->model, &params) != 0)
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			else
				ukh->ret = MALI_ERROR_NONE;
			spin_unlock_irqrestore(&kbdev->reg_op_lock, flags);
			/*mutex unlock */
#endif /* CONFIG_MALI_NO_MALI */
			break;
		}

#ifdef BASE_LEGACY_UK8_SUPPORT
	case KBASE_FUNC_KEEP_GPU_POWERED:
		{
			dev_warn(kbdev->dev, "kbase_dispatch case KBASE_FUNC_KEEP_GPU_POWERED: function is deprecated and disabled\n");
			ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			break;
		}
#endif /* BASE_LEGACY_UK8_SUPPORT */

	case KBASE_FUNC_GET_PROFILING_CONTROLS:
		{
			struct kbase_uk_profiling_controls *controls =
					(struct kbase_uk_profiling_controls *)args;
			u32 i;

			if (sizeof(*controls) != args_size)
				goto bad_size;

			for (i = FBDUMP_CONTROL_MIN; i < FBDUMP_CONTROL_MAX; i++)
				controls->profiling_controls[i] = kbase_get_profiling_control(kbdev, i);

			break;
		}

	/* used only for testing purposes; these controls are to be set by gator through gator API */
	case KBASE_FUNC_SET_PROFILING_CONTROLS:
		{
			struct kbase_uk_profiling_controls *controls =
					(struct kbase_uk_profiling_controls *)args;
			u32 i;

			if (sizeof(*controls) != args_size)
				goto bad_size;

			for (i = FBDUMP_CONTROL_MIN; i < FBDUMP_CONTROL_MAX; i++)
				_mali_profiling_control(i, controls->profiling_controls[i]);

			break;
		}

	case KBASE_FUNC_DEBUGFS_MEM_PROFILE_ADD:
		{
			struct kbase_uk_debugfs_mem_profile_add *add_data =
					(struct kbase_uk_debugfs_mem_profile_add *)args;
			char *buf;
			char __user *user_buf;

			if (sizeof(*add_data) != args_size)
				goto bad_size;

			if (add_data->len > KBASE_MEM_PROFILE_MAX_BUF_SIZE) {
				dev_err(kbdev->dev, "buffer too big");
				goto out_bad;
			}

#ifdef CONFIG_COMPAT
			if (kctx->is_compat)
				user_buf = compat_ptr(add_data->buf.compat_value);
			else
#endif
				user_buf = add_data->buf.value;

			buf = kmalloc(add_data->len, GFP_KERNEL);
			if (!buf)
				goto out_bad;

			if (0 != copy_from_user(buf, user_buf, add_data->len)) {
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
				kfree(buf);
				goto out_bad;
			}
			kbasep_mem_profile_debugfs_insert(kctx, buf,
					add_data->len);

			break;
		}
#ifdef CONFIG_MALI_MIPE_ENABLED
	case KBASE_FUNC_TLSTREAM_ACQUIRE:
		{
			struct kbase_uk_tlstream_acquire *tlstream_acquire =
				args;

			if (sizeof(*tlstream_acquire) != args_size)
				goto bad_size;

			if (0 != kbase_tlstream_acquire(
						kctx,
						&tlstream_acquire->fd)) {
				ukh->ret = MALI_ERROR_FUNCTION_FAILED;
			} else if (0 <= tlstream_acquire->fd) {
				/* Summary stream was cleared during acquire.
				 * Create static timeline objects that will be
				 * read by client. */
				kbase_create_timeline_objects(kctx);
			}
			break;
		}
	case KBASE_FUNC_TLSTREAM_FLUSH:
		{
			struct kbase_uk_tlstream_flush *tlstream_flush =
				args;

			if (sizeof(*tlstream_flush) != args_size)
				goto bad_size;

			kbase_tlstream_flush_streams();
			break;
		}
#if MALI_UNIT_TEST
	case KBASE_FUNC_TLSTREAM_TEST:
		{
			struct kbase_uk_tlstream_test *tlstream_test = args;

			if (sizeof(*tlstream_test) != args_size)
				goto bad_size;

			kbase_tlstream_test(
					tlstream_test->tpw_count,
					tlstream_test->msg_delay,
					tlstream_test->msg_count,
					tlstream_test->aux_msg);
			break;
		}
	case KBASE_FUNC_TLSTREAM_STATS:
		{
			struct kbase_uk_tlstream_stats *tlstream_stats = args;

			if (sizeof(*tlstream_stats) != args_size)
				goto bad_size;

			kbase_tlstream_stats(
					&tlstream_stats->bytes_collected,
					&tlstream_stats->bytes_generated);
			break;
		}
#endif /* MALI_UNIT_TEST */
#endif /* CONFIG_MALI_MIPE_ENABLED */

	case KBASE_FUNC_GET_CONTEXT_ID:
		{
			struct kbase_uk_context_id *info = args;

			info->id = kctx->id;
			break;
		}

	/* MALI_SEC_INTEGRATION */
#ifdef MALI_SEC_HWCNT
	case KBASE_FUNC_HWCNT_UTIL_SETUP:
	case KBASE_FUNC_HWCNT_GPR_DUMP:
	case KBASE_FUNC_VSYNC_SKIP:
#endif
	case KBASE_FUNC_TMU_SKIP:
	case KBASE_FUNC_CREATE_SURFACE:
	case KBASE_FUNC_DESTROY_SURFACE:
	case KBASE_FUNC_SET_MIN_LOCK :
	case KBASE_FUNC_UNSET_MIN_LOCK :
	case KBASE_FUNC_SECURE_WORLD_RENDERING :
	case KBASE_FUNC_NON_SECURE_WORLD_RENDERING :
		ukh->id = id;
		return gpu_vendor_dispatch(kctx, args, args_size);

	default:
		dev_err(kbdev->dev, "unknown ioctl %u", id);
		goto out_bad;
	}

	return 0;

 bad_size:
	dev_err(kbdev->dev, "Wrong syscall size (%d) for %08x\n", args_size, id);
 out_bad:
	return -EINVAL;
}

static struct kbase_device *to_kbase_device(struct device *dev)
{
	return dev_get_drvdata(dev);
}

/*
 * API to acquire device list mutex and
 * return pointer to the device list head
 */
const struct list_head *kbase_dev_list_get(void)
{
	mutex_lock(&kbase_dev_list_lock);
	return &kbase_dev_list;
}
KBASE_EXPORT_TEST_API(kbase_dev_list_get);

/* API to release the device list mutex */
void kbase_dev_list_put(const struct list_head *dev_list)
{
	mutex_unlock(&kbase_dev_list_lock);
}
KBASE_EXPORT_TEST_API(kbase_dev_list_put);

/* Find a particular kbase device (as specified by minor number), or find the "first" device if -1 is specified */
struct kbase_device *kbase_find_device(int minor)
{
	struct kbase_device *kbdev = NULL;
	struct list_head *entry;
	const struct list_head *dev_list = kbase_dev_list_get();

	list_for_each(entry, dev_list) {
		struct kbase_device *tmp;

		tmp = list_entry(entry, struct kbase_device, entry);
		if (tmp->mdev.minor == minor || minor == -1) {
			kbdev = tmp;
			get_device(kbdev->dev);
			break;
		}
	}
	kbase_dev_list_put(dev_list);

	return kbdev;
}
EXPORT_SYMBOL(kbase_find_device);

void kbase_release_device(struct kbase_device *kbdev)
{
	put_device(kbdev->dev);
}
EXPORT_SYMBOL(kbase_release_device);

static int kbase_open(struct inode *inode, struct file *filp)
{
	struct kbase_device *kbdev = NULL;
	struct kbase_context *kctx;
	int ret = 0;
#ifdef CONFIG_DEBUG_FS
	char kctx_name[64];
#endif

	kbdev = kbase_find_device(iminor(inode));

	if (!kbdev)
		return -ENODEV;

	kctx = kbase_create_context(kbdev, is_compat_task());
	if (!kctx) {
		ret = -ENOMEM;
		goto out;
	}

	init_waitqueue_head(&kctx->event_queue);
	filp->private_data = kctx;

	kctx->infinite_cache_active = kbdev->infinite_cache_active_default;

#ifdef CONFIG_DEBUG_FS
	snprintf(kctx_name, 64, "%d_%d", kctx->tgid, kctx->id);

	kctx->kctx_dentry = debugfs_create_dir(kctx_name,
			kbdev->debugfs_ctx_directory);

	if (IS_ERR_OR_NULL(kctx->kctx_dentry)) {
		ret = -ENOMEM;
		goto out;
	}

#ifdef CONFIG_MALI_COH_USER
	 /* if cache is completely coherent at hardware level, then remove the
	  * infinite cache control support from debugfs.
	  */
#else
	debugfs_create_bool("infinite_cache", 0644, kctx->kctx_dentry,
			&kctx->infinite_cache_active);
#endif /* CONFIG_MALI_COH_USER */
	kbasep_mem_profile_debugfs_add(kctx);

	kbasep_jd_debugfs_ctx_add(kctx);
	kbase_debug_mem_view_init(filp);

	kbase_debug_job_fault_context_init(kctx);

	kbase_mem_pool_debugfs_add(kctx->kctx_dentry, &kctx->mem_pool);

#endif /* CONFIG_DEBUGFS */

	dev_dbg(kbdev->dev, "created base context\n");

	{
		struct kbasep_kctx_list_element *element;

		element = kzalloc(sizeof(*element), GFP_KERNEL);
		if (element) {
			mutex_lock(&kbdev->kctx_list_lock);
			element->kctx = kctx;
			list_add(&element->link, &kbdev->kctx_list);
#ifdef CONFIG_MALI_MIPE_ENABLED
			kbase_tlstream_tl_new_ctx(
					element->kctx,
					(u32)(element->kctx->id));
#endif
			mutex_unlock(&kbdev->kctx_list_lock);
		} else {
			/* we don't treat this as a fail - just warn about it */
			dev_warn(kbdev->dev, "couldn't add kctx to kctx_list\n");
		}
	}
	return 0;

 out:
	kbase_release_device(kbdev);
	return ret;
}

static int kbase_release(struct inode *inode, struct file *filp)
{
	struct kbase_context *kctx = filp->private_data;
	struct kbase_device *kbdev = kctx->kbdev;
	struct kbasep_kctx_list_element *element, *tmp;
	bool found_element = false;

#ifdef CONFIG_MALI_MIPE_ENABLED
	kbase_tlstream_tl_del_ctx(kctx);
#endif

#ifdef CONFIG_DEBUG_FS
	debugfs_remove_recursive(kctx->kctx_dentry);
	kbasep_mem_profile_debugfs_remove(kctx);
	kbase_debug_job_fault_context_exit(kctx);
#endif

	mutex_lock(&kbdev->kctx_list_lock);
	list_for_each_entry_safe(element, tmp, &kbdev->kctx_list, link) {
		if (element->kctx == kctx) {
			list_del(&element->link);
			kfree(element);
			found_element = true;
		}
	}
	mutex_unlock(&kbdev->kctx_list_lock);
	if (!found_element)
		dev_warn(kbdev->dev, "kctx not in kctx_list\n");

	filp->private_data = NULL;

	mutex_lock(&kctx->vinstr_cli_lock);
	/* If this client was performing hwcnt dumping and did not explicitly
	 * detach itself, remove it from the vinstr core now */
	if (kctx->vinstr_cli) {
		struct kbase_uk_hwcnt_setup setup;

		setup.dump_buffer = 0llu;
		kbase_vinstr_legacy_hwc_setup(
				kbdev->vinstr_ctx, &kctx->vinstr_cli, &setup);
	}
	mutex_unlock(&kctx->vinstr_cli_lock);

	kbase_destroy_context(kctx);

	dev_dbg(kbdev->dev, "deleted base context\n");
	kbase_release_device(kbdev);
	return 0;
}

/* MALI_SEC_INTEGRATION */
//#define CALL_MAX_SIZE 536
#define CALL_MAX_SIZE	(KBASE_FUNC_MAX - 1)

static long kbase_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	u64 msg[(CALL_MAX_SIZE + 7) >> 3] = { 0xdeadbeefdeadbeefull };	/* alignment fixup */
	u32 size = _IOC_SIZE(cmd);
	struct kbase_context *kctx = filp->private_data;

	if (size > CALL_MAX_SIZE)
		return -ENOTTY;

	if (0 != copy_from_user(&msg, (void __user *)arg, size)) {
		dev_err(kctx->kbdev->dev, "failed to copy ioctl argument into kernel space\n");
		return -EFAULT;
	}

	if (kbase_dispatch(kctx, &msg, size) != 0)
		return -EFAULT;

	if (0 != copy_to_user((void __user *)arg, &msg, size)) {
		dev_err(kctx->kbdev->dev, "failed to copy results of UK call back to user space\n");
		return -EFAULT;
	}
	return 0;
}

static ssize_t kbase_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	struct kbase_context *kctx = filp->private_data;
	struct base_jd_event_v2 uevent;
	int out_count = 0;

	if (count < sizeof(uevent))
		return -ENOBUFS;

	do {
		while (kbase_event_dequeue(kctx, &uevent)) {
			if (out_count > 0)
				goto out;

			if (filp->f_flags & O_NONBLOCK)
				return -EAGAIN;

			if (wait_event_interruptible(kctx->event_queue,
					kbase_event_pending(kctx)) != 0)
				return -ERESTARTSYS;
		}
		if (uevent.event_code == BASE_JD_EVENT_DRV_TERMINATED) {
			if (out_count == 0)
				return -EPIPE;
			goto out;
		}

		if (copy_to_user(buf, &uevent, sizeof(uevent)) != 0)
			return -EFAULT;

		buf += sizeof(uevent);
		out_count++;
		count -= sizeof(uevent);
	} while (count >= sizeof(uevent));

 out:
	return out_count * sizeof(uevent);
}

static unsigned int kbase_poll(struct file *filp, poll_table *wait)
{
	struct kbase_context *kctx = filp->private_data;

	poll_wait(filp, &kctx->event_queue, wait);
	if (kbase_event_pending(kctx))
		return POLLIN | POLLRDNORM;

	return 0;
}

void kbase_event_wakeup(struct kbase_context *kctx)
{
	KBASE_DEBUG_ASSERT(kctx);

	wake_up_interruptible(&kctx->event_queue);
}

KBASE_EXPORT_TEST_API(kbase_event_wakeup);

static int kbase_check_flags(int flags)
{
	/* Enforce that the driver keeps the O_CLOEXEC flag so that execve() always
	 * closes the file descriptor in a child process.
	 */
	if (0 == (flags & O_CLOEXEC))
		return -EINVAL;

	return 0;
}

static unsigned long kbase_get_unmapped_area(struct file *filp,
		const unsigned long addr, const unsigned long len,
		const unsigned long pgoff, const unsigned long flags)
{
#ifdef CONFIG_64BIT
	/* based on get_unmapped_area, but simplified slightly due to that some
	 * values are known in advance */
	struct kbase_context *kctx = filp->private_data;

	if (!kctx->is_compat && !addr &&
		kbase_hw_has_feature(kctx->kbdev, BASE_HW_FEATURE_33BIT_VA)) {
		struct mm_struct *mm = current->mm;
		struct vm_area_struct *vma;
		unsigned long low_limit, high_limit, gap_start, gap_end;

		/* Hardware has smaller VA than userspace, ensure the page
		 * comes from a VA which can be used on the GPU */

		gap_end = (1UL<<33);
		if (gap_end < len)
			return -ENOMEM;
		high_limit = gap_end - len;
		low_limit = PAGE_SIZE + len;

		gap_start = mm->highest_vm_end;
		if (gap_start <= high_limit)
			goto found_highest;

		if (RB_EMPTY_ROOT(&mm->mm_rb))
			return -ENOMEM;
		vma = rb_entry(mm->mm_rb.rb_node, struct vm_area_struct, vm_rb);
		if (vma->rb_subtree_gap < len)
			return -ENOMEM;

		while (true) {
			gap_start = vma->vm_prev ? vma->vm_prev->vm_end : 0;
			if (gap_start <= high_limit && vma->vm_rb.rb_right) {
				struct vm_area_struct *right =
					rb_entry(vma->vm_rb.rb_right,
						 struct vm_area_struct, vm_rb);
				if (right->rb_subtree_gap >= len) {
					vma = right;
					continue;
				}
			}
check_current:
			gap_end = vma->vm_start;
			if (gap_end < low_limit)
				return -ENOMEM;
			if (gap_start <= high_limit &&
			    gap_end - gap_start >= len)
				goto found;

			if (vma->vm_rb.rb_left) {
				struct vm_area_struct *left =
					rb_entry(vma->vm_rb.rb_left,
						 struct vm_area_struct, vm_rb);

				if (left->rb_subtree_gap >= len) {
					vma = left;
					continue;
				}
			}
			while (true) {
				struct rb_node *prev = &vma->vm_rb;

				if (!rb_parent(prev))
					return -ENOMEM;
				vma = rb_entry(rb_parent(prev),
						struct vm_area_struct, vm_rb);
				if (prev == vma->vm_rb.rb_right) {
					gap_start = vma->vm_prev ?
						vma->vm_prev->vm_end : 0;
					goto check_current;
				}
			}
		}

found:
		if (gap_end > (1UL<<33))
			gap_end = (1UL<<33);

found_highest:
		gap_end -= len;

		VM_BUG_ON(gap_end < PAGE_SIZE);
		VM_BUG_ON(gap_end < gap_start);
		return gap_end;
	}
#endif
	/* No special requirements - fallback to the default version */
	return current->mm->get_unmapped_area(filp, addr, len, pgoff, flags);
}

static const struct file_operations kbase_fops = {
	.owner = THIS_MODULE,
	.open = kbase_open,
	.release = kbase_release,
	.read = kbase_read,
	.poll = kbase_poll,
	.unlocked_ioctl = kbase_ioctl,
	.compat_ioctl = kbase_ioctl,
	.mmap = kbase_mmap,
	.check_flags = kbase_check_flags,
	.get_unmapped_area = kbase_get_unmapped_area,
};

#ifndef CONFIG_MALI_NO_MALI
void kbase_os_reg_write(struct kbase_device *kbdev, u16 offset, u32 value)
{
	writel(value, kbdev->reg + offset);
}

u32 kbase_os_reg_read(struct kbase_device *kbdev, u16 offset)
{
	return readl(kbdev->reg + offset);
}
#endif /* !CONFIG_MALI_NO_MALI */


/** Show callback for the @c power_policy sysfs file.
 *
 * This function is called to get the contents of the @c power_policy sysfs
 * file. This is a list of the available policies with the currently active one
 * surrounded by square brackets.
 *
 * @param dev	The device this sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The output buffer for the sysfs file contents
 *
 * @return The number of bytes output to @c buf.
 */
static ssize_t show_policy(struct device *dev, struct device_attribute *attr, char *const buf)
{
	struct kbase_device *kbdev;
	const struct kbase_pm_policy *current_policy;
	const struct kbase_pm_policy *const *policy_list;
	int policy_count;
	int i;
	ssize_t ret = 0;

	kbdev = to_kbase_device(dev);

	if (!kbdev)
		return -ENODEV;

	current_policy = kbase_pm_get_policy(kbdev);

	policy_count = kbase_pm_list_policies(&policy_list);

	for (i = 0; i < policy_count && ret < PAGE_SIZE; i++) {
		if (policy_list[i] == current_policy)
			ret += scnprintf(buf + ret, PAGE_SIZE - ret, "[%s] ", policy_list[i]->name);
		else
			ret += scnprintf(buf + ret, PAGE_SIZE - ret, "%s ", policy_list[i]->name);
	}

	if (ret < PAGE_SIZE - 1) {
		ret += scnprintf(buf + ret, PAGE_SIZE - ret, "\n");
	} else {
		buf[PAGE_SIZE - 2] = '\n';
		buf[PAGE_SIZE - 1] = '\0';
		ret = PAGE_SIZE - 1;
	}

	return ret;
}

/** Store callback for the @c power_policy sysfs file.
 *
 * This function is called when the @c power_policy sysfs file is written to.
 * It matches the requested policy against the available policies and if a
 * matching policy is found calls @ref kbase_pm_set_policy to change the
 * policy.
 *
 * @param dev	The device with sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The value written to the sysfs file
 * @param count	The number of bytes written to the sysfs file
 *
 * @return @c count if the function succeeded. An error code on failure.
 */
static ssize_t set_policy(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	const struct kbase_pm_policy *new_policy = NULL;
	const struct kbase_pm_policy *const *policy_list;
	int policy_count;
	int i;

	kbdev = to_kbase_device(dev);

	if (!kbdev)
		return -ENODEV;

	policy_count = kbase_pm_list_policies(&policy_list);

	for (i = 0; i < policy_count; i++) {
		if (sysfs_streq(policy_list[i]->name, buf)) {
			new_policy = policy_list[i];
			break;
		}
	}

	if (!new_policy) {
		dev_err(dev, "power_policy: policy not found\n");
		return -EINVAL;
	}

	kbase_pm_set_policy(kbdev, new_policy);

	return count;
}

/** The sysfs file @c power_policy.
 *
 * This is used for obtaining information about the available policies,
 * determining which policy is currently active, and changing the active
 * policy.
 */
static DEVICE_ATTR(power_policy, S_IRUGO | S_IWUSR, show_policy, set_policy);

/** Show callback for the @c core_availability_policy sysfs file.
 *
 * This function is called to get the contents of the @c core_availability_policy
 * sysfs file. This is a list of the available policies with the currently
 * active one surrounded by square brackets.
 *
 * @param dev	The device this sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The output buffer for the sysfs file contents
 *
 * @return The number of bytes output to @c buf.
 */
static ssize_t show_ca_policy(struct device *dev, struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	const struct kbase_pm_ca_policy *current_policy;
	const struct kbase_pm_ca_policy *const *policy_list;
	int policy_count;
	int i;
	ssize_t ret = 0;

	kbdev = to_kbase_device(dev);

	if (!kbdev)
		return -ENODEV;

	current_policy = kbase_pm_ca_get_policy(kbdev);

	policy_count = kbase_pm_ca_list_policies(&policy_list);

	for (i = 0; i < policy_count && ret < PAGE_SIZE; i++) {
		if (policy_list[i] == current_policy)
			ret += scnprintf(buf + ret, PAGE_SIZE - ret, "[%s] ", policy_list[i]->name);
		else
			ret += scnprintf(buf + ret, PAGE_SIZE - ret, "%s ", policy_list[i]->name);
	}

	if (ret < PAGE_SIZE - 1) {
		ret += scnprintf(buf + ret, PAGE_SIZE - ret, "\n");
	} else {
		buf[PAGE_SIZE - 2] = '\n';
		buf[PAGE_SIZE - 1] = '\0';
		ret = PAGE_SIZE - 1;
	}

	return ret;
}

/** Store callback for the @c core_availability_policy sysfs file.
 *
 * This function is called when the @c core_availability_policy sysfs file is
 * written to. It matches the requested policy against the available policies
 * and if a matching policy is found calls @ref kbase_pm_set_policy to change
 * the policy.
 *
 * @param dev	The device with sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The value written to the sysfs file
 * @param count	The number of bytes written to the sysfs file
 *
 * @return @c count if the function succeeded. An error code on failure.
 */
static ssize_t set_ca_policy(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	const struct kbase_pm_ca_policy *new_policy = NULL;
	const struct kbase_pm_ca_policy *const *policy_list;
	int policy_count;
	int i;

	kbdev = to_kbase_device(dev);

	if (!kbdev)
		return -ENODEV;

	policy_count = kbase_pm_ca_list_policies(&policy_list);

	for (i = 0; i < policy_count; i++) {
		if (sysfs_streq(policy_list[i]->name, buf)) {
			new_policy = policy_list[i];
			break;
		}
	}

	if (!new_policy) {
		dev_err(dev, "core_availability_policy: policy not found\n");
		return -EINVAL;
	}

	kbase_pm_ca_set_policy(kbdev, new_policy);

	return count;
}

/** The sysfs file @c core_availability_policy
 *
 * This is used for obtaining information about the available policies,
 * determining which policy is currently active, and changing the active
 * policy.
 */
static DEVICE_ATTR(core_availability_policy, S_IRUGO | S_IWUSR, show_ca_policy, set_ca_policy);

/** Show callback for the @c core_mask sysfs file.
 *
 * This function is called to get the contents of the @c core_mask sysfs
 * file.
 *
 * @param dev	The device this sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The output buffer for the sysfs file contents
 *
 * @return The number of bytes output to @c buf.
 */
static ssize_t show_core_mask(struct device *dev, struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	ssize_t ret = 0;

	kbdev = to_kbase_device(dev);

	if (!kbdev)
		return -ENODEV;

	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "Current core mask : 0x%llX\n", kbdev->pm.debug_core_mask);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret,
			"Available core mask : 0x%llX\n",
			kbdev->gpu_props.props.raw_props.shader_present);

	return ret;
}

/** Store callback for the @c core_mask sysfs file.
 *
 * This function is called when the @c core_mask sysfs file is written to.
 *
 * @param dev	The device with sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The value written to the sysfs file
 * @param count	The number of bytes written to the sysfs file
 *
 * @return @c count if the function succeeded. An error code on failure.
 */
static ssize_t set_core_mask(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	u64 new_core_mask;
	int rc;

	kbdev = to_kbase_device(dev);

	if (!kbdev)
		return -ENODEV;

	rc = kstrtoull(buf, 16, &new_core_mask);
	if (rc)
		return rc;

	if ((new_core_mask & kbdev->gpu_props.props.raw_props.shader_present)
			!= new_core_mask ||
	    !(new_core_mask & kbdev->gpu_props.props.coherency_info.group[0].core_mask)) {
		dev_err(dev, "power_policy: invalid core specification\n");
		return -EINVAL;
	}

	if (kbdev->pm.debug_core_mask != new_core_mask) {
		unsigned long flags;

		spin_lock_irqsave(&kbdev->pm.power_change_lock, flags);

		kbase_pm_set_debug_core_mask(kbdev, new_core_mask);

		spin_unlock_irqrestore(&kbdev->pm.power_change_lock, flags);
	}

	return count;
}

/** The sysfs file @c core_mask.
 *
 * This is used to restrict shader core availability for debugging purposes.
 * Reading it will show the current core mask and the mask of cores available.
 * Writing to it will set the current core mask.
 */
static DEVICE_ATTR(core_mask, S_IRUGO | S_IWUSR, show_core_mask, set_core_mask);

#ifdef CONFIG_MALI_DEBUG_SHADER_SPLIT_FS
/**
 * struct sc_split_config
 * @tag: Short name
 * @human_readable: Long name
 * @js0_mask: Mask for job slot 0
 * @js1_mask: Mask for job slot 1
 * @js2_mask: Mask for job slot 2
 *
 * Structure containing a single shader affinity split configuration.
 */
struct sc_split_config {
	char const *tag;
	char const *human_readable;
	u64          js0_mask;
	u64          js1_mask;
	u64          js2_mask;
};

/*
 * Array of available shader affinity split configurations.
 */
static struct sc_split_config const sc_split_configs[] = {
	/* All must be the first config (default). */
	{
		"all", "All cores",
		0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
	},
	{
		"mp1", "MP1 shader core",
		0x1, 0x1, 0x1
	},
	{
		"mp2", "MP2 shader core",
		0x3, 0x3, 0x3
	},
	{
		"mp4", "MP4 shader core",
		0xF, 0xF, 0xF
	},
	{
		"mp1_vf", "MP1 vertex + MP1 fragment shader core",
		0x2, 0x1, 0xFFFFFFFFFFFFFFFFULL
	},
	{
		"mp2_vf", "MP2 vertex + MP2 fragment shader core",
		0xA, 0x5, 0xFFFFFFFFFFFFFFFFULL
	},
	/* This must be the last config. */
	{
		NULL, NULL,
		0x0, 0x0, 0x0
	},
};

/* Pointer to the currently active shader split configuration. */
static struct sc_split_config const *current_sc_split_config = &sc_split_configs[0];

/** Show callback for the @c sc_split sysfs file
 *
 * Returns the current shader core affinity policy.
 */
static ssize_t show_split(struct device *dev, struct device_attribute *attr, char * const buf)
{
	ssize_t ret;
	/* We know we are given a buffer which is PAGE_SIZE long. Our strings are all guaranteed
	 * to be shorter than that at this time so no length check needed. */
	ret = scnprintf(buf, PAGE_SIZE, "Current sc_split: '%s'\n", current_sc_split_config->tag);
	return ret;
}

/** Store callback for the @c sc_split sysfs file.
 *
 * This function is called when the @c sc_split sysfs file is written to
 * It modifies the system shader core affinity configuration to allow
 * system profiling with different hardware configurations.
 *
 * @param dev	The device with sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The value written to the sysfs file
 * @param count	The number of bytes written to the sysfs file
 *
 * @return @c count if the function succeeded. An error code on failure.
 */
static ssize_t set_split(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct sc_split_config const *config = &sc_split_configs[0];

	/* Try to match: loop until we hit the last "NULL" entry */
	while (config->tag) {
		if (sysfs_streq(config->tag, buf)) {
			current_sc_split_config = config;
			mali_js0_affinity_mask  = config->js0_mask;
			mali_js1_affinity_mask  = config->js1_mask;
			mali_js2_affinity_mask  = config->js2_mask;
			dev_dbg(dev, "Setting sc_split: '%s'\n", config->tag);
			return count;
		}
		config++;
	}

	/* No match found in config list */
	dev_err(dev, "sc_split: invalid value\n");
	dev_err(dev, "  Possible settings: mp[1|2|4], mp[1|2]_vf\n");
	return -ENOENT;
}

/** The sysfs file @c sc_split
 *
 * This is used for configuring/querying the current shader core work affinity
 * configuration.
 */
static DEVICE_ATTR(sc_split, S_IRUGO|S_IWUSR, show_split, set_split);
#endif /* CONFIG_MALI_DEBUG_SHADER_SPLIT_FS */


/** Store callback for the @c js_timeouts sysfs file.
 *
 * This function is called to get the contents of the @c js_timeouts sysfs
 * file. This file contains five values separated by whitespace. The values
 * are basically the same as JS_SOFT_STOP_TICKS, JS_HARD_STOP_TICKS_SS,
 * JS_HARD_STOP_TICKS_DUMPING, JS_RESET_TICKS_SS, JS_RESET_TICKS_DUMPING
 * configuration values (in that order), with the difference that the js_timeout
 * values are expressed in MILLISECONDS.
 *
 * The js_timeouts sysfile file allows the current values in
 * use by the job scheduler to get override. Note that a value needs to
 * be other than 0 for it to override the current job scheduler value.
 *
 * @param dev	The device with sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The value written to the sysfs file
 * @param count	The number of bytes written to the sysfs file
 *
 * @return @c count if the function succeeded. An error code on failure.
 */
static ssize_t set_js_timeouts(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	int items;
	long js_soft_stop_ms;
	long js_soft_stop_ms_cl;
	long js_hard_stop_ms_ss;
	long js_hard_stop_ms_cl;
	long js_hard_stop_ms_dumping;
	long js_reset_ms_ss;
	long js_reset_ms_cl;
	long js_reset_ms_dumping;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	items = sscanf(buf, "%ld %ld %ld %ld %ld %ld %ld %ld",
			&js_soft_stop_ms, &js_soft_stop_ms_cl,
			&js_hard_stop_ms_ss, &js_hard_stop_ms_cl,
			&js_hard_stop_ms_dumping, &js_reset_ms_ss,
			&js_reset_ms_cl, &js_reset_ms_dumping);

	if (items == 8) {
		u64 ticks;

		if (js_soft_stop_ms >= 0) {
			ticks = js_soft_stop_ms * 1000000ULL;
			do_div(ticks, kbdev->js_data.scheduling_period_ns);
			kbdev->js_soft_stop_ticks = ticks;
		} else {
			kbdev->js_soft_stop_ticks = -1;
		}

		if (js_soft_stop_ms_cl >= 0) {
			ticks = js_soft_stop_ms_cl * 1000000ULL;
			do_div(ticks, kbdev->js_data.scheduling_period_ns);
			kbdev->js_soft_stop_ticks_cl = ticks;
		} else {
			kbdev->js_soft_stop_ticks_cl = -1;
		}

		if (js_hard_stop_ms_ss >= 0) {
			ticks = js_hard_stop_ms_ss * 1000000ULL;
			do_div(ticks, kbdev->js_data.scheduling_period_ns);
			kbdev->js_hard_stop_ticks_ss = ticks;
		} else {
			kbdev->js_hard_stop_ticks_ss = -1;
		}

		if (js_hard_stop_ms_cl >= 0) {
			ticks = js_hard_stop_ms_cl * 1000000ULL;
			do_div(ticks, kbdev->js_data.scheduling_period_ns);
			kbdev->js_hard_stop_ticks_cl = ticks;
		} else {
			kbdev->js_hard_stop_ticks_cl = -1;
		}

		if (js_hard_stop_ms_dumping >= 0) {
			ticks = js_hard_stop_ms_dumping * 1000000ULL;
			do_div(ticks, kbdev->js_data.scheduling_period_ns);
			kbdev->js_hard_stop_ticks_dumping = ticks;
		} else {
			kbdev->js_hard_stop_ticks_dumping = -1;
		}

		if (js_reset_ms_ss >= 0) {
			ticks = js_reset_ms_ss * 1000000ULL;
			do_div(ticks, kbdev->js_data.scheduling_period_ns);
			kbdev->js_reset_ticks_ss = ticks;
		} else {
			kbdev->js_reset_ticks_ss = -1;
		}

		if (js_reset_ms_cl >= 0) {
			ticks = js_reset_ms_cl * 1000000ULL;
			do_div(ticks, kbdev->js_data.scheduling_period_ns);
			kbdev->js_reset_ticks_cl = ticks;
		} else {
			kbdev->js_reset_ticks_cl = -1;
		}

		if (js_reset_ms_dumping >= 0) {
			ticks = js_reset_ms_dumping * 1000000ULL;
			do_div(ticks, kbdev->js_data.scheduling_period_ns);
			kbdev->js_reset_ticks_dumping = ticks;
		} else {
			kbdev->js_reset_ticks_dumping = -1;
		}

		kbdev->js_timeouts_updated = true;

		dev_dbg(kbdev->dev, "Overriding JS_SOFT_STOP_TICKS with %lu ticks (%lu ms)\n",
				(unsigned long)kbdev->js_soft_stop_ticks,
				js_soft_stop_ms);
		dev_dbg(kbdev->dev, "Overriding JS_SOFT_STOP_TICKS_CL with %lu ticks (%lu ms)\n",
				(unsigned long)kbdev->js_soft_stop_ticks_cl,
				js_soft_stop_ms_cl);
		dev_dbg(kbdev->dev, "Overriding JS_HARD_STOP_TICKS_SS with %lu ticks (%lu ms)\n",
				(unsigned long)kbdev->js_hard_stop_ticks_ss,
				js_hard_stop_ms_ss);
		dev_dbg(kbdev->dev, "Overriding JS_HARD_STOP_TICKS_CL with %lu ticks (%lu ms)\n",
				(unsigned long)kbdev->js_hard_stop_ticks_cl,
				js_hard_stop_ms_cl);
		dev_dbg(kbdev->dev, "Overriding JS_HARD_STOP_TICKS_DUMPING with %lu ticks (%lu ms)\n",
				(unsigned long)
					kbdev->js_hard_stop_ticks_dumping,
				js_hard_stop_ms_dumping);
		dev_dbg(kbdev->dev, "Overriding JS_RESET_TICKS_SS with %lu ticks (%lu ms)\n",
				(unsigned long)kbdev->js_reset_ticks_ss,
				js_reset_ms_ss);
		dev_dbg(kbdev->dev, "Overriding JS_RESET_TICKS_CL with %lu ticks (%lu ms)\n",
				(unsigned long)kbdev->js_reset_ticks_cl,
				js_reset_ms_cl);
		dev_dbg(kbdev->dev, "Overriding JS_RESET_TICKS_DUMPING with %lu ticks (%lu ms)\n",
				(unsigned long)kbdev->js_reset_ticks_dumping,
				js_reset_ms_dumping);

		return count;
	}

	dev_err(kbdev->dev, "Couldn't process js_timeouts write operation.\n"
			"Use format <soft_stop_ms> <soft_stop_ms_cl> <hard_stop_ms_ss> <hard_stop_ms_cl> <hard_stop_ms_dumping> <reset_ms_ss> <reset_ms_cl> <reset_ms_dumping>\n"
			"Write 0 for no change, -1 to restore default timeout\n");
	return -EINVAL;
}

/** Show callback for the @c js_timeouts sysfs file.
 *
 * This function is called to get the contents of the @c js_timeouts sysfs
 * file. It returns the last set values written to the js_timeouts sysfs file.
 * If the file didn't get written yet, the values will be current setting in
 * use.
 * @param dev	The device this sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The output buffer for the sysfs file contents
 *
 * @return The number of bytes output to @c buf.
 */
static ssize_t show_js_timeouts(struct device *dev, struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	ssize_t ret;
	u64 ms;
	unsigned long js_soft_stop_ms;
	unsigned long js_soft_stop_ms_cl;
	unsigned long js_hard_stop_ms_ss;
	unsigned long js_hard_stop_ms_cl;
	unsigned long js_hard_stop_ms_dumping;
	unsigned long js_reset_ms_ss;
	unsigned long js_reset_ms_cl;
	unsigned long js_reset_ms_dumping;
	unsigned long ticks;
	u32 scheduling_period_ns;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	/* If no contexts have been scheduled since js_timeouts was last written
	 * to, the new timeouts might not have been latched yet. So check if an
	 * update is pending and use the new values if necessary. */
	if (kbdev->js_timeouts_updated && kbdev->js_scheduling_period_ns > 0)
		scheduling_period_ns = kbdev->js_scheduling_period_ns;
	else
		scheduling_period_ns = kbdev->js_data.scheduling_period_ns;

	if (kbdev->js_timeouts_updated && kbdev->js_soft_stop_ticks > 0)
		ticks = kbdev->js_soft_stop_ticks;
	else
		ticks = kbdev->js_data.soft_stop_ticks;
	ms = (u64)ticks * scheduling_period_ns;
	do_div(ms, 1000000UL);
	js_soft_stop_ms = (unsigned long)ms;

	if (kbdev->js_timeouts_updated && kbdev->js_soft_stop_ticks_cl > 0)
		ticks = kbdev->js_soft_stop_ticks_cl;
	else
		ticks = kbdev->js_data.soft_stop_ticks_cl;
	ms = (u64)ticks * scheduling_period_ns;
	do_div(ms, 1000000UL);
	js_soft_stop_ms_cl = (unsigned long)ms;

	if (kbdev->js_timeouts_updated && kbdev->js_hard_stop_ticks_ss > 0)
		ticks = kbdev->js_hard_stop_ticks_ss;
	else
		ticks = kbdev->js_data.hard_stop_ticks_ss;
	ms = (u64)ticks * scheduling_period_ns;
	do_div(ms, 1000000UL);
	js_hard_stop_ms_ss = (unsigned long)ms;

	if (kbdev->js_timeouts_updated && kbdev->js_hard_stop_ticks_cl > 0)
		ticks = kbdev->js_hard_stop_ticks_cl;
	else
		ticks = kbdev->js_data.hard_stop_ticks_cl;
	ms = (u64)ticks * scheduling_period_ns;
	do_div(ms, 1000000UL);
	js_hard_stop_ms_cl = (unsigned long)ms;

	if (kbdev->js_timeouts_updated && kbdev->js_hard_stop_ticks_dumping > 0)
		ticks = kbdev->js_hard_stop_ticks_dumping;
	else
		ticks = kbdev->js_data.hard_stop_ticks_dumping;
	ms = (u64)ticks * scheduling_period_ns;
	do_div(ms, 1000000UL);
	js_hard_stop_ms_dumping = (unsigned long)ms;

	if (kbdev->js_timeouts_updated && kbdev->js_reset_ticks_ss > 0)
		ticks = kbdev->js_reset_ticks_ss;
	else
		ticks = kbdev->js_data.gpu_reset_ticks_ss;
	ms = (u64)ticks * scheduling_period_ns;
	do_div(ms, 1000000UL);
	js_reset_ms_ss = (unsigned long)ms;

	if (kbdev->js_timeouts_updated && kbdev->js_reset_ticks_cl > 0)
		ticks = kbdev->js_reset_ticks_cl;
	else
		ticks = kbdev->js_data.gpu_reset_ticks_cl;
	ms = (u64)ticks * scheduling_period_ns;
	do_div(ms, 1000000UL);
	js_reset_ms_cl = (unsigned long)ms;

	if (kbdev->js_timeouts_updated && kbdev->js_reset_ticks_dumping > 0)
		ticks = kbdev->js_reset_ticks_dumping;
	else
		ticks = kbdev->js_data.gpu_reset_ticks_dumping;
	ms = (u64)ticks * scheduling_period_ns;
	do_div(ms, 1000000UL);
	js_reset_ms_dumping = (unsigned long)ms;

	ret = scnprintf(buf, PAGE_SIZE, "%lu %lu %lu %lu %lu %lu %lu %lu\n",
			js_soft_stop_ms, js_soft_stop_ms_cl,
			js_hard_stop_ms_ss, js_hard_stop_ms_cl,
			js_hard_stop_ms_dumping, js_reset_ms_ss,
			js_reset_ms_cl, js_reset_ms_dumping);

	if (ret >= PAGE_SIZE) {
		buf[PAGE_SIZE - 2] = '\n';
		buf[PAGE_SIZE - 1] = '\0';
		ret = PAGE_SIZE - 1;
	}

	return ret;
}

/** The sysfs file @c js_timeouts.
 *
 * This is used to override the current job scheduler values for
 * JS_STOP_STOP_TICKS_SS
 * JS_STOP_STOP_TICKS_CL
 * JS_HARD_STOP_TICKS_SS
 * JS_HARD_STOP_TICKS_CL
 * JS_HARD_STOP_TICKS_DUMPING
 * JS_RESET_TICKS_SS
 * JS_RESET_TICKS_CL
 * JS_RESET_TICKS_DUMPING.
 */
static DEVICE_ATTR(js_timeouts, S_IRUGO | S_IWUSR, show_js_timeouts, set_js_timeouts);

/**
 * set_js_scheduling_period - Store callback for the js_scheduling_period sysfs
 *                            file
 * @dev:   The device the sysfs file is for
 * @attr:  The attributes of the sysfs file
 * @buf:   The value written to the sysfs file
 * @count: The number of bytes written to the sysfs file
 *
 * This function is called when the js_scheduling_period sysfs file is written
 * to. It checks the data written, and if valid updates the js_scheduling_period
 * value
 *
 * Return: @c count if the function succeeded. An error code on failure.
 */
static ssize_t set_js_scheduling_period(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	int ret;
	unsigned int js_scheduling_period;
	u32 new_scheduling_period_ns;
	u32 old_period;
	u64 ticks;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	ret = kstrtouint(buf, 0, &js_scheduling_period);
	if (ret || !js_scheduling_period) {
		dev_err(kbdev->dev, "Couldn't process js_scheduling_period write operation.\n"
				"Use format <js_scheduling_period_ms>\n");
		return -EINVAL;
	}

	new_scheduling_period_ns = js_scheduling_period * 1000000;

	/* Update scheduling timeouts */
	mutex_lock(&kbdev->js_data.runpool_mutex);

	/* If no contexts have been scheduled since js_timeouts was last written
	 * to, the new timeouts might not have been latched yet. So check if an
	 * update is pending and use the new values if necessary. */

	/* Use previous 'new' scheduling period as a base if present. */
	if (kbdev->js_timeouts_updated && kbdev->js_scheduling_period_ns)
		old_period = kbdev->js_scheduling_period_ns;
	else
		old_period = kbdev->js_data.scheduling_period_ns;

	if (kbdev->js_timeouts_updated && kbdev->js_soft_stop_ticks > 0)
		ticks = (u64)kbdev->js_soft_stop_ticks * old_period;
	else
		ticks = (u64)kbdev->js_data.soft_stop_ticks *
				kbdev->js_data.scheduling_period_ns;
	do_div(ticks, new_scheduling_period_ns);
	kbdev->js_soft_stop_ticks = ticks ? ticks : 1;

	if (kbdev->js_timeouts_updated && kbdev->js_soft_stop_ticks_cl > 0)
		ticks = (u64)kbdev->js_soft_stop_ticks_cl * old_period;
	else
		ticks = (u64)kbdev->js_data.soft_stop_ticks_cl *
				kbdev->js_data.scheduling_period_ns;
	do_div(ticks, new_scheduling_period_ns);
	kbdev->js_soft_stop_ticks_cl = ticks ? ticks : 1;

	if (kbdev->js_timeouts_updated && kbdev->js_hard_stop_ticks_ss > 0)
		ticks = (u64)kbdev->js_hard_stop_ticks_ss * old_period;
	else
		ticks = (u64)kbdev->js_data.hard_stop_ticks_ss *
				kbdev->js_data.scheduling_period_ns;
	do_div(ticks, new_scheduling_period_ns);
	kbdev->js_hard_stop_ticks_ss = ticks ? ticks : 1;

	if (kbdev->js_timeouts_updated && kbdev->js_hard_stop_ticks_cl > 0)
		ticks = (u64)kbdev->js_hard_stop_ticks_cl * old_period;
	else
		ticks = (u64)kbdev->js_data.hard_stop_ticks_cl *
				kbdev->js_data.scheduling_period_ns;
	do_div(ticks, new_scheduling_period_ns);
	kbdev->js_hard_stop_ticks_cl = ticks ? ticks : 1;

	if (kbdev->js_timeouts_updated && kbdev->js_hard_stop_ticks_dumping > 0)
		ticks = (u64)kbdev->js_hard_stop_ticks_dumping * old_period;
	else
		ticks = (u64)kbdev->js_data.hard_stop_ticks_dumping *
				kbdev->js_data.scheduling_period_ns;
	do_div(ticks, new_scheduling_period_ns);
	kbdev->js_hard_stop_ticks_dumping = ticks ? ticks : 1;

	if (kbdev->js_timeouts_updated && kbdev->js_reset_ticks_ss > 0)
		ticks = (u64)kbdev->js_reset_ticks_ss * old_period;
	else
		ticks = (u64)kbdev->js_data.gpu_reset_ticks_ss *
				kbdev->js_data.scheduling_period_ns;
	do_div(ticks, new_scheduling_period_ns);
	kbdev->js_reset_ticks_ss = ticks ? ticks : 1;

	if (kbdev->js_timeouts_updated && kbdev->js_reset_ticks_cl > 0)
		ticks = (u64)kbdev->js_reset_ticks_cl * old_period;
	else
		ticks = (u64)kbdev->js_data.gpu_reset_ticks_cl *
				kbdev->js_data.scheduling_period_ns;
	do_div(ticks, new_scheduling_period_ns);
	kbdev->js_reset_ticks_cl = ticks ? ticks : 1;

	if (kbdev->js_timeouts_updated && kbdev->js_reset_ticks_dumping > 0)
		ticks = (u64)kbdev->js_reset_ticks_dumping * old_period;
	else
		ticks = (u64)kbdev->js_data.gpu_reset_ticks_dumping *
				kbdev->js_data.scheduling_period_ns;
	do_div(ticks, new_scheduling_period_ns);
	kbdev->js_reset_ticks_dumping = ticks ? ticks : 1;

	kbdev->js_scheduling_period_ns = new_scheduling_period_ns;
	kbdev->js_timeouts_updated = true;

	mutex_unlock(&kbdev->js_data.runpool_mutex);

	dev_dbg(kbdev->dev, "JS scheduling period: %dms\n",
			js_scheduling_period);

	return count;
}

/**
 * show_js_scheduling_period - Show callback for the js_scheduling_period sysfs
 *                             entry.
 * @dev:  The device this sysfs file is for.
 * @attr: The attributes of the sysfs file.
 * @buf:  The output buffer to receive the GPU information.
 *
 * This function is called to get the current period used for the JS scheduling
 * period.
 *
 * Return: The number of bytes output to buf.
 */
static ssize_t show_js_scheduling_period(struct device *dev,
		struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	u32 period;
	ssize_t ret;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	if (kbdev->js_timeouts_updated && kbdev->js_scheduling_period_ns > 0)
		period = kbdev->js_scheduling_period_ns;
	else
		period = kbdev->js_data.scheduling_period_ns;

	ret = scnprintf(buf, PAGE_SIZE, "%d\n",
			period / 1000000);

	return ret;
}

static DEVICE_ATTR(js_scheduling_period, S_IRUGO | S_IWUSR,
		show_js_scheduling_period, set_js_scheduling_period);

#if !MALI_CUSTOMER_RELEASE
/** Store callback for the @c force_replay sysfs file.
 *
 * @param dev	The device with sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The value written to the sysfs file
 * @param count	The number of bytes written to the sysfs file
 *
 * @return @c count if the function succeeded. An error code on failure.
 */
static ssize_t set_force_replay(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	if (!strncmp("limit=", buf, MIN(6, count))) {
		int force_replay_limit;
		int items = sscanf(buf, "limit=%u", &force_replay_limit);

		if (items == 1) {
			kbdev->force_replay_random = false;
			kbdev->force_replay_limit = force_replay_limit;
			kbdev->force_replay_count = 0;

			return count;
		}
	} else if (!strncmp("random_limit", buf, MIN(12, count))) {
		kbdev->force_replay_random = true;
		kbdev->force_replay_count = 0;

		return count;
	} else if (!strncmp("norandom_limit", buf, MIN(14, count))) {
		kbdev->force_replay_random = false;
		kbdev->force_replay_limit = KBASEP_FORCE_REPLAY_DISABLED;
		kbdev->force_replay_count = 0;

		return count;
	} else if (!strncmp("core_req=", buf, MIN(9, count))) {
		unsigned int core_req;
		int items = sscanf(buf, "core_req=%x", &core_req);

		if (items == 1) {
			kbdev->force_replay_core_req = (base_jd_core_req)core_req;

			return count;
		}
	}
	dev_err(kbdev->dev, "Couldn't process force_replay write operation.\nPossible settings: limit=<limit>, random_limit, norandom_limit, core_req=<core_req>\n");
	return -EINVAL;
}

/** Show callback for the @c force_replay sysfs file.
 *
 * This function is called to get the contents of the @c force_replay sysfs
 * file. It returns the last set value written to the force_replay sysfs file.
 * If the file didn't get written yet, the values will be 0.
 *
 * @param dev	The device this sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The output buffer for the sysfs file contents
 *
 * @return The number of bytes output to @c buf.
 */
static ssize_t show_force_replay(struct device *dev,
		struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	ssize_t ret;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	if (kbdev->force_replay_random)
		ret = scnprintf(buf, PAGE_SIZE,
				"limit=0\nrandom_limit\ncore_req=%x\n",
				kbdev->force_replay_core_req);
	else
		ret = scnprintf(buf, PAGE_SIZE,
				"limit=%u\nnorandom_limit\ncore_req=%x\n",
				kbdev->force_replay_limit,
				kbdev->force_replay_core_req);

	if (ret >= PAGE_SIZE) {
		buf[PAGE_SIZE - 2] = '\n';
		buf[PAGE_SIZE - 1] = '\0';
		ret = PAGE_SIZE - 1;
	}

	return ret;
}

/** The sysfs file @c force_replay.
 *
 */
static DEVICE_ATTR(force_replay, S_IRUGO | S_IWUSR, show_force_replay,
		set_force_replay);
#endif /* !MALI_CUSTOMER_RELEASE */

#ifdef CONFIG_MALI_DEBUG
static ssize_t set_js_softstop_always(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	int ret;
	int softstop_always;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	ret = kstrtoint(buf, 0, &softstop_always);
	if (ret || ((softstop_always != 0) && (softstop_always != 1))) {
		dev_err(kbdev->dev, "Couldn't process js_softstop_always write operation.\n"
				"Use format <soft_stop_always>\n");
		return -EINVAL;
	}

	kbdev->js_data.softstop_always = (bool) softstop_always;
	dev_dbg(kbdev->dev, "Support for softstop on a single context: %s\n",
			(kbdev->js_data.softstop_always) ?
			"Enabled" : "Disabled");
	return count;
}

static ssize_t show_js_softstop_always(struct device *dev,
		struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	ssize_t ret;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	ret = scnprintf(buf, PAGE_SIZE, "%d\n", kbdev->js_data.softstop_always);

	if (ret >= PAGE_SIZE) {
		buf[PAGE_SIZE - 2] = '\n';
		buf[PAGE_SIZE - 1] = '\0';
		ret = PAGE_SIZE - 1;
	}

	return ret;
}

/*
 * By default, soft-stops are disabled when only a single context is present. The ability to
 * enable soft-stop when only a single context is present can be used for debug and unit-testing purposes.
 * (see CL t6xx_stress_1 unit-test as an example whereby this feature is used.)
 */
static DEVICE_ATTR(js_softstop_always, S_IRUGO | S_IWUSR, show_js_softstop_always, set_js_softstop_always);
#endif /* CONFIG_MALI_DEBUG */

#ifdef CONFIG_MALI_DEBUG
typedef void (kbasep_debug_command_func) (struct kbase_device *);

enum kbasep_debug_command_code {
	KBASEP_DEBUG_COMMAND_DUMPTRACE,

	/* This must be the last enum */
	KBASEP_DEBUG_COMMAND_COUNT
};

struct kbasep_debug_command {
	char *str;
	kbasep_debug_command_func *func;
};

/** Debug commands supported by the driver */
static const struct kbasep_debug_command debug_commands[] = {
	{
	 .str = "dumptrace",
	 .func = &kbasep_trace_dump,
	 }
};

/** Show callback for the @c debug_command sysfs file.
 *
 * This function is called to get the contents of the @c debug_command sysfs
 * file. This is a list of the available debug commands, separated by newlines.
 *
 * @param dev	The device this sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The output buffer for the sysfs file contents
 *
 * @return The number of bytes output to @c buf.
 */
static ssize_t show_debug(struct device *dev, struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	int i;
	ssize_t ret = 0;

	kbdev = to_kbase_device(dev);

	if (!kbdev)
		return -ENODEV;

	for (i = 0; i < KBASEP_DEBUG_COMMAND_COUNT && ret < PAGE_SIZE; i++)
		ret += scnprintf(buf + ret, PAGE_SIZE - ret, "%s\n", debug_commands[i].str);

	if (ret >= PAGE_SIZE) {
		buf[PAGE_SIZE - 2] = '\n';
		buf[PAGE_SIZE - 1] = '\0';
		ret = PAGE_SIZE - 1;
	}

	return ret;
}

/** Store callback for the @c debug_command sysfs file.
 *
 * This function is called when the @c debug_command sysfs file is written to.
 * It matches the requested command against the available commands, and if
 * a matching command is found calls the associated function from
 * @ref debug_commands to issue the command.
 *
 * @param dev	The device with sysfs file is for
 * @param attr	The attributes of the sysfs file
 * @param buf	The value written to the sysfs file
 * @param count	The number of bytes written to the sysfs file
 *
 * @return @c count if the function succeeded. An error code on failure.
 */
static ssize_t issue_debug(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	int i;

	kbdev = to_kbase_device(dev);

	if (!kbdev)
		return -ENODEV;

	for (i = 0; i < KBASEP_DEBUG_COMMAND_COUNT; i++) {
		if (sysfs_streq(debug_commands[i].str, buf)) {
			debug_commands[i].func(kbdev);
			return count;
		}
	}

	/* Debug Command not found */
	dev_err(dev, "debug_command: command not known\n");
	return -EINVAL;
}

/** The sysfs file @c debug_command.
 *
 * This is used to issue general debug commands to the device driver.
 * Reading it will produce a list of debug commands, separated by newlines.
 * Writing to it with one of those commands will issue said command.
 */
static DEVICE_ATTR(debug_command, S_IRUGO | S_IWUSR, show_debug, issue_debug);
#endif /* CONFIG_MALI_DEBUG */

/**
 * kbase_show_gpuinfo - Show callback for the gpuinfo sysfs entry.
 * @dev: The device this sysfs file is for.
 * @attr: The attributes of the sysfs file.
 * @buf: The output buffer to receive the GPU information.
 *
 * This function is called to get a description of the present Mali
 * GPU via the gpuinfo sysfs entry.  This includes the GPU family, the
 * number of cores, the hardware version and the raw product id.  For
 * example:
 *
 *    Mali-T60x MP4 r0p0 0x6956
 *
 * Return: The number of bytes output to buf.
 */
static ssize_t kbase_show_gpuinfo(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	static const struct gpu_product_id_name {
		unsigned id;
		char *name;
	} gpu_product_id_names[] = {
		{ .id = GPU_ID_PI_T60X, .name = "Mali-T60x" },
		{ .id = GPU_ID_PI_T62X, .name = "Mali-T62x" },
		{ .id = GPU_ID_PI_T72X, .name = "Mali-T72x" },
		{ .id = GPU_ID_PI_T76X, .name = "Mali-T76x" },
		{ .id = GPU_ID_PI_T82X, .name = "Mali-T82x" },
		{ .id = GPU_ID_PI_T83X, .name = "Mali-T83x" },
		{ .id = GPU_ID_PI_T86X, .name = "Mali-T86x" },
		{ .id = GPU_ID_PI_TFRX, .name = "Mali-T88x" },
	};
	const char *product_name = "(Unknown Mali GPU)";
	struct kbase_device *kbdev;
	u32 gpu_id;
	unsigned product_id;
	unsigned i;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	gpu_id = kbdev->gpu_props.props.raw_props.gpu_id;
	product_id = gpu_id >> GPU_ID_VERSION_PRODUCT_ID_SHIFT;

	for (i = 0; i < ARRAY_SIZE(gpu_product_id_names); ++i) {
		if (gpu_product_id_names[i].id == product_id) {
			product_name = gpu_product_id_names[i].name;
			break;
		}
	}

	return scnprintf(buf, PAGE_SIZE, "%s MP%d r%dp%d 0x%04X\n",
		product_name, kbdev->gpu_props.num_cores,
		(gpu_id & GPU_ID_VERSION_MAJOR) >> GPU_ID_VERSION_MAJOR_SHIFT,
		(gpu_id & GPU_ID_VERSION_MINOR) >> GPU_ID_VERSION_MINOR_SHIFT,
		product_id);
}
static DEVICE_ATTR(gpuinfo, S_IRUGO, kbase_show_gpuinfo, NULL);

/**
 * set_dvfs_period - Store callback for the dvfs_period sysfs file.
 * @dev:   The device with sysfs file is for
 * @attr:  The attributes of the sysfs file
 * @buf:   The value written to the sysfs file
 * @count: The number of bytes written to the sysfs file
 *
 * This function is called when the dvfs_period sysfs file is written to. It
 * checks the data written, and if valid updates the DVFS period variable,
 *
 * Return: @c count if the function succeeded. An error code on failure.
 */
static ssize_t set_dvfs_period(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	int ret;
	int dvfs_period;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	ret = kstrtoint(buf, 0, &dvfs_period);
	if (ret || dvfs_period <= 0) {
		dev_err(kbdev->dev, "Couldn't process dvfs_period write operation.\n"
				"Use format <dvfs_period_ms>\n");
		return -EINVAL;
	}

	kbdev->pm.dvfs_period = dvfs_period;
	dev_dbg(kbdev->dev, "DVFS period: %dms\n", dvfs_period);

	return count;
}

/**
 * show_dvfs_period - Show callback for the dvfs_period sysfs entry.
 * @dev:  The device this sysfs file is for.
 * @attr: The attributes of the sysfs file.
 * @buf:  The output buffer to receive the GPU information.
 *
 * This function is called to get the current period used for the DVFS sample
 * timer.
 *
 * Return: The number of bytes output to buf.
 */
static ssize_t show_dvfs_period(struct device *dev,
		struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	ssize_t ret;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	ret = scnprintf(buf, PAGE_SIZE, "%d\n", kbdev->pm.dvfs_period);

	return ret;
}

static DEVICE_ATTR(dvfs_period, S_IRUGO | S_IWUSR, show_dvfs_period,
		set_dvfs_period);

/**
 * set_pm_poweroff - Store callback for the pm_poweroff sysfs file.
 * @dev:   The device with sysfs file is for
 * @attr:  The attributes of the sysfs file
 * @buf:   The value written to the sysfs file
 * @count: The number of bytes written to the sysfs file
 *
 * This function is called when the pm_poweroff sysfs file is written to.
 *
 * This file contains three values separated by whitespace. The values
 * are gpu_poweroff_time (the period of the poweroff timer, in ns),
 * poweroff_shader_ticks (the number of poweroff timer ticks before an idle
 * shader is powered off), and poweroff_gpu_ticks (the number of poweroff timer
 * ticks before the GPU is powered off), in that order.
 *
 * Return: @c count if the function succeeded. An error code on failure.
 */
static ssize_t set_pm_poweroff(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	int items;
	s64 gpu_poweroff_time;
	int poweroff_shader_ticks, poweroff_gpu_ticks;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	items = sscanf(buf, "%llu %u %u", &gpu_poweroff_time,
			&poweroff_shader_ticks,
			&poweroff_gpu_ticks);
	if (items != 3) {
		dev_err(kbdev->dev, "Couldn't process pm_poweroff write operation.\n"
				"Use format <gpu_poweroff_time_ns> <poweroff_shader_ticks> <poweroff_gpu_ticks>\n");
		return -EINVAL;
	}

	kbdev->pm.gpu_poweroff_time = HR_TIMER_DELAY_NSEC(gpu_poweroff_time);
	kbdev->pm.poweroff_shader_ticks = poweroff_shader_ticks;
	kbdev->pm.poweroff_gpu_ticks = poweroff_gpu_ticks;

	return count;
}

/**
 * show_pm_poweroff - Show callback for the pm_poweroff sysfs entry.
 * @dev:  The device this sysfs file is for.
 * @attr: The attributes of the sysfs file.
 * @buf:  The output buffer to receive the GPU information.
 *
 * This function is called to get the current period used for the DVFS sample
 * timer.
 *
 * Return: The number of bytes output to buf.
 */
static ssize_t show_pm_poweroff(struct device *dev,
		struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	ssize_t ret;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	ret = scnprintf(buf, PAGE_SIZE, "%llu %u %u\n",
			ktime_to_ns(kbdev->pm.gpu_poweroff_time),
			kbdev->pm.poweroff_shader_ticks,
			kbdev->pm.poweroff_gpu_ticks);

	return ret;
}

static DEVICE_ATTR(pm_poweroff, S_IRUGO | S_IWUSR, show_pm_poweroff,
		set_pm_poweroff);

/**
 * set_reset_timeout - Store callback for the reset_timeout sysfs file.
 * @dev:   The device with sysfs file is for
 * @attr:  The attributes of the sysfs file
 * @buf:   The value written to the sysfs file
 * @count: The number of bytes written to the sysfs file
 *
 * This function is called when the reset_timeout sysfs file is written to. It
 * checks the data written, and if valid updates the reset timeout.
 *
 * Return: @c count if the function succeeded. An error code on failure.
 */
static ssize_t set_reset_timeout(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	int ret;
	int reset_timeout;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	ret = kstrtoint(buf, 0, &reset_timeout);
	if (ret || reset_timeout <= 0) {
		dev_err(kbdev->dev, "Couldn't process reset_timeout write operation.\n"
				"Use format <reset_timeout_ms>\n");
		return -EINVAL;
	}

	kbdev->reset_timeout_ms = reset_timeout;
	dev_dbg(kbdev->dev, "Reset timeout: %dms\n", reset_timeout);

	return count;
}

/**
 * show_reset_timeout - Show callback for the reset_timeout sysfs entry.
 * @dev:  The device this sysfs file is for.
 * @attr: The attributes of the sysfs file.
 * @buf:  The output buffer to receive the GPU information.
 *
 * This function is called to get the current reset timeout.
 *
 * Return: The number of bytes output to buf.
 */
static ssize_t show_reset_timeout(struct device *dev,
		struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	ssize_t ret;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	ret = scnprintf(buf, PAGE_SIZE, "%d\n", kbdev->reset_timeout_ms);

	return ret;
}

static DEVICE_ATTR(reset_timeout, S_IRUGO | S_IWUSR, show_reset_timeout,
		set_reset_timeout);



static ssize_t show_mem_pool_size(struct device *dev,
		struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	ssize_t ret;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	ret = scnprintf(buf, PAGE_SIZE, "%zu\n",
			kbase_mem_pool_size(&kbdev->mem_pool));

	return ret;
}

static ssize_t set_mem_pool_size(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	size_t new_size;
	int err;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	err = kstrtoul(buf, 0, (unsigned long *)&new_size);
	if (err)
		return err;

	kbase_mem_pool_trim(&kbdev->mem_pool, new_size);

	return count;
}

static DEVICE_ATTR(mem_pool_size, S_IRUGO | S_IWUSR, show_mem_pool_size,
		set_mem_pool_size);

static ssize_t show_mem_pool_max_size(struct device *dev,
		struct device_attribute *attr, char * const buf)
{
	struct kbase_device *kbdev;
	ssize_t ret;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	ret = scnprintf(buf, PAGE_SIZE, "%zu\n",
			kbase_mem_pool_max_size(&kbdev->mem_pool));

	return ret;
}

static ssize_t set_mem_pool_max_size(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct kbase_device *kbdev;
	size_t new_max_size;
	int err;

	kbdev = to_kbase_device(dev);
	if (!kbdev)
		return -ENODEV;

	err = kstrtoul(buf, 0, (unsigned long *)&new_max_size);
	if (err)
		return -EINVAL;

	kbase_mem_pool_set_max_size(&kbdev->mem_pool, new_max_size);

	return count;
}

static DEVICE_ATTR(mem_pool_max_size, S_IRUGO | S_IWUSR, show_mem_pool_max_size,
		set_mem_pool_max_size);



static int kbasep_secure_mode_init(struct kbase_device *kbdev)
{

#ifdef SECURE_CALLBACKS
	kbdev->secure_ops = SECURE_CALLBACKS;
	kbdev->secure_mode_support = false;

	if (kbdev->secure_ops) {
		int err;

		/* MALI_SEC_SECURE_RENDERING */
		/* removed below code : Make sure secure mode msut be called by job manager before seucre rendering */
		err = kbdev->secure_ops->secure_mode_init(kbdev);

		/* MALI_SEC_SECURE_RENDERING */
		/* secure_mode_init() returns 0 < value if not supported */
		if (!err)
			kbdev->secure_mode_support = true;
	}
/* MALI_SEC_SECURE_RENDERING */
#else
	kbdev->secure_mode_support = false;
#endif

	return 0;
}

#ifdef CONFIG_MALI_NO_MALI
static int kbase_common_reg_map(struct kbase_device *kbdev)
{
	return 0;
}
static void kbase_common_reg_unmap(struct kbase_device * const kbdev)
{
}
#else /* CONFIG_MALI_NO_MALI */
static int kbase_common_reg_map(struct kbase_device *kbdev)
{
	int err = -ENOMEM;

	if (!request_mem_region(kbdev->reg_start, kbdev->reg_size, dev_name(kbdev->dev))) {
		dev_err(kbdev->dev, "Register window unavailable\n");
		err = -EIO;
		goto out_region;
	}

	kbdev->reg = ioremap(kbdev->reg_start, kbdev->reg_size);
	if (!kbdev->reg) {
		dev_err(kbdev->dev, "Can't remap register window\n");
		err = -EINVAL;
		goto out_ioremap;
	}

	return 0;

 out_ioremap:
	release_mem_region(kbdev->reg_start, kbdev->reg_size);
 out_region:
	return err;
}

static void kbase_common_reg_unmap(struct kbase_device * const kbdev)
{
	iounmap(kbdev->reg);
	release_mem_region(kbdev->reg_start, kbdev->reg_size);
}
#endif /* CONFIG_MALI_NO_MALI */


#ifdef CONFIG_DEBUG_FS

#if KBASE_GPU_RESET_EN
#include <mali_kbase_hwaccess_jm.h>

static void trigger_quirks_reload(struct kbase_device *kbdev)
{
	kbase_pm_context_active(kbdev);
	if (kbase_prepare_to_reset_gpu(kbdev))
		kbase_reset_gpu(kbdev);
	kbase_pm_context_idle(kbdev);
}

#define MAKE_QUIRK_ACCESSORS(type) \
static int type##_quirks_set(void *data, u64 val) \
{ \
	struct kbase_device *kbdev; \
	kbdev = (struct kbase_device *)data; \
	kbdev->hw_quirks_##type = (u32)val; \
	trigger_quirks_reload(kbdev); \
	return 0;\
} \
\
static int type##_quirks_get(void *data, u64 *val) \
{ \
	struct kbase_device *kbdev;\
	kbdev = (struct kbase_device *)data;\
	*val = kbdev->hw_quirks_##type;\
	return 0;\
} \
DEFINE_SIMPLE_ATTRIBUTE(fops_##type##_quirks, type##_quirks_get,\
		type##_quirks_set, "%llu\n")

MAKE_QUIRK_ACCESSORS(sc);
MAKE_QUIRK_ACCESSORS(tiler);
MAKE_QUIRK_ACCESSORS(mmu);

#endif /* KBASE_GPU_RESET_EN */

static int kbasep_secure_mode_seq_show(struct seq_file *m, void *p)
{
	struct kbase_device *kbdev = m->private;

	if (!kbdev->secure_mode_support)
		seq_puts(m, "unsupported\n");
	else
		seq_printf(m, "%s\n", kbdev->secure_mode ? "Y" : "N");

	return 0;
}

static int kbasep_secure_mode_debugfs_open(struct inode *in, struct file *file)
{
	return single_open(file, kbasep_secure_mode_seq_show, in->i_private);
}

static const struct file_operations kbasep_secure_mode_debugfs_fops = {
	.open = kbasep_secure_mode_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

#ifndef MALI_SEC_INTEGRATION
extern const struct file_operations kbasep_trace_debugfs_fops;
#endif /* MALI_SEC_INTEGRATION */

static int kbase_device_debugfs_init(struct kbase_device *kbdev)
{
	struct dentry *debugfs_ctx_defaults_directory;
	int err;

#ifdef MALI_SEC_INTEGRATION
	kbdev->mali_debugfs_directory = debugfs_create_dir(kbdev->devname,
			NULL);
#else
	kbdev->mali_debugfs_directory = debugfs_create_dir("mali",
			NULL);
#endif /* MALI_SEC_INTEGRATION */
	if (!kbdev->mali_debugfs_directory) {
		dev_err(kbdev->dev, "Couldn't create mali debugfs directory\n");
		err = -ENOMEM;
		goto out;
	}

#ifdef MALI_SEC_INTEGRATION
	kbdev->debugfs_ctx_directory = debugfs_create_dir("ctx",
			kbdev->mali_debugfs_directory);
#else
	kbdev->trace_dentry = debugfs_create_file("mali_trace", S_IRUGO,
			kbdev->mali_debugfs_directory, kbdev,
			&kbasep_trace_debugfs_fops);

	kbdev->debugfs_ctx_directory = debugfs_create_dir("mem",
			kbdev->mali_debugfs_directory);
#endif /* MALI_SEC_INTEGRATION */
	if (!kbdev->debugfs_ctx_directory) {
		dev_err(kbdev->dev, "Couldn't create mali debugfs ctx directory\n");
		err = -ENOMEM;
		goto out;
	}

	debugfs_ctx_defaults_directory = debugfs_create_dir("defaults",
			kbdev->debugfs_ctx_directory);
	if (!debugfs_ctx_defaults_directory) {
		dev_err(kbdev->dev, "Couldn't create mali debugfs ctx defaults directory\n");
		err = -ENOMEM;
		goto out;
	}
	kbase_debug_job_fault_dev_init(kbdev);
	kbasep_gpu_memory_debugfs_init(kbdev);
#if KBASE_GPU_RESET_EN
	debugfs_create_file("quirks_sc", 0644,
			kbdev->mali_debugfs_directory, kbdev,
			&fops_sc_quirks);
	debugfs_create_file("quirks_tiler", 0644,
			kbdev->mali_debugfs_directory, kbdev,
			&fops_tiler_quirks);
	debugfs_create_file("quirks_mmu", 0644,
			kbdev->mali_debugfs_directory, kbdev,
			&fops_mmu_quirks);
#endif /* KBASE_GPU_RESET_EN */

#ifndef CONFIG_MALI_COH_USER
	debugfs_create_bool("infinite_cache", 0644,
			debugfs_ctx_defaults_directory,
			&kbdev->infinite_cache_active_default);
#endif /* CONFIG_MALI_COH_USER */

	debugfs_create_size_t("mem_pool_max_size", 0644,
			debugfs_ctx_defaults_directory,
			&kbdev->mem_pool_max_size_default);

#if KBASE_TRACE_ENABLE
	kbasep_trace_debugfs_init(kbdev);
#endif /* KBASE_TRACE_ENABLE */

#ifdef CONFIG_MALI_TRACE_TIMELINE
	kbasep_trace_timeline_debugfs_init(kbdev);
#endif /* CONFIG_MALI_TRACE_TIMELINE */

	debugfs_create_file("secure_mode", S_IRUGO,
			kbdev->mali_debugfs_directory, kbdev,
			&kbasep_secure_mode_debugfs_fops);

	return 0;

out:
	debugfs_remove_recursive(kbdev->mali_debugfs_directory);
	return err;
}

static void kbase_device_debugfs_term(struct kbase_device *kbdev)
{
	debugfs_remove_recursive(kbdev->mali_debugfs_directory);
}

#else /* CONFIG_DEBUG_FS */
static inline int kbase_device_debugfs_init(struct kbase_device *kbdev)
{
	return 0;
}

static inline void kbase_device_debugfs_term(struct kbase_device *kbdev) { }
#endif /* CONFIG_DEBUG_FS */

static void kbase_device_coherency_init(struct kbase_device *kbdev, u32 gpu_id)
{
	u32 selected_coherency = COHERENCY_NONE;
	/* COHERENCY_NONE is always supported */
	u32 supported_coherency_bitmap = COHERENCY_FEATURE_BIT(COHERENCY_NONE);

#ifdef CONFIG_OF
	const void *coherency_override_dts;
	u32 override_coherency;
#endif /* CONFIG_OF */

	kbdev->system_coherency = selected_coherency;

	/* device tree may override the coherency */
#ifdef CONFIG_OF
	coherency_override_dts = of_get_property(kbdev->dev->of_node,
						"override-coherency",
						NULL);
	if (coherency_override_dts) {

		override_coherency = be32_to_cpup(coherency_override_dts);

		if ((override_coherency <= COHERENCY_NONE) &&
			(supported_coherency_bitmap &
			 COHERENCY_FEATURE_BIT(override_coherency))) {

			kbdev->system_coherency = override_coherency;

			dev_info(kbdev->dev,
				"Using coherency override, mode %u set from dtb",
				override_coherency);
		} else
			dev_warn(kbdev->dev,
				"Ignoring invalid coherency override, mode %u set from dtb",
				override_coherency);
	}

#endif /* CONFIG_OF */

	kbdev->gpu_props.props.raw_props.coherency_features =
		kbdev->system_coherency;
}

#ifdef CONFIG_MALI_FPGA_BUS_LOGGER

/* Callback used by the kbase bus logger client, to initiate a GPU reset
 * when the bus log is restarted.  GPU reset is used as reference point
 * in HW bus log analyses.
 */
static void kbase_logging_started_cb(void *data)
{
	struct kbase_device *kbdev = (struct kbase_device *)data;

	if (kbase_prepare_to_reset_gpu(kbdev))
		kbase_reset_gpu(kbdev);
	dev_info(kbdev->dev, "KBASE - Bus logger restarted\n");
}
#endif


static int kbase_common_device_init(struct kbase_device *kbdev)
{
	int err;
#if defined(CONFIG_MALI_PLATFORM_VEXPRESS)
	struct mali_base_gpu_core_props *core_props;
#endif
	enum {
		inited_mem = (1u << 0),
		inited_js = (1u << 1),
		inited_pm_runtime_init = (1u << 6),
#ifdef CONFIG_MALI_DEVFREQ
		inited_devfreq = (1u << 9),
#endif /* CONFIG_MALI_DEVFREQ */
#ifdef CONFIG_MALI_MIPE_ENABLED
		inited_tlstream = (1u << 10),
#endif /* CONFIG_MALI_MIPE_ENABLED */
		inited_backend_early = (1u << 11),
		inited_backend_late = (1u << 12),
		inited_device = (1u << 13),
		inited_vinstr = (1u << 19),
		inited_ipa = (1u << 20)
	};

	int inited = 0;
	u32 gpu_id;
#if defined(CONFIG_MALI_PLATFORM_VEXPRESS)
	u32 ve_logic_tile = 0;
#endif /* CONFIG_MALI_PLATFORM_VEXPRESS */

	dev_set_drvdata(kbdev->dev, kbdev);

	err = kbase_backend_early_init(kbdev);
	if (err)
		goto out_partial;
	inited |= inited_backend_early;

	scnprintf(kbdev->devname, DEVNAME_SIZE, "%s%d", kbase_drv_name,
			kbase_dev_nr++);

	kbase_disjoint_init(kbdev);

/* MALI_SEC_INTEGRATION */ /* Move vexpress definition to here */
#if defined(CONFIG_MALI_PLATFORM_VEXPRESS)
	/* obtain min/max configured gpu frequencies */
	core_props = &(kbdev->gpu_props.props.core_props);

	/* For versatile express platforms, min and max values of GPU frequency
	 * depend on the type of the logic tile; these values may not be known
	 * at the build time so in some cases a platform config file with wrong
	 * GPU freguency values may be included; to ensure the correct value of
	 * min and max GPU frequency is obtained, the type of the logic tile is
	 * read from the corresponding register on the platform and frequency
	 * values assigned accordingly.*/

	ve_logic_tile = kbase_get_platform_logic_tile_type();

	switch (ve_logic_tile) {
	case 0x217:
		/* Virtex 6, HBI0217 */
		core_props->gpu_freq_khz_min = VE_VIRTEX6_GPU_FREQ_MIN;
		core_props->gpu_freq_khz_max = VE_VIRTEX6_GPU_FREQ_MAX;
		break;
	case 0x247:
		/* Virtex 7, HBI0247 */
		core_props->gpu_freq_khz_min = VE_VIRTEX7_GPU_FREQ_MIN;
		core_props->gpu_freq_khz_max = VE_VIRTEX7_GPU_FREQ_MAX;
		break;
	default:
		/* all other logic tiles, i.e., Virtex 5 HBI0192
		 * or unsuccessful reading from the platform -
		 * fall back to the config_platform default */
		core_props->gpu_freq_khz_min = GPU_FREQ_KHZ_MIN;
		core_props->gpu_freq_khz_max = GPU_FREQ_KHZ_MAX;
		break;
	}
 #endif /* CONFIG_MALI_PLATFORM_VEXPRESS */

	kbdev->gpu_props.irq_throttle_time_us = DEFAULT_IRQ_THROTTLE_TIME_US;

	err = kbase_device_init(kbdev);
	if (err) {
		dev_err(kbdev->dev, "Can't initialize device (%d)\n", err);
		goto out_partial;
	}

	inited |= inited_device;

#ifdef MALI_SEC_HWCNT
	mutex_init(&kbdev->hwcnt.mlock);
#endif

	kbdev->vinstr_ctx = kbase_vinstr_init(kbdev);
	if (!kbdev->vinstr_ctx) {
		dev_err(kbdev->dev, "Can't initialize virtual instrumentation core\n");
		goto out_partial;
	}

	inited |= inited_vinstr;

	kbdev->ipa_ctx = kbase_ipa_init(kbdev);
	if (!kbdev->ipa_ctx) {
		dev_err(kbdev->dev, "Can't initialize IPA\n");
		goto out_partial;
	}

	inited |= inited_ipa;

	if (kbdev->pm.callback_power_runtime_init) {
		err = kbdev->pm.callback_power_runtime_init(kbdev);
		if (err)
			goto out_partial;

		inited |= inited_pm_runtime_init;
	}

	err = kbase_mem_init(kbdev);
	if (err)
		goto out_partial;

	inited |= inited_mem;

	gpu_id = kbdev->gpu_props.props.raw_props.gpu_id;
	gpu_id &= GPU_ID_VERSION_PRODUCT_ID;
	gpu_id = gpu_id >> GPU_ID_VERSION_PRODUCT_ID_SHIFT;

	kbase_device_coherency_init(kbdev, gpu_id);

	err = kbasep_secure_mode_init(kbdev);
	if (err)
		goto out_partial;

	err = kbasep_js_devdata_init(kbdev);
	if (err)
		goto out_partial;

	inited |= inited_js;

#ifdef CONFIG_MALI_MIPE_ENABLED
	err = kbase_tlstream_init();
	if (err) {
		dev_err(kbdev->dev, "Couldn't initialize timeline stream\n");
		goto out_partial;
	}
	inited |= inited_tlstream;
#endif /* CONFIG_MALI_MIPE_ENABLED */

	err = kbase_backend_late_init(kbdev);
	if (err)
		goto out_partial;
	inited |= inited_backend_late;

#ifdef CONFIG_MALI_DEVFREQ
	err = kbase_devfreq_init(kbdev);
	if (err) {
		dev_err(kbdev->dev, "Couldn't initialize devfreq\n");
		goto out_partial;
	}
	inited |= inited_devfreq;
#endif /* CONFIG_MALI_DEVFREQ */

	err = kbase_device_debugfs_init(kbdev);
	if (err)
		goto out_partial;

	/* intialise the kctx list */
	mutex_init(&kbdev->kctx_list_lock);
	INIT_LIST_HEAD(&kbdev->kctx_list);

	kbdev->mdev.minor = MISC_DYNAMIC_MINOR;
	kbdev->mdev.name = kbdev->devname;
	kbdev->mdev.fops = &kbase_fops;
	kbdev->mdev.parent = get_device(kbdev->dev);

	err = misc_register(&kbdev->mdev);
	if (err) {
		dev_err(kbdev->dev, "Couldn't register misc dev %s\n", kbdev->devname);
		goto out_misc;
	}

	{
		const struct list_head *dev_list = kbase_dev_list_get();

		list_add(&kbdev->entry, &kbase_dev_list);
		kbase_dev_list_put(dev_list);
	}

	dev_info(kbdev->dev, "Probed as %s\n", dev_name(kbdev->mdev.this_device));

	return 0;

out_misc:
	put_device(kbdev->dev);
	kbase_device_debugfs_term(kbdev);
out_partial:
	if (inited & inited_ipa)
		kbase_ipa_term(kbdev->ipa_ctx);
	if (inited & inited_vinstr)
		kbase_vinstr_term(kbdev->vinstr_ctx);
#ifdef CONFIG_MALI_DEVFREQ
	if (inited & inited_devfreq)
		kbase_devfreq_term(kbdev);
#endif /* CONFIG_MALI_DEVFREQ */
	if (inited & inited_backend_late)
		kbase_backend_late_term(kbdev);
#ifdef CONFIG_MALI_MIPE_ENABLED
	if (inited & inited_tlstream)
		kbase_tlstream_term();
#endif /* CONFIG_MALI_MIPE_ENABLED */

	if (inited & inited_js)
		kbasep_js_devdata_halt(kbdev);

	if (inited & inited_mem)
		kbase_mem_halt(kbdev);

	if (inited & inited_js)
		kbasep_js_devdata_term(kbdev);

	if (inited & inited_mem)
		kbase_mem_term(kbdev);

	if (inited & inited_pm_runtime_init) {
		if (kbdev->pm.callback_power_runtime_term)
			kbdev->pm.callback_power_runtime_term(kbdev);
	}

	if (inited & inited_device)
		kbase_device_term(kbdev);

	if (inited & inited_backend_early)
		kbase_backend_early_term(kbdev);

	return err;
}


static struct attribute *kbase_attrs[] = {
#ifdef CONFIG_MALI_DEBUG_SHADER_SPLIT_FS
	&dev_attr_sc_split.attr,
#endif
#ifdef CONFIG_MALI_DEBUG
	&dev_attr_debug_command.attr,
	&dev_attr_js_softstop_always.attr,
#endif
#if !MALI_CUSTOMER_RELEASE
	&dev_attr_force_replay.attr,
#endif
	&dev_attr_js_timeouts.attr,
	&dev_attr_gpuinfo.attr,
	&dev_attr_dvfs_period.attr,
	&dev_attr_pm_poweroff.attr,
	&dev_attr_reset_timeout.attr,
	&dev_attr_js_scheduling_period.attr,
	&dev_attr_power_policy.attr,
	&dev_attr_core_availability_policy.attr,
	&dev_attr_core_mask.attr,
	&dev_attr_mem_pool_size.attr,
	&dev_attr_mem_pool_max_size.attr,
	NULL
};

static const struct attribute_group kbase_attr_group = {
	.attrs = kbase_attrs,
};

static int kbase_common_device_remove(struct kbase_device *kbdev);

static int kbase_platform_device_probe(struct platform_device *pdev)
{
	struct kbase_device *kbdev;
	struct resource *reg_res;
	int err = 0;
	int i;

#ifdef CONFIG_OF
	err = kbase_platform_early_init();
	if (err) {
		dev_err(&pdev->dev, "Early platform initialization failed\n");
		return err;
	}
#endif

	kbdev = kbase_device_alloc();
	if (!kbdev) {
		dev_err(&pdev->dev, "Can't allocate device\n");
		err = -ENOMEM;
		goto out;
	}
#ifdef CONFIG_MALI_NO_MALI
	err = gpu_device_create(kbdev);
	if (err) {
		dev_err(&pdev->dev, "Can't initialize dummy model\n");
		goto out_midg;
	}
#endif /* CONFIG_MALI_NO_MALI */

	kbdev->dev = &pdev->dev;
	/* 3 IRQ resources */
	for (i = 0; i < 3; i++) {
		struct resource *irq_res;
		int irqtag;

		irq_res = platform_get_resource(pdev, IORESOURCE_IRQ, i);
		if (!irq_res) {
			dev_err(kbdev->dev, "No IRQ resource at index %d\n", i);
			err = -ENOENT;
			goto out_platform_irq;
		}

/* MALI_SEC_INTEGRATION */
#if 0 /* #ifdef CONFIG_OF */
		if (!strcmp(irq_res->name, "JOB")) {
			irqtag = JOB_IRQ_TAG;
		} else if (!strcmp(irq_res->name, "MMU")) {
			irqtag = MMU_IRQ_TAG;
		} else if (!strcmp(irq_res->name, "GPU")) {
			irqtag = GPU_IRQ_TAG;
		} else {
			dev_err(&pdev->dev, "Invalid irq res name: '%s'\n",
				irq_res->name);
			err = -EINVAL;
			goto out_irq_name;
		}
#else
		irqtag = i;
#endif /* CONFIG_OF */
		kbdev->irqs[irqtag].irq = irq_res->start;
		kbdev->irqs[irqtag].flags = (irq_res->flags & IRQF_TRIGGER_MASK);
	}
		/* the first memory resource is the physical address of the GPU
		 * registers */
		reg_res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
		if (!reg_res) {
			dev_err(kbdev->dev, "Invalid register resource\n");
			err = -ENOENT;
			goto out_platform_mem;
		}

		kbdev->reg_start = reg_res->start;
		kbdev->reg_size = resource_size(reg_res);

		err = kbase_common_reg_map(kbdev);
		if (err)
			goto out_reg_map;

#ifdef CONFIG_MALI_MIDGARD_DVFS
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)) && defined(CONFIG_OF) \
			&& defined(CONFIG_REGULATOR)
	kbdev->regulator = regulator_get_optional(kbdev->dev, "mali");
	if (IS_ERR_OR_NULL(kbdev->regulator)) {
		dev_info(kbdev->dev, "Continuing without Mali regulator control\n");
		kbdev->regulator = NULL;
		/* Allow probe to continue without regulator */
	}
#endif /* LINUX_VERSION_CODE >= 3, 12, 0 */
#endif

#ifdef CONFIG_MALI_PLATFORM_DEVICETREE
	pm_runtime_enable(kbdev->dev);
#endif
#ifdef CONFIG_HAVE_CLK
	kbdev->clock = clk_get(kbdev->dev, "clk_mali");
	if (IS_ERR_OR_NULL(kbdev->clock)) {
		dev_info(kbdev->dev, "Continuing without Mali clock control\n");
		kbdev->clock = NULL;
		/* Allow probe to continue without clock. */
	} else {
		err = clk_prepare_enable(kbdev->clock);
		if (err) {
			dev_err(kbdev->dev,
				"Failed to prepare and enable clock (%d)\n", err);
			goto out_clock_prepare;
		}
	}
#endif
#ifdef CONFIG_MALI_MIDGARD_DVFS
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)) && defined(CONFIG_OF) \
			&& defined(CONFIG_PM_OPP)
	/* Register the OPPs if they are available in device tree */
	if (of_init_opp_table(kbdev->dev) < 0)
		dev_dbg(kbdev->dev, "OPP table not found\n");
#endif
#endif

	err = kbase_common_device_init(kbdev);
	if (err) {
		dev_err(kbdev->dev, "Failed kbase_common_device_init\n");
		goto out_common_init;
	}

	err = sysfs_create_group(&kbdev->dev->kobj, &kbase_attr_group);
	if (err) {
		dev_err(&pdev->dev, "Failed to create sysfs entries\n");
		goto out_sysfs;
	}

#ifdef CONFIG_MALI_FPGA_BUS_LOGGER
	err = bl_core_client_register(kbdev->devname,
						kbase_logging_started_cb,
						kbdev, &kbdev->buslogger,
						THIS_MODULE, NULL);
	if (err) {
		dev_err(kbdev->dev, "Couldn't register bus log client\n");
		goto out_bl_core_register;
	}

	bl_core_set_threshold(kbdev->buslogger, 1024*1024*1024);
#endif
	return 0;

#ifdef CONFIG_MALI_FPGA_BUS_LOGGER
out_bl_core_register:
	sysfs_remove_group(&kbdev->dev->kobj, &kbase_attr_group);
#endif

out_sysfs:
	kbase_common_device_remove(kbdev);
out_common_init:
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0))
	of_free_opp_table(kbdev->dev);
#endif
#ifdef CONFIG_HAVE_CLK
	clk_disable_unprepare(kbdev->clock);
out_clock_prepare:
	clk_put(kbdev->clock);
#endif
#ifdef CONFIG_MALI_PLATFORM_DEVICETREE
	pm_runtime_disable(kbdev->dev);
#endif
#ifdef CONFIG_MALI_MIDGARD_DVFS
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)) && defined(CONFIG_OF) \
			&& defined(CONFIG_REGULATOR)
	regulator_put(kbdev->regulator);
#endif /* LINUX_VERSION_CODE >= 3, 12, 0 */
#endif
		kbase_common_reg_unmap(kbdev);
out_reg_map:
out_platform_mem:
/* MALI_SEC_INTEGRATION */
#if 0 /* #ifdef CONFIG_OF */
out_irq_name:
#endif
out_platform_irq:
#ifdef CONFIG_MALI_NO_MALI
	gpu_device_destroy(kbdev);
out_midg:
#endif /* CONFIG_MALI_NO_MALI */
	kbase_device_free(kbdev);
out:
	return err;
}

static int kbase_common_device_remove(struct kbase_device *kbdev)
{
#ifdef MALI_SEC_HWCNT
	mutex_lock(&kbdev->hwcnt.mlock);
	if(kbdev->vendor_callbacks->hwcnt_detach)
		kbdev->vendor_callbacks->hwcnt_detach(kbdev);
	mutex_unlock(&kbdev->hwcnt.mlock);
#endif

	kbase_ipa_term(kbdev->ipa_ctx);
	kbase_vinstr_term(kbdev->vinstr_ctx);
	sysfs_remove_group(&kbdev->dev->kobj, &kbase_attr_group);

#ifdef CONFIG_MALI_FPGA_BUS_LOGGER
	if (kbdev->buslogger)
		bl_core_client_unregister(kbdev->buslogger);
#endif

#ifdef CONFIG_DEBUG_FS
	debugfs_remove_recursive(kbdev->mali_debugfs_directory);
#endif
#ifdef CONFIG_MALI_DEVFREQ
	kbase_devfreq_term(kbdev);
#endif

	kbase_backend_late_term(kbdev);

	if (kbdev->pm.callback_power_runtime_term)
		kbdev->pm.callback_power_runtime_term(kbdev);
#ifdef CONFIG_MALI_PLATFORM_DEVICETREE
	pm_runtime_disable(kbdev->dev);
#endif

#ifdef CONFIG_MALI_MIPE_ENABLED
	kbase_tlstream_term();
#endif /* CONFIG_MALI_MIPE_ENABLED */

	kbasep_js_devdata_halt(kbdev);
	kbase_mem_halt(kbdev);

	kbasep_js_devdata_term(kbdev);
	kbase_mem_term(kbdev);
	kbase_backend_early_term(kbdev);

	{
		const struct list_head *dev_list = kbase_dev_list_get();

		list_del(&kbdev->entry);
		kbase_dev_list_put(dev_list);
	}
	misc_deregister(&kbdev->mdev);
	put_device(kbdev->dev);
		kbase_common_reg_unmap(kbdev);
	kbase_device_term(kbdev);
#ifdef CONFIG_HAVE_CLK
	if (kbdev->clock) {
		clk_disable_unprepare(kbdev->clock);
		clk_put(kbdev->clock);
		kbdev->clock = NULL;
	}
#endif
#ifdef CONFIG_MALI_MIDGARD_DVFS
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)) && defined(CONFIG_OF) \
			&& defined(CONFIG_REGULATOR)
	regulator_put(kbdev->regulator);
#endif /* LINUX_VERSION_CODE >= 3, 12, 0 */
#endif
#ifdef CONFIG_MALI_NO_MALI
	gpu_device_destroy(kbdev);
#endif /* CONFIG_MALI_NO_MALI */
	kbase_device_free(kbdev);

	return 0;
}

static int kbase_platform_device_remove(struct platform_device *pdev)
{
	struct kbase_device *kbdev = to_kbase_device(&pdev->dev);

	if (!kbdev)
		return -ENODEV;

	return kbase_common_device_remove(kbdev);
}

/** Suspend callback from the OS.
 *
 * This is called by Linux when the device should suspend.
 *
 * @param dev  The device to suspend
 *
 * @return A standard Linux error code
 */

/* MALI_SEC_INTEGRATION */
static int kbase_device_suspend_dummy(struct device *dev)
{
	return 0;
}

/* MALI_SEC_INTEGRATION */
int kbase_device_suspend(struct kbase_device *kbdev)
{
	if (!kbdev)
		return -ENODEV;

#if defined(CONFIG_PM_DEVFREQ) && \
		(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
	devfreq_suspend_device(kbdev->devfreq);
#endif

	kbase_pm_suspend(kbdev);
	return 0;
}

/** Resume callback from the OS.
 *
 * This is called by Linux when the device should resume from suspension.
 *
 * @param dev  The device to resume
 *
 * @return A standard Linux error code
 */

/* MALI_SEC_INTEGRATION */
static int kbase_device_resume_dummy(struct device *dev)
{
	return 0;
}

/* MALI_SEC_INTEGRATION */
int kbase_device_resume(struct kbase_device *kbdev)
{
	if (!kbdev)
		return -ENODEV;

	kbase_pm_resume(kbdev);

#if defined(CONFIG_PM_DEVFREQ) && \
		(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
	devfreq_resume_device(kbdev->devfreq);
#endif
	return 0;
}

/** Runtime suspend callback from the OS.
 *
 * This is called by Linux when the device should prepare for a condition in which it will
 * not be able to communicate with the CPU(s) and RAM due to power management.
 *
 * @param dev  The device to suspend
 *
 * @return A standard Linux error code
 */
#ifdef KBASE_PM_RUNTIME
static int kbase_device_runtime_suspend(struct device *dev)
{
	struct kbase_device *kbdev = to_kbase_device(dev);

	if (!kbdev)
		return -ENODEV;

#if defined(CONFIG_PM_DEVFREQ) && \
		(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
	devfreq_suspend_device(kbdev->devfreq);
#endif

/* MALI_SEC_INTEGRATION */
	if (kbdev->pm.active_count > 0)
		return -EBUSY;

	if (kbdev->pm.backend.callback_power_runtime_off) {
		kbdev->pm.backend.callback_power_runtime_off(kbdev);
		dev_dbg(dev, "runtime suspend\n");
	}
	return 0;
}
#endif /* KBASE_PM_RUNTIME */

/** Runtime resume callback from the OS.
 *
 * This is called by Linux when the device should go into a fully active state.
 *
 * @param dev  The device to suspend
 *
 * @return A standard Linux error code
 */

#ifdef KBASE_PM_RUNTIME
int kbase_device_runtime_resume(struct device *dev)
{
	int ret = 0;
	struct kbase_device *kbdev = to_kbase_device(dev);

	if (!kbdev)
		return -ENODEV;

	if (kbdev->pm.backend.callback_power_runtime_on) {
		ret = kbdev->pm.backend.callback_power_runtime_on(kbdev);
		dev_dbg(dev, "runtime resume\n");
	}

#if defined(CONFIG_PM_DEVFREQ) && \
		(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
	devfreq_resume_device(kbdev->devfreq);
#endif

	return ret;
}
#endif /* KBASE_PM_RUNTIME */

/** Runtime idle callback from the OS.
 *
 * This is called by Linux when the device appears to be inactive and it might be
 * placed into a low power state
 *
 * @param dev  The device to suspend
 *
 * @return A standard Linux error code
 */

#ifdef KBASE_PM_RUNTIME
static int kbase_device_runtime_idle(struct device *dev)
{
	/* Avoid pm_runtime_suspend being called */
	return 1;
}
#endif /* KBASE_PM_RUNTIME */

/** The power management operations for the platform driver.
 */
static const struct dev_pm_ops kbase_pm_ops = {
	/* MALI_SEC_INTEGRATION */
	.suspend = kbase_device_suspend_dummy,
	.resume = kbase_device_resume_dummy,
#ifdef KBASE_PM_RUNTIME
	.runtime_suspend = kbase_device_runtime_suspend,
	.runtime_resume = kbase_device_runtime_resume,
	.runtime_idle = kbase_device_runtime_idle,
#endif /* KBASE_PM_RUNTIME */
};

#ifdef CONFIG_OF
static const struct of_device_id kbase_dt_ids[] = {
	{ .compatible = "arm,malit6xx" },
	{ .compatible = "arm,mali-midgard" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, kbase_dt_ids);
#endif

/* MALI_SEC_INTEGRATION */
#ifdef CONFIG_OF
static const struct of_device_id exynos_mali_match[] = {
	{ .compatible = "arm,mali", },
	{},
};
MODULE_DEVICE_TABLE(of, exynos_mali_match);
#endif

static struct platform_driver kbase_platform_driver = {
	.probe = kbase_platform_device_probe,
	.remove = kbase_platform_device_remove,
	.driver = {
		   .name = kbase_drv_name,
		   .owner = THIS_MODULE,
		   .pm = &kbase_pm_ops,
		   /* MALI_SEC_INTEGRATION */
		   .of_match_table = exynos_mali_match, /* .of_match_table = of_match_ptr(kbase_dt_ids), */
	},
};

/*
 * The driver will not provide a shortcut to create the Mali platform device
 * anymore when using Device Tree.
 */
#ifdef CONFIG_OF
module_platform_driver(kbase_platform_driver);
#else

static int __init kbase_driver_init(void)
{
	int ret;

	ret = kbase_platform_early_init();
	if (ret)
		return ret;

#ifndef CONFIG_MACH_MANTA
#ifdef CONFIG_MALI_PLATFORM_FAKE
	ret = kbase_platform_fake_register();
	if (ret)
		return ret;
#endif
#endif
	ret = platform_driver_register(&kbase_platform_driver);
#ifndef CONFIG_MACH_MANTA
#ifdef CONFIG_MALI_PLATFORM_FAKE
	if (ret)
		kbase_platform_fake_unregister();
#endif
#endif
	return ret;
}

static void __exit kbase_driver_exit(void)
{
	platform_driver_unregister(&kbase_platform_driver);
#ifndef CONFIG_MACH_MANTA
#ifdef CONFIG_MALI_PLATFORM_FAKE
	kbase_platform_fake_unregister();
#endif
#endif
}

module_init(kbase_driver_init);
module_exit(kbase_driver_exit);

#endif /* CONFIG_OF */

MODULE_LICENSE("GPL");
MODULE_VERSION(MALI_RELEASE_NAME " (UK version " \
		__stringify(BASE_UK_VERSION_MAJOR) "." \
		__stringify(BASE_UK_VERSION_MINOR) ")");

#if defined(CONFIG_MALI_GATOR_SUPPORT) || defined(CONFIG_MALI_SYSTEM_TRACE)
#define CREATE_TRACE_POINTS
#endif

#ifdef CONFIG_MALI_GATOR_SUPPORT
/* Create the trace points (otherwise we just get code to call a tracepoint) */
#include "mali_linux_trace.h"

EXPORT_TRACEPOINT_SYMBOL_GPL(mali_job_slots_event);
EXPORT_TRACEPOINT_SYMBOL_GPL(mali_pm_status);
EXPORT_TRACEPOINT_SYMBOL_GPL(mali_pm_power_on);
EXPORT_TRACEPOINT_SYMBOL_GPL(mali_pm_power_off);
EXPORT_TRACEPOINT_SYMBOL_GPL(mali_page_fault_insert_pages);
EXPORT_TRACEPOINT_SYMBOL_GPL(mali_mmu_as_in_use);
EXPORT_TRACEPOINT_SYMBOL_GPL(mali_mmu_as_released);
EXPORT_TRACEPOINT_SYMBOL_GPL(mali_total_alloc_pages_change);
EXPORT_TRACEPOINT_SYMBOL_GPL(mali_sw_counter);

void kbase_trace_mali_pm_status(u32 event, u64 value)
{
	trace_mali_pm_status(event, value);
}

void kbase_trace_mali_pm_power_off(u32 event, u64 value)
{
	trace_mali_pm_power_off(event, value);
}

void kbase_trace_mali_pm_power_on(u32 event, u64 value)
{
	trace_mali_pm_power_on(event, value);
}

void kbase_trace_mali_job_slots_event(u32 event, const struct kbase_context *kctx, u8 atom_id)
{
	trace_mali_job_slots_event(event, (kctx != NULL ? kctx->tgid : 0), (kctx != NULL ? kctx->pid : 0), atom_id);
}

void kbase_trace_mali_page_fault_insert_pages(int event, u32 value)
{
	trace_mali_page_fault_insert_pages(event, value);
}

void kbase_trace_mali_mmu_as_in_use(int event)
{
	trace_mali_mmu_as_in_use(event);
}

void kbase_trace_mali_mmu_as_released(int event)
{
	trace_mali_mmu_as_released(event);
}

void kbase_trace_mali_total_alloc_pages_change(long long int event)
{
	trace_mali_total_alloc_pages_change(event);
}
#endif /* CONFIG_MALI_GATOR_SUPPORT */
#ifdef CONFIG_MALI_SYSTRACE_SUPPORT
/*{ SRUK-MALI_SYSTRACE_SUPPORT*/
// Create the trace points (otherwise we just get code to call a tracepoint)
#define CREATE_TRACE_POINTS
#include "mali_linux_systrace.h"
/**
 * Called on job events to trigger ftrace logging
 * Pass the even type, job slot, context, atom_id (job identifier in a context?), job start timestamp (this is unique and used to track the job)
 */
void kbase_systrace_mali_job_slots_event(u8 job_event, u8 job_slot, const struct kbase_context *kctx, u8 atom_id, u64 start_timestamp, u8 dep_0_id, u8 dep_0_type, u8 dep_1_id, u8 dep_1_type, u32 gles_ctx_handle)
{
    {
            unsigned int unit;
            char job_name[32];

            switch (job_slot) {
            case 0:
                    unit = GPU_UNIT_FP;
                    strcpy(job_name, "fragment-job");
                    break;
            case 1:
                    unit = GPU_UNIT_VP;
                    strcpy(job_name, "vertex-job");
                    break;
            case 2:
                    unit = GPU_UNIT_CL;
                    strcpy(job_name, "compute-job");
                    break;
            default:
                    unit = GPU_UNIT_NONE;
            }

            if (unit != GPU_UNIT_NONE) {
                    switch (job_event) {
                    case SYSTRACE_EVENT_TYPE_START:
                            trace_mali_job_systrace_event_start(job_name, (kctx != NULL ? kctx->tgid : 0), (kctx != NULL ? kctx->pid : 0),
                                                                atom_id, (kctx != NULL ? kctx->id : 0), (kctx != NULL ? kctx->cookies : 0),
                                                                start_timestamp, dep_0_id, dep_0_type, dep_1_id, dep_1_type, gles_ctx_handle);
                            break;
                    case SYSTRACE_EVENT_TYPE_STOP:
                    default: // Some jobs can be soft-stopped, so ensure that this terminates the activity trace.
                            trace_mali_job_systrace_event_stop(job_name, (kctx != NULL ? kctx->tgid : 0), (kctx != NULL ? kctx->id : 0),
                                                               atom_id, (kctx != NULL ? kctx->id : 0), (kctx != NULL ? kctx->cookies : 0),
                                                               start_timestamp, dep_0_id, dep_0_type, dep_1_id, dep_1_type, gles_ctx_handle);
                            break;
                    }
            }
    }

}
#endif /* CONFIG_MALI_SYSTRACE_SUPPORT */
/* SRUK-MALI_SYSTRACE_SUPPORT }*/
#ifdef CONFIG_MALI_SYSTEM_TRACE
#include "mali_linux_kbase_trace.h"
#endif
