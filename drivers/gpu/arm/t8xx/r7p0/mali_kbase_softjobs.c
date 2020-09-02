/*
 *
 * (C) COPYRIGHT 2011-2015 ARM Limited. All rights reserved.
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

#include <linux/dma-mapping.h>
#ifdef CONFIG_SYNC
#include "sync.h"
#include <linux/syscalls.h>
#include "mali_kbase_sync.h"
#endif
#include <mali_kbase_hwaccess_time.h>
#include <linux/version.h>

/* Mask to check cache alignment of data structures */
#define KBASE_CACHE_ALIGNMENT_MASK		((1<<L1_CACHE_SHIFT)-1)

/**
 * @file mali_kbase_softjobs.c
 *
 * This file implements the logic behind software only jobs that are
 * executed within the driver rather than being handed over to the GPU.
 */

static int kbase_dump_cpu_gpu_time(struct kbase_jd_atom *katom)
{
	struct kbase_va_region *reg;
	phys_addr_t addr = 0;
	u64 pfn;
	u32 offset;
	char *page;
	struct timespec ts;
	struct base_dump_cpu_gpu_counters data;
	u64 system_time;
	u64 cycle_counter;
	u64 jc = katom->jc;
	struct kbase_context *kctx = katom->kctx;
	int pm_active_err;

	memset(&data, 0, sizeof(data));

	/* Take the PM active reference as late as possible - otherwise, it could
	 * delay suspend until we process the atom (which may be at the end of a
	 * long chain of dependencies */
	pm_active_err = kbase_pm_context_active_handle_suspend(kctx->kbdev, KBASE_PM_SUSPEND_HANDLER_DONT_REACTIVATE);
	if (pm_active_err) {
		struct kbasep_js_device_data *js_devdata = &kctx->kbdev->js_data;

		/* We're suspended - queue this on the list of suspended jobs
		 * Use dep_item[1], because dep_item[0] is in use for 'waiting_soft_jobs' */
		mutex_lock(&js_devdata->runpool_mutex);
		list_add_tail(&katom->dep_item[1], &js_devdata->suspended_soft_jobs_list);
		mutex_unlock(&js_devdata->runpool_mutex);

		return pm_active_err;
	}

	kbase_backend_get_gpu_time(kctx->kbdev, &cycle_counter, &system_time,
									&ts);

	kbase_pm_context_idle(kctx->kbdev);

	data.sec = ts.tv_sec;
	data.usec = ts.tv_nsec / 1000;
	data.system_time = system_time;
	data.cycle_counter = cycle_counter;

	pfn = jc >> PAGE_SHIFT;
	offset = jc & ~PAGE_MASK;

	/* Assume this atom will be cancelled until we know otherwise */
	katom->event_code = BASE_JD_EVENT_JOB_CANCELLED;
	if (offset > 0x1000 - sizeof(data)) {
		/* Wouldn't fit in the page */
		return 0;
	}

	kbase_gpu_vm_lock(kctx);
	reg = kbase_region_tracker_find_region_enclosing_address(kctx, jc);
	if (reg &&
	    (reg->flags & KBASE_REG_GPU_WR) &&
	    reg->cpu_alloc && reg->cpu_alloc->pages)
		addr = reg->cpu_alloc->pages[pfn - reg->start_pfn];

	kbase_gpu_vm_unlock(kctx);
	if (!addr)
		return 0;

	page = kmap(pfn_to_page(PFN_DOWN(addr)));
	if (!page)
		return 0;

	kbase_sync_single_for_cpu(katom->kctx->kbdev,
			kbase_dma_addr(pfn_to_page(PFN_DOWN(addr))) +
			offset, sizeof(data),
			DMA_BIDIRECTIONAL);

	memcpy(page + offset, &data, sizeof(data));

	kbase_sync_single_for_device(katom->kctx->kbdev,
			kbase_dma_addr(pfn_to_page(PFN_DOWN(addr))) +
			offset, sizeof(data),
			DMA_BIDIRECTIONAL);

	kunmap(pfn_to_page(PFN_DOWN(addr)));

	/* Atom was fine - mark it as done */
	katom->event_code = BASE_JD_EVENT_DONE;

	return 0;
}

#ifdef CONFIG_SYNC

/* Complete an atom that has returned '1' from kbase_process_soft_job (i.e. has waited)
 *
 * @param katom     The atom to complete
 */
static void complete_soft_job(struct kbase_jd_atom *katom)
{
	struct kbase_context *kctx = katom->kctx;
/* MALI_SEC_INTEGRATION */
	struct list_head *entry = (struct list_head *)&katom->dep_item[0];

	mutex_lock(&kctx->jctx.lock);
/* MALI_SEC_INTEGRATION */
	/* Do not delete from list if item was removed already */
	if (!(entry->prev == LIST_POISON2 || entry->next == LIST_POISON1))
		list_del(&katom->dep_item[0]);

	kbase_finish_soft_job(katom);
	if (jd_done_nolock(katom, NULL))
		kbase_js_sched_all(kctx->kbdev);
	mutex_unlock(&kctx->jctx.lock);
}

static enum base_jd_event_code kbase_fence_trigger(struct kbase_jd_atom *katom, int result)
{
	struct sync_pt *pt;
	struct sync_timeline *timeline;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
	if (!list_is_singular(&katom->fence->pt_list_head)) {
#else
	if (katom->fence->num_fences != 1) {
#endif
		/* Not exactly one item in the list - so it didn't (directly) come from us */
		return BASE_JD_EVENT_JOB_CANCELLED;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
	pt = list_first_entry(&katom->fence->pt_list_head, struct sync_pt, pt_list);
#else
	pt = container_of(katom->fence->cbs[0].sync_pt, struct sync_pt, base);
#endif
	timeline = sync_pt_parent(pt);

	if (!kbase_sync_timeline_is_ours(timeline)) {
		/* Fence has a sync_pt which isn't ours! */
		return BASE_JD_EVENT_JOB_CANCELLED;
	}

	/* MALI_SEC_INTEGRATION */
	//kbase_sync_signal_pt(pt, result);
	kbase_sync_signal_pt(pt, 0);

	sync_timeline_signal(timeline);

	return (result < 0) ? BASE_JD_EVENT_JOB_CANCELLED : BASE_JD_EVENT_DONE;
}

static void kbase_fence_wait_worker(struct work_struct *data)
{
	struct kbase_jd_atom *katom;
	struct kbase_context *kctx;

	katom = container_of(data, struct kbase_jd_atom, work);
	kctx = katom->kctx;

	complete_soft_job(katom);
}

static void kbase_fence_wait_callback(struct sync_fence *fence, struct sync_fence_waiter *waiter)
{
	struct kbase_jd_atom *katom = container_of(waiter, struct kbase_jd_atom, sync_waiter);
	struct kbase_context *kctx;

	KBASE_DEBUG_ASSERT(NULL != katom);

	kctx = katom->kctx;

	KBASE_DEBUG_ASSERT(NULL != kctx);

	/* Propagate the fence status to the atom.
	 * If negative then cancel this atom and its dependencies.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
	if (fence->status < 0)
#else
	if (atomic_read(&fence->status) < 0)
#endif
		katom->event_code = BASE_JD_EVENT_JOB_CANCELLED;

	/* To prevent a potential deadlock we schedule the work onto the job_done_wq workqueue
	 *
	 * The issue is that we may signal the timeline while holding kctx->jctx.lock and
	 * the callbacks are run synchronously from sync_timeline_signal. So we simply defer the work.
	 */

	KBASE_DEBUG_ASSERT(0 == object_is_on_stack(&katom->work));
	INIT_WORK(&katom->work, kbase_fence_wait_worker);
	queue_work(kctx->jctx.job_done_wq, &katom->work);
}

static int kbase_fence_wait(struct kbase_jd_atom *katom)
{
	int ret;

	KBASE_DEBUG_ASSERT(NULL != katom);
	KBASE_DEBUG_ASSERT(NULL != katom->kctx);

	sync_fence_waiter_init(&katom->sync_waiter, kbase_fence_wait_callback);

	ret = sync_fence_wait_async(katom->fence, &katom->sync_waiter);

	if (ret == 1) {
		/* Already signalled */
		return 0;
	} else if (ret < 0) {
		goto cancel_atom;
	}
/* MALI_SEC_INTEGRATION */
{
	struct kbase_context *kctx = katom->kctx;
	struct kbase_device *kbdev = kctx->kbdev;

	if(kbdev->vendor_callbacks->fence_timer_init)
		kbdev->vendor_callbacks->fence_timer_init(katom);
}

	return 1;

 cancel_atom:
	katom->event_code = BASE_JD_EVENT_JOB_CANCELLED;
	/* We should cause the dependant jobs in the bag to be failed,
	 * to do this we schedule the work queue to complete this job */
	KBASE_DEBUG_ASSERT(0 == object_is_on_stack(&katom->work));
	INIT_WORK(&katom->work, kbase_fence_wait_worker);
	queue_work(katom->kctx->jctx.job_done_wq, &katom->work);
	return 1;
}

static void kbase_fence_cancel_wait(struct kbase_jd_atom *katom)
{
	if (sync_fence_cancel_async(katom->fence, &katom->sync_waiter) != 0) {
		/* The wait wasn't cancelled - leave the cleanup for kbase_fence_wait_callback */
		return;
	}

	/* Wait was cancelled - zap the atoms */
	katom->event_code = BASE_JD_EVENT_JOB_CANCELLED;

	kbase_finish_soft_job(katom);

	if (jd_done_nolock(katom, NULL))
		kbase_js_sched_all(katom->kctx->kbdev);
}
#endif /* CONFIG_SYNC */

int kbase_process_soft_job(struct kbase_jd_atom *katom)
{
	unsigned long flags;

	switch (katom->core_req & BASEP_JD_REQ_ATOM_TYPE) {
	case BASE_JD_REQ_SOFT_DUMP_CPU_GPU_TIME:
		return kbase_dump_cpu_gpu_time(katom);
#ifdef CONFIG_SYNC
	case BASE_JD_REQ_SOFT_FENCE_TRIGGER:
		KBASE_DEBUG_ASSERT(katom->fence != NULL);
		katom->event_code = kbase_fence_trigger(katom, katom->event_code == BASE_JD_EVENT_DONE ? 0 : -EFAULT);
		/* Release the reference as we don't need it any more */
		sync_fence_put(katom->fence);
/* MALI_SEC_INTEGRATION */
		spin_lock_irqsave(&katom->fence_lock, flags);
		katom->fence = NULL;
		spin_unlock_irqrestore(&katom->fence_lock, flags);
		break;
	case BASE_JD_REQ_SOFT_FENCE_WAIT:
		return kbase_fence_wait(katom);
#endif				/* CONFIG_SYNC */
	case BASE_JD_REQ_SOFT_REPLAY:
		return kbase_replay_process(katom);
#ifdef CONFIG_MALI_DVFS_USER
	case BASE_JD_REQ_SOFT_DVFS:
		if(katom->kctx->kbdev->vendor_callbacks->dvfs_process_job) {
			if (katom->kctx->kbdev->vendor_callbacks->dvfs_process_job(katom)) {
				katom->event_code = BASE_JD_EVENT_DVFS_EVENT;
			}
		}
		break;
#endif
	}

	/* Atom is complete */
	return 0;
}

void kbase_cancel_soft_job(struct kbase_jd_atom *katom)
{
/* MALI_SEC_INTEGRATION */
	pgd_t *pgd;
	struct mm_struct *mm = katom->kctx->process_mm;

	pgd = pgd_offset(mm, (unsigned long)katom);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		printk("Abnormal katom\n");
		printk("katom->kctx: 0x%p, katom->kctx->tgid: %d, katom->kctx->process_mm: 0x%p, pgd: 0x%px\n", katom->kctx, katom->kctx->tgid, katom->kctx->process_mm, pgd);
		return;
	}

	switch (katom->core_req & BASEP_JD_REQ_ATOM_TYPE) {
#ifdef CONFIG_SYNC
	case BASE_JD_REQ_SOFT_FENCE_WAIT:
		kbase_fence_cancel_wait(katom);
		break;
#endif
#ifdef CONFIG_MALI_DVFS_USER
	case BASE_JD_REQ_SOFT_DVFS:
		break;
#endif
	default:
		/* This soft-job doesn't support cancellation! */
		KBASE_DEBUG_ASSERT(0);
	}
}

int kbase_prepare_soft_job(struct kbase_jd_atom *katom)
{
	unsigned long flags;

	switch (katom->core_req & BASEP_JD_REQ_ATOM_TYPE) {
	case BASE_JD_REQ_SOFT_DUMP_CPU_GPU_TIME:
		{
			if (0 != (katom->jc & KBASE_CACHE_ALIGNMENT_MASK))
				return -EINVAL;
		}
		break;
#ifdef CONFIG_SYNC
	case BASE_JD_REQ_SOFT_FENCE_TRIGGER:
		{
			struct base_fence fence;
			int fd;

			if (0 != copy_from_user(&fence, (__user void *)(uintptr_t) katom->jc, sizeof(fence)))
				return -EINVAL;

			fd = kbase_stream_create_fence(fence.basep.stream_fd);
			if (fd < 0)
				return -EINVAL;

			katom->fence = sync_fence_fdget(fd);

			if (katom->fence == NULL) {
				/* The only way the fence can be NULL is if userspace closed it for us.
				 * So we don't need to clear it up */
				return -EINVAL;
			}
			fence.basep.fd = fd;
			if (0 != copy_to_user((__user void *)(uintptr_t) katom->jc, &fence, sizeof(fence))) {
				spin_lock_irqsave(&katom->fence_lock, flags);
				katom->fence = NULL;
				spin_unlock_irqrestore(&katom->fence_lock, flags);
				sys_close(fd);
				return -EINVAL;
			}
		}
		break;
	case BASE_JD_REQ_SOFT_FENCE_WAIT:
		{
			struct base_fence fence;

			if (0 != copy_from_user(&fence, (__user void *)(uintptr_t) katom->jc, sizeof(fence)))
				return -EINVAL;

			/* Get a reference to the fence object */
			katom->fence = sync_fence_fdget(fence.basep.fd);
			if (katom->fence == NULL)
				return -EINVAL;
		}
		break;
#endif				/* CONFIG_SYNC */
	case BASE_JD_REQ_SOFT_REPLAY:
		break;
#ifdef CONFIG_MALI_DVFS_USER
	case BASE_JD_REQ_SOFT_DVFS:
		break;
#endif
	default:
		/* Unsupported soft-job */
		return -EINVAL;
	}
	return 0;
}

void kbase_finish_soft_job(struct kbase_jd_atom *katom)
{
	unsigned long flags;

	switch (katom->core_req & BASEP_JD_REQ_ATOM_TYPE) {
	case BASE_JD_REQ_SOFT_DUMP_CPU_GPU_TIME:
		/* Nothing to do */
		break;
#ifdef CONFIG_SYNC
	case BASE_JD_REQ_SOFT_FENCE_TRIGGER:
		/* If fence has not yet been signalled, do it now */
		if (katom->fence) {
			kbase_fence_trigger(katom, katom->event_code ==
					BASE_JD_EVENT_DONE ? 0 : -EFAULT);
			sync_fence_put(katom->fence);

			spin_lock_irqsave(&katom->fence_lock, flags);
			katom->fence = NULL;
			spin_unlock_irqrestore(&katom->fence_lock, flags);
		}
		break;
	case BASE_JD_REQ_SOFT_FENCE_WAIT:
/* MALI_SEC_INTEGRATION */
#ifdef MALI_SEC_FENCE_INTEGRATION
		if (katom->fence) {
			sync_fence_put(katom->fence);
			spin_lock_irqsave(&katom->fence_lock, flags);
			katom->fence = NULL;
			spin_unlock_irqrestore(&katom->fence_lock, flags);
		}

		{
			struct kbase_context *kctx = katom->kctx;
			struct kbase_device *kbdev = kctx->kbdev;

			if(kbdev->vendor_callbacks->fence_del_timer)
				kbdev->vendor_callbacks->fence_del_timer(katom);
		}
#else
		/* Release the reference to the fence object */
		sync_fence_put(katom->fence);
		spin_lock_irqsave(&katom->fence_lock, flags);
		katom->fence = NULL;
		spin_unlock_irqrestore(&katom->fence_lock, flags);
#endif
		break;
#endif				/* CONFIG_SYNC */
#ifdef CONFIG_MALI_DVFS_USER
	case BASE_JD_REQ_SOFT_DVFS:
		break;
#endif
	}
}

void kbase_resume_suspended_soft_jobs(struct kbase_device *kbdev)
{
	LIST_HEAD(local_suspended_soft_jobs);
	struct kbase_jd_atom *tmp_iter;
	struct kbase_jd_atom *katom_iter;
	struct kbasep_js_device_data *js_devdata;
	bool resched = false;

	KBASE_DEBUG_ASSERT(kbdev);

	js_devdata = &kbdev->js_data;

	/* Move out the entire list */
	mutex_lock(&js_devdata->runpool_mutex);
	list_splice_init(&js_devdata->suspended_soft_jobs_list,
			&local_suspended_soft_jobs);
	mutex_unlock(&js_devdata->runpool_mutex);

	/*
	 * Each atom must be detached from the list and ran separately -
	 * it could be re-added to the old list, but this is unlikely
	 */
	list_for_each_entry_safe(katom_iter, tmp_iter,
			&local_suspended_soft_jobs, dep_item[1]) {
		struct kbase_context *kctx = katom_iter->kctx;

		mutex_lock(&kctx->jctx.lock);

		/* Remove from the global list */
		list_del(&katom_iter->dep_item[1]);
		/* Remove from the context's list of waiting soft jobs */
		list_del(&katom_iter->dep_item[0]);

		if (kbase_process_soft_job(katom_iter) == 0) {
			kbase_finish_soft_job(katom_iter);
			resched |= jd_done_nolock(katom_iter, NULL);
		} else {
			/* The job has not completed */
			KBASE_DEBUG_ASSERT((katom_iter->core_req &
					BASEP_JD_REQ_ATOM_TYPE)
					!= BASE_JD_REQ_SOFT_REPLAY);
			list_add_tail(&katom_iter->dep_item[0],
					&kctx->waiting_soft_jobs);
		}

		mutex_unlock(&kctx->jctx.lock);
	}

	if (resched)
		kbase_js_sched_all(kbdev);
}
