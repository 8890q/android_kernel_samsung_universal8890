/* drivers/misc/lowmemorykiller.c
 *
 * The lowmemorykiller driver lets user-space specify a set of memory thresholds
 * where processes with a range of oom_score_adj values will get killed. Specify
 * the minimum oom_score_adj values in
 * /sys/module/lowmemorykiller/parameters/adj and the number of free pages in
 * /sys/module/lowmemorykiller/parameters/minfree. Both files take a comma
 * separated list of numbers in ascending order.
 *
 * For example, write "0,8" to /sys/module/lowmemorykiller/parameters/adj and
 * "1024,4096" to /sys/module/lowmemorykiller/parameters/minfree to kill
 * processes with a oom_score_adj value of 8 or higher when the free memory
 * drops below 4096 pages and kill processes with a oom_score_adj value of 0 or
 * higher when the free memory drops below 1024 pages.
 *
 * The driver considers memory used for caches to be free, but if a large
 * percentage of the cached memory is locked this can be very inaccurate
 * and processes may not get killed until the normal oom killer is triggered.
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/oom.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/rcupdate.h>
#include <linux/notifier.h>
#include <linux/delay.h>

#define CREATE_TRACE_POINTS
#include "trace/lowmemorykiller.h"

static uint32_t lowmem_debug_level = 1;
static short lowmem_adj[6] = {
	0,
	1,
	6,
	12,
};
static int lowmem_adj_size = 4;
static int lowmem_minfree[6] = {
	3 * 512,	/* 6MB */
	2 * 1024,	/* 8MB */
	4 * 1024,	/* 16MB */
	16 * 1024,	/* 64MB */
};
static int lowmem_minfree_size = 4;
static uint32_t lowmem_lmkcount = 0;
static int lmkd_count;
static int lmkd_cricount;

static unsigned long lowmem_deathpending_timeout;

#define lowmem_print(level, x...)			\
	do {						\
		if (lowmem_debug_level >= (level))	\
			pr_info(x);			\
	} while (0)

#if defined(CONFIG_ZSWAP)
extern u64 zswap_pool_pages;
extern atomic_t zswap_stored_pages;
#endif

static int test_task_flag(struct task_struct *p, int flag)
{
	struct task_struct *t = p;

	do {
		task_lock(t);
		if (test_tsk_thread_flag(t, flag)) {
			task_unlock(t);
			return 1;
		}
		task_unlock(t);
	} while_each_thread(p, t);

	return 0;
}

static void show_memory(void)
{
	unsigned long nr_rbin_free, nr_rbin_pool, nr_rbin_alloc, nr_rbin_file;

	nr_rbin_free = global_page_state(NR_FREE_RBIN_PAGES);
	nr_rbin_pool = atomic_read(&rbin_pool_pages);
	nr_rbin_alloc = atomic_read(&rbin_allocated_pages);
	nr_rbin_file = totalrbin_pages - nr_rbin_free - nr_rbin_pool
					- nr_rbin_alloc;

#define K(x) ((x) << (PAGE_SHIFT - 10))
	printk("Mem-Info:"
		" totalram_pages:%lukB"
		" free:%lukB"
		" active_anon:%lukB"
		" inactive_anon:%lukB"
		" active_file:%lukB"
		" inactive_file:%lukB"
		" unevictable:%lukB"
		" isolated(anon):%lukB"
		" isolated(file):%lukB"
		" dirty:%lukB"
		" writeback:%lukB"
		" mapped:%lukB"
		" shmem:%lukB"
		" slab_reclaimable:%lukB"
		" slab_unreclaimable:%lukB"
		" kernel_stack:%lukB"
		" pagetables:%lukB"
		" free_cma:%lukB"
		" rbin_free:%lukB"
		" rbin_pool:%lukB"
		" rbin_alloc:%lukB"
		" rbin_file:%lukB"
		"\n",
		K(totalram_pages),
		K(global_page_state(NR_FREE_PAGES)),
		K(global_page_state(NR_ACTIVE_ANON)),
		K(global_page_state(NR_INACTIVE_ANON)),
		K(global_page_state(NR_ACTIVE_FILE)),
		K(global_page_state(NR_INACTIVE_FILE)),
		K(global_page_state(NR_UNEVICTABLE)),
		K(global_page_state(NR_ISOLATED_ANON)),
		K(global_page_state(NR_ISOLATED_FILE)),
		K(global_page_state(NR_FILE_DIRTY)),
		K(global_page_state(NR_WRITEBACK)),
		K(global_page_state(NR_FILE_MAPPED)),
		K(global_page_state(NR_SHMEM)),
		K(global_page_state(NR_SLAB_RECLAIMABLE)),
		K(global_page_state(NR_SLAB_UNRECLAIMABLE)),
		K(global_page_state(NR_KERNEL_STACK)),
		K(global_page_state(NR_PAGETABLE)),
		K(global_page_state(NR_FREE_CMA_PAGES)),
		K(nr_rbin_free),
		K(nr_rbin_pool),
		K(nr_rbin_alloc),
		K(nr_rbin_file)
		);
#undef K
}

static unsigned long lowmem_count(struct shrinker *s,
				  struct shrink_control *sc)
{
	return global_page_state(NR_ACTIVE_ANON) +
		global_page_state(NR_ACTIVE_FILE) +
		global_page_state(NR_INACTIVE_ANON) +
		global_page_state(NR_INACTIVE_FILE);
}

static unsigned long lowmem_scan(struct shrinker *s, struct shrink_control *sc)
{
	struct task_struct *tsk;
	struct task_struct *selected = NULL;
	unsigned long rem = 0;
	int tasksize;
	int i;
	short min_score_adj = OOM_SCORE_ADJ_MAX + 1;
	int minfree = 0;
	int selected_tasksize = 0;
	short selected_oom_score_adj;
	int array_size = ARRAY_SIZE(lowmem_adj);
	int other_free = global_page_state(NR_FREE_PAGES) - totalreserve_pages;
	int other_file = global_page_state(NR_FILE_PAGES) -
						global_page_state(NR_SHMEM) -
						global_page_state(NR_UNEVICTABLE) -
						total_swapcache_pages();
	struct reclaim_state *reclaim_state = current->reclaim_state;
	unsigned long nr_rbin_free, nr_rbin_pool, nr_rbin_alloc, nr_rbin_file;

	if ((sc->gfp_mask & __GFP_RBIN) != __GFP_RBIN) {
		nr_rbin_free = global_page_state(NR_FREE_RBIN_PAGES);
		nr_rbin_pool = atomic_read(&rbin_pool_pages);
		nr_rbin_alloc = atomic_read(&rbin_allocated_pages);
		nr_rbin_file = totalrbin_pages - nr_rbin_free - nr_rbin_pool
						- nr_rbin_alloc;
		other_free -= nr_rbin_free;
		other_file -= nr_rbin_file;
	}
#ifdef CONFIG_CMA
	other_free -= global_page_state(NR_FREE_CMA_PAGES);
#endif
	if (lowmem_adj_size < array_size)
		array_size = lowmem_adj_size;
	if (lowmem_minfree_size < array_size)
		array_size = lowmem_minfree_size;
	for (i = 0; i < array_size; i++) {
		minfree = lowmem_minfree[i];
		if (other_free < minfree && other_file < minfree) {
			min_score_adj = lowmem_adj[i];
			break;
		}
	}

	lowmem_print(3, "lowmem_scan %lu, %x, ofree %d %d, ma %hd\n",
			sc->nr_to_scan, sc->gfp_mask, other_free,
			other_file, min_score_adj);

	if (min_score_adj == OOM_SCORE_ADJ_MAX + 1) {
		lowmem_print(5, "lowmem_scan %lu, %x, return 0\n",
			     sc->nr_to_scan, sc->gfp_mask);
		return 0;
	}

	selected_oom_score_adj = min_score_adj;

	rcu_read_lock();
	for_each_process(tsk) {
		struct task_struct *p;
		short oom_score_adj;

		if (tsk->flags & PF_KTHREAD)
			continue;

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
		if (test_task_flag(tsk, TIF_MEMALLOC))
			continue;
#endif
		p = find_lock_task_mm(tsk);
		if (!p)
			continue;

		if (test_tsk_thread_flag(p, TIF_MEMDIE) &&
		    time_before_eq(jiffies, lowmem_deathpending_timeout)) {
			task_unlock(p);
			rcu_read_unlock();
			/* give the system time to free up the memory */
			msleep_interruptible(20);
			return 0;
		}
		oom_score_adj = p->signal->oom_score_adj;
		if (oom_score_adj < min_score_adj) {
			task_unlock(p);
			continue;
		}
		tasksize = get_mm_rss(p->mm);
#if defined(CONFIG_ZSWAP)
		if (atomic_read(&zswap_stored_pages)) {
			lowmem_print(3, "shown tasksize : %d\n", tasksize);
			tasksize += (int)zswap_pool_pages * get_mm_counter(p->mm, MM_SWAPENTS)
				/ atomic_read(&zswap_stored_pages);
			lowmem_print(3, "real tasksize : %d\n", tasksize);
		}
#endif

		task_unlock(p);
		if (tasksize <= 0)
			continue;
		if (same_thread_group(p, current))
			continue;
		if (selected) {
			if (oom_score_adj < selected_oom_score_adj)
				continue;
			if (oom_score_adj == selected_oom_score_adj &&
			    tasksize <= selected_tasksize)
				continue;
		}
		selected = p;
		selected_tasksize = tasksize;
		selected_oom_score_adj = oom_score_adj;
		lowmem_print(2, "select '%s' (%d), adj %hd, size %d, to kill\n",
			     p->comm, p->pid, oom_score_adj, tasksize);
	}
	if (selected) {
		long cache_size = other_file * (long)(PAGE_SIZE / 1024);
		long cache_limit = minfree * (long)(PAGE_SIZE / 1024);
		long free = other_free * (long)(PAGE_SIZE / 1024);
		trace_lowmemory_kill(selected, cache_size, cache_limit, free);
		lowmem_print(1, "Killing '%s' (%d), adj %hd,\n" \
				"   to free %ldkB on behalf of '%s' (%d) because\n" \
				"   cache %ldkB is below limit %ldkB for oom_score_adj %hd\n" \
				"   Free memory is %ldkB above reserved\n",
			     selected->comm, selected->pid,
			     selected_oom_score_adj,
			     selected_tasksize * (long)(PAGE_SIZE / 1024),
			     current->comm, current->pid,
			     cache_size, cache_limit,
			     min_score_adj,
			     free);
		show_memory();
		lowmem_deathpending_timeout = jiffies + HZ;
		set_tsk_thread_flag(selected, TIF_MEMDIE);
		send_sig(SIGKILL, selected, 0);
		rem += selected_tasksize;
		lowmem_lmkcount++;
		rcu_read_unlock();
		/* give the system time to free up the memory */
		msleep_interruptible(20);

		if (reclaim_state)
			reclaim_state->reclaimed_slab += selected_tasksize;
	} else {
		rcu_read_unlock();
	}

	lowmem_print(4, "lowmem_scan %lu, %x, return %lu\n",
		     sc->nr_to_scan, sc->gfp_mask, rem);
	return rem;
}

static struct shrinker lowmem_shrinker = {
	.scan_objects = lowmem_scan,
	.count_objects = lowmem_count,
	.seeks = DEFAULT_SEEKS * 16
};

static int __init lowmem_init(void)
{
	register_shrinker(&lowmem_shrinker);
	return 0;
}

static void __exit lowmem_exit(void)
{
	unregister_shrinker(&lowmem_shrinker);
}

#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES
static short lowmem_oom_adj_to_oom_score_adj(short oom_adj)
{
	if (oom_adj == OOM_ADJUST_MAX)
		return OOM_SCORE_ADJ_MAX;
	else
		return (oom_adj * OOM_SCORE_ADJ_MAX) / -OOM_DISABLE;
}

static void lowmem_autodetect_oom_adj_values(void)
{
	int i;
	short oom_adj;
	short oom_score_adj;
	int array_size = ARRAY_SIZE(lowmem_adj);

	if (lowmem_adj_size < array_size)
		array_size = lowmem_adj_size;

	if (array_size <= 0)
		return;

	oom_adj = lowmem_adj[array_size - 1];
	if (oom_adj > OOM_ADJUST_MAX)
		return;

	oom_score_adj = lowmem_oom_adj_to_oom_score_adj(oom_adj);
	if (oom_score_adj <= OOM_ADJUST_MAX)
		return;

	lowmem_print(1, "lowmem_shrink: convert oom_adj to oom_score_adj:\n");
	for (i = 0; i < array_size; i++) {
		oom_adj = lowmem_adj[i];
		oom_score_adj = lowmem_oom_adj_to_oom_score_adj(oom_adj);
		lowmem_adj[i] = oom_score_adj;
		lowmem_print(1, "oom_adj %d => oom_score_adj %d\n",
			     oom_adj, oom_score_adj);
	}
}

static int lowmem_adj_array_set(const char *val, const struct kernel_param *kp)
{
	int ret;

	ret = param_array_ops.set(val, kp);

	/* HACK: Autodetect oom_adj values in lowmem_adj array */
	lowmem_autodetect_oom_adj_values();

	return ret;
}

static int lowmem_adj_array_get(char *buffer, const struct kernel_param *kp)
{
	return param_array_ops.get(buffer, kp);
}

static void lowmem_adj_array_free(void *arg)
{
	param_array_ops.free(arg);
}

static struct kernel_param_ops lowmem_adj_array_ops = {
	.set = lowmem_adj_array_set,
	.get = lowmem_adj_array_get,
	.free = lowmem_adj_array_free,
};

static const struct kparam_array __param_arr_adj = {
	.max = ARRAY_SIZE(lowmem_adj),
	.num = &lowmem_adj_size,
	.ops = &param_ops_short,
	.elemsize = sizeof(lowmem_adj[0]),
	.elem = lowmem_adj,
};
#endif

module_param_named(cost, lowmem_shrinker.seeks, int, S_IRUGO | S_IWUSR);
#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES
module_param_cb(adj, &lowmem_adj_array_ops,
		.arr = &__param_arr_adj, S_IRUGO | S_IWUSR);
__MODULE_PARM_TYPE(adj, "array of short");
#else
module_param_array_named(adj, lowmem_adj, short, &lowmem_adj_size,
			 S_IRUGO | S_IWUSR);
#endif
module_param_array_named(minfree, lowmem_minfree, uint, &lowmem_minfree_size,
			 S_IRUGO | S_IWUSR);
module_param_named(debug_level, lowmem_debug_level, uint, S_IRUGO | S_IWUSR);
module_param_named(lmkcount, lowmem_lmkcount, uint, S_IRUGO);
module_param_named(lmkd_count, lmkd_count, int, 0644);
module_param_named(lmkd_cricount, lmkd_cricount, int, 0644);

module_init(lowmem_init);
module_exit(lowmem_exit);

MODULE_LICENSE("GPL");

