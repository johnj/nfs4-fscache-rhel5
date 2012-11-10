/*
 * include/linux/backing-dev.h
 *
 * low-level device information and state which is propagated up through
 * to high-level code.
 */

#ifndef _LINUX_BACKING_DEV_H
#define _LINUX_BACKING_DEV_H

#include <asm/atomic.h>

/*
 * Bits in backing_dev_info.state
 */
enum bdi_state {
	BDI_pdflush,		/* A pdflush thread is working this device */
	BDI_pending,		/* On its way to being activated */
	BDI_wb_alloc,		/* Default embedded wb allocated */
	BDI_async_congested,	/* The async (write) queue is getting full */
	BDI_sync_congested,	/* The sync queue is getting full */
	BDI_registered,		/* bdi_register() was done */
	BDI_unused,		/* Available bits start here */
};

enum bdi_stat_item {
	BDI_RECLAIMABLE,
	BDI_WRITEBACK,
	NR_BDI_STAT_ITEMS
};

typedef int (congested_fn)(void *, int);

struct bdi_writeback {
	struct list_head list;			/* hangs off the bdi */

	struct backing_dev_info *bdi;		/* our parent bdi */
	unsigned int nr;

	unsigned long last_old_flush;		/* last old data flush */

	struct task_struct	*task;		/* writeback task */
	struct list_head	b_dirty;	/* dirty inodes */
	struct list_head	b_io;		/* parked for writeback */
	struct list_head	b_more_io;	/* parked for more writeback */
};

struct backing_dev_info {
	struct list_head bdi_list;
	struct rcu_head rcu_head;
	unsigned long ra_pages;	/* max readahead in PAGE_CACHE_SIZE units */
	unsigned long state;	/* Always use atomic bitops on this */
	unsigned int capabilities; /* Device capabilities */
	congested_fn *congested_fn; /* Function pointer if device is md/dm */
	void *congested_data;	/* Pointer to aux data for congested func */
	void (*unplug_io_fn)(struct backing_dev_info *, struct page *);
	void *unplug_io_data;

	char *name;

	int dirty_exceeded;

	unsigned int min_ratio;
	unsigned int max_ratio, max_prop_frac;

	struct bdi_writeback wb;  /* default writeback info for this bdi */
	spinlock_t wb_lock;	  /* protects update side of wb_list */
	struct list_head wb_list; /* the flusher threads hanging off this bdi */
	unsigned long wb_mask;	  /* bitmask of registered tasks */
	unsigned int wb_cnt;	  /* number of registered tasks */

	struct list_head work_list;

	struct device *dev;

#ifdef CONFIG_DEBUG_FS
	struct dentry *debug_dir;
	struct dentry *debug_stats;
#endif
};


/*
 * Flags in backing_dev_info::capability
 * - The first two flags control whether dirty pages will contribute to the
 *   VM's accounting and whether writepages() should be called for dirty pages
 *   (something that would not, for example, be appropriate for ramfs)
 * - These flags let !MMU mmap() govern direct device mapping vs immediate
 *   copying more easily for MAP_PRIVATE, especially for ROM filesystems
 */
#define BDI_CAP_NO_ACCT_DIRTY	0x00000001	/* Dirty pages shouldn't contribute to accounting */
#define BDI_CAP_NO_WRITEBACK	0x00000002	/* Don't write pages back */
#define BDI_CAP_MAP_COPY	0x00000004	/* Copy can be mapped (MAP_PRIVATE) */
#define BDI_CAP_MAP_DIRECT	0x00000008	/* Can be mapped directly (MAP_SHARED) */
#define BDI_CAP_READ_MAP	0x00000010	/* Can be mapped for reading */
#define BDI_CAP_WRITE_MAP	0x00000020	/* Can be mapped for writing */
#define BDI_CAP_EXEC_MAP	0x00000040	/* Can be mapped for execution */
/* private RHEL BDI flags */
#define BDI_CAP_THROTTLE_DIRTY	0x00010000	/* throttle in balance_dirty_pages when BDI is congested */
#define BDI_CAP_VMFLAGS \
	(BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP | BDI_CAP_EXEC_MAP)

#if defined(VM_MAYREAD) && \
	(BDI_CAP_READ_MAP != VM_MAYREAD || \
	 BDI_CAP_WRITE_MAP != VM_MAYWRITE || \
	 BDI_CAP_EXEC_MAP != VM_MAYEXEC)
#error please change backing_dev_info::capabilities flags
#endif

extern struct backing_dev_info default_backing_dev_info;
void default_unplug_io_fn(struct backing_dev_info *bdi, struct page *page);

int writeback_acquire(struct backing_dev_info *bdi);
int writeback_in_progress(struct backing_dev_info *bdi);
void writeback_release(struct backing_dev_info *bdi);

static inline int bdi_congested(struct backing_dev_info *bdi, int bdi_bits)
{
	if (bdi->congested_fn)
		return bdi->congested_fn(bdi->congested_data, bdi_bits);
	return (bdi->state & bdi_bits);
}

static inline int bdi_read_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, 1 << BDI_sync_congested);
}

static inline int bdi_write_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, 1 << BDI_async_congested);
}

static inline int bdi_rw_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, (1 << BDI_sync_congested) |
				  (1 << BDI_async_congested));
}

enum {
	BLK_RW_ASYNC	= 0,
	BLK_RW_SYNC	= 1,
};

#define bdi_cap_writeback_dirty(bdi) \
	(!((bdi)->capabilities & BDI_CAP_NO_WRITEBACK))

#define bdi_cap_account_dirty(bdi) \
	(!((bdi)->capabilities & BDI_CAP_NO_ACCT_DIRTY))

#define bdi_cap_throttle_dirty(bdi) \
	((bdi)->capabilities & BDI_CAP_THROTTLE_DIRTY)

#define mapping_cap_writeback_dirty(mapping) \
	bdi_cap_writeback_dirty((mapping)->backing_dev_info)

#define mapping_cap_account_dirty(mapping) \
	bdi_cap_account_dirty((mapping)->backing_dev_info)


#endif		/* _LINUX_BACKING_DEV_H */
