/* SPDX-License-Identifier: GPL-2.0 */
/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
*/

#ifndef _FS_FUSE_I_H
#define _FS_FUSE_I_H

#ifndef pr_fmt
# define pr_fmt(fmt) "fuse: " fmt
#endif

#include "args.h"
#include <linux/fuse.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/workqueue.h>
#include <linux/xattr.h>
#include <linux/pid_namespace.h>
#include <linux/refcount.h>
#include <linux/user_namespace.h>

/** Maximum length of a filename, not including terminating null */

/* maximum, small enough for FUSE_MIN_READ_BUFFER*/
#define FUSE_NAME_LOW_MAX 1024
/* maximum, but needs a request buffer > FUSE_MIN_READ_BUFFER */
#define FUSE_NAME_MAX (PATH_MAX - 1)

/** Maximum of max_pages received in init_out */
extern unsigned int fuse_max_pages_limit;

/** List of active connections */
extern struct list_head fuse_conn_list;

/** Global mutex protecting fuse_conn_list and the control filesystem */
extern struct mutex fuse_mutex;

extern struct kmem_cache *fuse_inode_cachep;

/**
 * struct fuse_inode - FUSE inode
 */
struct fuse_inode {
	/** @inode: Inode data */
	struct inode inode;

	/**
	 * @nodeid: Unique ID, which identifies the inode between userspace
	 * and kernel
	 */
	u64 nodeid;

	/** @nlookup: Number of lookups on this inode */
	u64 nlookup;

	/** @inval_mask: Which attributes are invalid */
	u32 inval_mask;

	/** @fetch_mask: Which invalid attributes the running fetch is getting */
	u32 fetch_mask;

	/** @write_end: Furthest end of a write since the running fetch started */
	loff_t write_end;

	/** @i_btime: Cache birthtime */
	struct timespec64 i_btime;

	/** @orig_ino: 64-bit inode number */
	u64 orig_ino;

	/** @attr_version: Version of last attribute change */
	u64 attr_version;

	/** @state: Miscellaneous bits describing inode state */
	unsigned long state;

	/** @mutex: Serializes fetching the attributes */
	struct mutex mutex;

	/** @lock: Protects attr_version and the attributes it versions */
	spinlock_t lock;

	/**
	 * @cached_i_blkbits: The underlying inode->i_blkbits value will not
	 * be modified, so preserve the blocksize specified by the server.
	 */
	u8 cached_i_blkbits;
};

/** FUSE inode state bits */
enum {
	/* Has btime */
	FUSE_I_BTIME,
};

struct fuse_conn;
struct fuse_mount;

/**
 * struct fuse_file - FUSE-specific data of an open directory
 */
struct fuse_file {
	/** @fh: File handle used by userspace */
	u64 fh;

	/** @nodeid: Node id of this file */
	u64 nodeid;
};

#define FUSE_ARGS(args) struct fuse_args args = {}

/**
 * struct fuse_conn - A Fuse connection.
 *
 * This structure is created, when the device fd is given to the mount, and
 * is destroyed, when the device is closed and the fuse_mount is destroyed.
 */
struct fuse_conn {
	/** @count: Refcount */
	refcount_t count;

	/** @rcu: Used to delay freeing fuse_conn, making it safe */
	struct rcu_head rcu;

	/** @pid_ns: The pid namespace for this mount */
	struct pid_namespace *pid_ns;

	/** @user_ns: The user namespace for this mount */
	struct user_namespace *user_ns;

	/** @max_write: Maximum write size */
	unsigned max_write;

	/**
	 * @max_pages: Maximum number of pages that can be used in a
	 * single request
	 */
	unsigned int max_pages;

	/**
	 * @max_pages_limit: Constrain ->max_pages to this value during
	 * feature negotiation
	 */
	unsigned int max_pages_limit;

	/** @chan: transport layer object */
	struct fuse_chan *chan;

	/** @destroy: Send DESTROY request */
	unsigned int destroy:1;

	/** @no_syncfs: The server doesn't implement SYNCFS */
	unsigned int no_syncfs:1;

	/** @entry: Entry on the fuse_conn_list */
	struct list_head entry;

	/** @dev: Device ID from the root super block */
	dev_t dev;

	/** @attr_version: Version counter for attribute changes */
	atomic64_t attr_version;

	/**
	 * @killsb: Read/write semaphore to hold when accessing the sb of any
	 * fuse_mount belonging to this connection
	 */
	struct rw_semaphore killsb;

	/** @mounts: List of filesystems using this connection */
	struct list_head mounts;
};

/*
 * Represents a mounted filesystem.
 */
struct fuse_mount {
	/* Underlying connection to the FUSE server */
	struct fuse_conn *fc;

	/*
	 * Super block for this connection (fc->killsb must be held when
	 * accessing this).
	 */
	struct super_block *sb;

	/* Entry on fc->mounts */
	struct list_head fc_entry;
	struct rcu_head rcu;
};

static inline struct fuse_mount *get_fuse_mount_super(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct fuse_conn *get_fuse_conn_super(struct super_block *sb)
{
	return get_fuse_mount_super(sb)->fc;
}

static inline struct fuse_mount *get_fuse_mount(struct inode *inode)
{
	return get_fuse_mount_super(inode->i_sb);
}

static inline struct fuse_conn *get_fuse_conn(struct inode *inode)
{
	return get_fuse_mount_super(inode->i_sb)->fc;
}

static inline struct fuse_inode *get_fuse_inode(const struct inode *inode)
{
	return container_of(inode, struct fuse_inode, inode);
}

static inline u64 get_node_id(struct inode *inode)
{
	return get_fuse_inode(inode)->nodeid;
}

static inline u64 fuse_get_attr_version(struct fuse_conn *fc)
{
	return atomic64_read(&fc->attr_version);
}

static inline struct folio **fuse_folios_alloc(unsigned int nfolios, gfp_t flags,
					       struct fuse_folio_desc **desc)
{
	struct folio **folios;

	folios = kzalloc(nfolios * (sizeof(struct folio *) +
				    sizeof(struct fuse_folio_desc)), flags);
	*desc = (void *) (folios + nfolios);

	return folios;
}

/** Device operations */
extern const struct file_operations fuse_dev_operations;

void fuse_umount_begin(struct super_block *sb);

int fuse_ctl_init(void);
void fuse_ctl_cleanup(void);

/*
 * Simple request sending that does request allocation and freeing
 */
ssize_t __fuse_simple_request(struct mnt_idmap *idmap,
			      struct fuse_mount *fm,
			      struct fuse_args *args);

static inline ssize_t fuse_simple_request(struct fuse_mount *fm, struct fuse_args *args)
{
	return __fuse_simple_request(&invalid_mnt_idmap, fm, args);
}

int fuse_simple_background(struct fuse_mount *fm, struct fuse_args *args,
			   gfp_t gfp_flags);

/*
 * Invalidate inode attributes
 */

/* Attributes possibly changed on data modification */
#define FUSE_STATX_MODIFY	(STATX_MTIME | STATX_CTIME | STATX_BLOCKS)

/* Attributes possibly changed on data and/or size modification */
#define FUSE_STATX_MODSIZE	(FUSE_STATX_MODIFY | STATX_SIZE)

/* Attributes possibly changed on directory modification */
#define FUSE_STATX_MODDIR	(FUSE_STATX_MODSIZE | STATX_NLINK)

void fuse_invalidate_attr(struct inode *inode);
void fuse_invalidate_attr_mask(struct inode *inode, u32 mask);
void fuse_drop_nlink(struct inode *inode);

void fuse_invalidate_atime(struct inode *inode);

/*
 * Initialize fuse_conn
 */
void fuse_conn_init(struct fuse_conn *fc, struct fuse_mount *fm,
		    struct user_namespace *user_ns, struct fuse_chan *fch);

/**
 * fuse_mount_remove - Remove the mount from the connection
 * @fm: fuse_mount to remove
 */
void fuse_mount_remove(struct fuse_mount *fm);

/*
 * Shut down the connection (possibly sending DESTROY request).
 */
void fuse_conn_destroy(struct fuse_mount *fm);

/* Drop the connection and free the fuse mount */
void fuse_mount_destroy(struct fuse_mount *fm);

/**
 * fuse_ctl_add_conn - Add connection to control filesystem
 * @fc: Fuse connection to add
 */
int fuse_ctl_add_conn(struct fuse_conn *fc);

/**
 * fuse_ctl_remove_conn - Remove connection from control filesystem
 * @fc: Fuse connection to remove
 */
void fuse_ctl_remove_conn(struct fuse_conn *fc);

/*
 * Is file type valid?
 */
int fuse_valid_type(int m);
bool fuse_valid_size(u64 size);

/*
 * Is current process allowed to perform filesystem operation?
 */
bool fuse_allow_current_process(struct fuse_conn *fc);

/*
 * Find the inode of a node id.  The caller must hold fc->killsb.
 */
struct inode *fuse_ilookup(struct fuse_conn *fc, u64 nodeid);

/*
 * File-system tells the kernel to invalidate cache for the given node id.
 */
int fuse_reverse_inval_inode(struct fuse_conn *fc, u64 nodeid,
			     loff_t offset, loff_t len);

/*
 * File-system tells the kernel to invalidate parent attributes and
 * the dentry matching parent/name.
 *
 * If the child_nodeid is non-zero and:
 *    - matches the inode number for the dentry matching parent/name,
 *    - is not a mount point
 *    - is a file or oan empty directory
 * then the dentry is unhashed (d_delete()).
 */
int fuse_reverse_inval_entry(struct fuse_conn *fc, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name);

/*
 * Try to prune this inode.  If neither the inode itself nor dentries associated
 * with this inode have any external reference, then the inode can be freed.
 */
void fuse_try_prune_one_inode(struct fuse_conn *fc, u64 nodeid);

void fuse_convert_statfs(struct kstatfs *stbuf, struct fuse_kstatfs *attr);

/* readdir.c */
int fuse_readdir(struct file *file, struct dir_context *ctx);

#ifdef CONFIG_SYSCTL
extern int fuse_sysctl_register(void);
extern void fuse_sysctl_unregister(void);
#else
#define fuse_sysctl_register()		(0)
#define fuse_sysctl_unregister()	do { } while (0)
#endif /* CONFIG_SYSCTL */

#endif /* _FS_FUSE_I_H */
