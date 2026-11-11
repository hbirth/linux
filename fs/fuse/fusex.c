// SPDX-License-Identifier: GPL-2.0-only

#include "fusex.h"
#include "dev.h"
#include "fuse_i.h"

#include <linux/fs_context.h>
#include <linux/miscdevice.h>
#include <linux/pagemap.h>
#include <linux/exportfs.h>
#include <linux/posix_acl_xattr.h>
#include <linux/statfs.h>
#include <linux/falloc.h>
#include <linux/fs_parser.h>
#include <linux/uio.h>
#include <uapi/linux/magic.h>

static void fusex_init_inode(struct inode *inode);

#define FUSEX_ATTR_PERM		(STATX_MODE | STATX_UID | STATX_GID)

static struct workqueue_struct *fusex_wq;

#define ADD_IN_ARG(_args, _size, _value) \
	(*NEXT_IN_ARG(&(_args)) = (struct fuse_in_arg) { .size = (_size), .value = (_value) })

#define ADD_IN_ARG_S(args, ptr) \
	ADD_IN_ARG(args, sizeof(*(ptr)), ptr)

#define ADD_IN_ARG_ZERO(args) \
	ADD_IN_ARG(args, 0, NULL)

#define ADD_OUT_ARG(_args, _size, _value) \
	(*NEXT_OUT_ARG(&(_args)) = (struct fuse_arg) { .size = (_size), .value = (_value) })

#define ADD_OUT_ARG_S(args, ptr)			\
	ADD_OUT_ARG(args, sizeof(*(ptr)), ptr)

static struct fuse_in_arg *NEXT_IN_ARG(struct fuse_args *args)
{
	if (WARN_ON(args->in_numargs >= ARRAY_SIZE(args->in_args)))
		return NULL;

	return &args->in_args[args->in_numargs++];
}

static struct fuse_arg *NEXT_OUT_ARG(struct fuse_args *args)
{
	if (WARN_ON(args->out_numargs >= ARRAY_SIZE(args->out_args)))
		return NULL;

	return &args->out_args[args->out_numargs++];
}

struct fusex_id {
	u64 nodeid;
	/* will extend with file handle */
};

static int fusex_id_from_args(struct fuse_args *args, struct fusex_id *id)
{
	struct fuse_entryx_out *outarg = args->out_args[0].value;

	/* will extract file handle */
	id->nodeid = outarg->nodeid;
	if (!id->nodeid)
		return -EIO;

	return 0;
}

static ssize_t fusex_inode_request(struct inode *inode, struct fuse_args *args)
{
	args->nodeid = get_node_id(inode);
	/* will add file handle */
	return fuse_simple_request(get_fuse_mount(inode), args);
}

static ssize_t fusex_id_request(struct inode *inode, const struct fusex_id *id,
				struct fuse_args *args)
{
	args->nodeid = id->nodeid;
	/* will add file handle */
	return fuse_simple_request(get_fuse_mount(inode), args);
}

static ssize_t fusex_inode2_request(struct inode *inode, struct inode *inode2,
				    struct fuse_args *args)
{
	/* will add file handle for both inodes */
	return fusex_inode_request(inode, args);
}

static struct inode *fusex_alloc_inode(struct super_block *sb)
{
	struct fuse_inode *fi;

	fi = alloc_inode_sb(sb, fuse_inode_cachep, GFP_KERNEL);
	if (!fi)
		return NULL;

	/* Initialize private data (i.e. everything except fi->inode) */
	BUILD_BUG_ON(offsetof(struct fuse_inode, inode) != 0);
	memset((void *) fi + sizeof(fi->inode), 0, sizeof(*fi) - sizeof(fi->inode));

	mutex_init(&fi->mutex);
	spin_lock_init(&fi->lock);

	return &fi->inode;
}

static void fusex_free_inode(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	kmem_cache_free(fuse_inode_cachep, fi);
}

struct fusex_forget_args {
	struct fuse_args args;
	struct fuse_forget_in inarg;
};

static void fusex_forget_end(struct fuse_args *args, int error)
{
	kfree(container_of(args, struct fusex_forget_args, args));
}

/*
 * A normal ring request, the server commits it to get the entry back.  This can
 * run in reclaim, on failure the server keeps the node id until unmount.
 */
static void fusex_send_forget(struct fuse_mount *fm, u64 nodeid, u64 nlookup)
{
	struct fusex_forget_args *fa = kzalloc_obj(*fa, GFP_NOFS);

	if (!fa)
		return;

	fa->inarg.nlookup = nlookup;
	fa->args.opcode = FUSE_FORGET;
	fa->args.nodeid = nodeid;
	fa->args.force = true;
	fa->args.nocreds = true;
	fa->args.end = fusex_forget_end;
	ADD_IN_ARG_S(fa->args, &fa->inarg);

	if (fuse_simple_background(fm, &fa->args, GFP_NOFS))
		kfree(fa);
}

static void fusex_evict_inode(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (fi->nlookup)
		fusex_send_forget(get_fuse_mount(inode), fi->nodeid, fi->nlookup);
}

static int fusex_send_setstatx(struct inode *inode, struct fuse_setstatx_in *inarg)
{
	FUSE_ARGS(args);
	struct fuse_statx_out outarg;

	args.opcode = FUSE_SETSTATX;
	/* The first arg goes to the 128 byte op_in of the ring header */
	ADD_IN_ARG(args, offsetof(struct fuse_setstatx_in, stat), inarg);
	ADD_IN_ARG_S(args, &inarg->stat);
	ADD_OUT_ARG_S(args, &outarg);

	return fusex_inode_request(inode, &args);
}

static void fusex_get_atime(const struct inode *inode, struct fuse_statx *sx)
{
	sx->mask |= STATX_ATIME;
	sx->atime.tv_sec = inode->i_atime_sec;
	sx->atime.tv_nsec = inode->i_atime_nsec;
}

static void fusex_get_mtime(const struct inode *inode, struct fuse_statx *sx)
{
	sx->mask |= STATX_MTIME;
	sx->mtime.tv_sec = inode->i_mtime_sec;
	sx->mtime.tv_nsec = inode->i_mtime_nsec;
}

static void fusex_get_ctime(const struct inode *inode, struct fuse_statx *sx)
{
	sx->mask |= STATX_CTIME;
	sx->ctime.tv_sec = inode->i_ctime_sec;
	sx->ctime.tv_nsec = inode->i_ctime_nsec;
}

/* The cache is the server's, sync(2) has to reach it */
static int fusex_sync_fs(struct super_block *sb, int wait)
{
	FUSE_ARGS(args);
	struct fuse_syncfs_in inarg;
	int err;

	if (!wait)
		return 0;

	/* generic_shutdown_super() syncs after clearing s_root, the server is gone */
	if (!sb->s_root)
		return 0;

	memset(&inarg, 0, sizeof(inarg));
	args.opcode = FUSE_SYNCFS;
	ADD_IN_ARG_S(args, &inarg);
	err = fusex_inode_request(d_inode(sb->s_root), &args);

	return err == -ENOSYS ? 0 : err;
}

static int fusex_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	FUSE_ARGS(args);
	struct fuse_statfs_out outarg = {};
	int err;

	if (!fuse_allow_current_process(get_fuse_conn(d_inode(dentry)))) {
		buf->f_type = FUSE_SUPER_MAGIC;
		return 0;
	}

	args.opcode = FUSE_STATFS;
	ADD_OUT_ARG_S(args, &outarg);
	err = fusex_inode_request(d_inode(dentry), &args);
	if (!err)
		fuse_convert_statfs(buf, &outarg.st);
	return err;
}

/*
 * I_DONTCACHE makes iput_final() write back the inode, also waiting for the
 * flusher.  That can be on a server thread or in reclaim and must not wait for
 * the server: leave it to the flusher.
 */
static int fusex_drop_inode(struct inode *inode)
{
	if (inode_state_read(inode) & (I_DIRTY_ALL | I_SYNC))
		inode_state_clear(inode, I_DONTCACHE);

	return inode_generic_drop(inode);
}

static const struct super_operations fusex_super_operations = {
	.alloc_inode    = fusex_alloc_inode,
	.free_inode     = fusex_free_inode,
	.drop_inode	= fusex_drop_inode,
	.evict_inode	= fusex_evict_inode,
	.sync_fs	= fusex_sync_fs,
	.umount_begin	= fuse_umount_begin,
	.statfs		= fusex_statfs,
};

static void fusex_set_blkbits(struct inode *inode, u32 blksize)
{
	get_fuse_inode(inode)->cached_i_blkbits =
		blksize ? ilog2(blksize) : inode->i_sb->s_blocksize_bits;
}

static void fusex_set_times(struct inode *inode, struct fuse_statx *attr)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	/* Sanitize nsecs */
	attr->atime.tv_nsec = min_t(u32, attr->atime.tv_nsec, NSEC_PER_SEC - 1);
	attr->mtime.tv_nsec = min_t(u32, attr->mtime.tv_nsec, NSEC_PER_SEC - 1);
	attr->ctime.tv_nsec = min_t(u32, attr->ctime.tv_nsec, NSEC_PER_SEC - 1);

	inode_set_mtime(inode, attr->mtime.tv_sec, attr->mtime.tv_nsec);
	inode_set_ctime(inode, attr->ctime.tv_sec, attr->ctime.tv_nsec);
	inode_set_atime(inode, attr->atime.tv_sec, attr->atime.tv_nsec);

	if (attr->mask & STATX_BTIME) {
		set_bit(FUSE_I_BTIME, &fi->state);
		fi->i_btime.tv_sec = attr->btime.tv_sec;
		fi->i_btime.tv_nsec = attr->btime.tv_nsec;
	}
}

/* The server changes it without notify_change() */
static void fusex_set_mode(struct inode *inode, umode_t mode)
{
	inode->i_mode = mode;
	if (is_sxid(mode))
		inode_set_flags(inode, 0, S_NOSEC);
}

static void fusex_set_attr(struct inode *inode, struct fuse_statx *attr)
{
	struct user_namespace *user_ns = i_user_ns(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	fusex_set_mode(inode, attr->mode);
	i_size_write(inode, attr->size);
	inode->i_blocks = attr->blocks;
	inode->i_ino = fi->orig_ino = attr->ino;
	inode->i_uid = make_kuid(user_ns, attr->uid);
	inode->i_gid = make_kgid(user_ns, attr->gid);
	fusex_set_blkbits(inode, attr->blksize);
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		inode->i_rdev = MKDEV(attr->rdev_major, attr->rdev_minor);

	if (S_ISDIR(attr->mode) && attr->nlink > 1)
		attr->nlink = 1;
	set_nlink(inode, attr->nlink);

	fusex_set_times(inode, attr);
}

static int fusex_inode_eq(struct inode *inode, void *_id)
{
	struct fusex_id *id = _id;
	struct fuse_inode *fi = get_fuse_inode(inode);

	return id->nodeid == fi->nodeid;
}

static int fusex_inode_set(struct inode *inode, void *_id)
{
	struct fusex_id *id = _id;
	struct fuse_inode *fi = get_fuse_inode(inode);

	fi->nodeid = id->nodeid;

	return 0;
}

static u64 fusex_hash_id(const struct fusex_id *id)
{
	/* fuse_ilookup() has to find it */
	return id->nodeid;
}

static void fusex_fill_statx(struct fuse_args *args, struct fuse_statx_in *inarg,
			     struct fuse_statx_out *outarg)
{
	memset(inarg, 0, sizeof(*inarg));
	inarg->sx_mask = STATX_BASIC_STATS | STATX_BTIME;

	args->opcode = FUSE_STATX;
	ADD_IN_ARG_S(*args, inarg);
	ADD_OUT_ARG_S(*args, outarg);
}

static int fusex_send_statx(struct inode *inode, struct fuse_statx_out *outarg)
{
	FUSE_ARGS(args);
	struct fuse_statx_in inarg;
	int err;

	fusex_fill_statx(&args, &inarg, outarg);
	err = fusex_inode_request(inode, &args);
	if (err)
		return err;

	if (!fuse_valid_type(outarg->stat.mode) || !fuse_valid_size(outarg->stat.size))
		return -EIO;

	return 0;
}

static struct inode *fusex_iget(struct super_block *sb, struct fusex_id *id)
{
	return iget5_locked(sb, fusex_hash_id(id), fusex_inode_eq, fusex_inode_set, id);
}

/* Not findable any more: its attributes are not what the server has */
static void fusex_discard_new_inode(struct inode *inode)
{
	remove_inode_hash(inode);
	discard_new_inode(inode);
}

static struct inode *fusex_get_inode(struct super_block *sb, struct fusex_id *id)
{
	struct inode *inode = fusex_iget(sb, id);
	struct fuse_statx_out statx;
	struct fuse_inode *fi;
	int err;

	if (!inode) {
		/* The server counted this lookup */
		fusex_send_forget(get_fuse_mount_super(sb), id->nodeid, 1);
		return ERR_PTR(-ENOMEM);
	}

	fi = get_fuse_inode(inode);
	spin_lock(&fi->lock);
	fi->nlookup++;
	spin_unlock(&fi->lock);

	if (inode_state_read_once(inode) & I_NEW) {
		spin_lock(&inode->i_lock);
		inode_state_set(inode, I_DONTCACHE);
		spin_unlock(&inode->i_lock);
		err = fusex_send_statx(inode, &statx);
		if (err) {
			fusex_discard_new_inode(inode);
			return ERR_PTR(err);
		}
		fusex_set_attr(inode, &statx.stat);
		fusex_init_inode(inode);
		unlock_new_inode(inode);
	}
	return inode;
}

static void fusex_extend_file(struct inode *inode, loff_t old_size, loff_t new_size)
{
	if (old_size < new_size)
		truncate_pagecache_range(inode, old_size, new_size - 1);
}

/* A fetch clears the mask before it has the reply, so what it is getting counts too */
static bool fusex_attr_stale(struct fuse_inode *fi, u32 mask)
{
	if (READ_ONCE(fi->inval_mask) & mask)
		return true;

	/* The fetch sets fetch_mask before it clears the mask */
	smp_rmb();
	return smp_load_acquire(&fi->fetch_mask) & mask;
}

/*
 * Mapped data is flushed first so that the reply includes it.  Returns 1 if a
 * change during the request made the reply useless.  A write during it doesn't:
 * write_end keeps the size and the times it invalidated stay invalid.
 */
static int fusex_fetch_attr(struct inode *inode, bool perm_only)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_statx_out outarg;
	struct fuse_statx *stat = &outarg.stat;
	u32 fetching = READ_ONCE(fi->inval_mask) & (perm_only ? FUSEX_ATTR_PERM : ~0U);
	loff_t oldsize;
	u64 attr_version;
	int err;

	WRITE_ONCE(fi->fetch_mask, fetching);
	set_mask_bits(&fi->inval_mask, fetching, 0);

	if (!perm_only && S_ISREG(inode->i_mode))
		filemap_write_and_wait(inode->i_mapping);

	spin_lock(&fi->lock);
	fi->write_end = 0;
	spin_unlock(&fi->lock);

	attr_version = fuse_get_attr_version(get_fuse_conn(inode));
	err = fusex_send_statx(inode, &outarg);
	if (!err && (inode->i_mode ^ stat->mode) & S_IFMT)
		err = -EIO;
	if (err) {
		fuse_invalidate_attr(inode);
		return err;
	}

	spin_lock(&fi->lock);
	if (fi->attr_version > attr_version) {
		spin_unlock(&fi->lock);
		fuse_invalidate_attr(inode);
		return 1;
	}
	oldsize = inode->i_size;
	if (perm_only) {
		fusex_set_mode(inode, stat->mode);
		inode->i_uid = make_kuid(i_user_ns(inode), stat->uid);
		inode->i_gid = make_kgid(i_user_ns(inode), stat->gid);
	} else {
		stat->size = max_t(u64, stat->size, fi->write_end);
		fusex_set_attr(inode, stat);
	}
	spin_unlock(&fi->lock);

	/* Not a truncation: a write can have grown the file by now */
	if (!perm_only && S_ISREG(inode->i_mode) && stat->size != oldsize)
		invalidate_inode_pages2_range(inode->i_mapping,
					      min_t(u64, stat->size, oldsize) >> PAGE_SHIFT, -1);

	return 0;
}

/*
 * The inode is authoritative until it is invalidated, by the server or by an
 * operation that makes the server change it.  The server has the answer at any
 * time, so this needs no i_rwsem.
 *
 * Asking only for the permissions of a regular file leaves the rest invalid: a
 * path walk doesn't flush.
 *
 * Local changes can keep invalidating the reply: give up after a few tries and
 * leave it to the next user.
 */
static int fusex_refresh_attr(struct inode *inode, u32 mask)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	const bool perm_only = mask == FUSEX_ATTR_PERM && S_ISREG(inode->i_mode);
	int tries = 3;
	int err = 0;

	if (!fusex_attr_stale(fi, mask))
		return 0;

	guard(mutex)(&fi->mutex);
	while (tries-- && (READ_ONCE(fi->inval_mask) & mask)) {
		err = fusex_fetch_attr(inode, perm_only);
		if (err <= 0)
			break;
	}
	/* After the attributes, see fusex_attr_stale() */
	smp_store_release(&fi->fetch_mask, 0);

	return min(err, 0);
}

/* Before the local update: a reply applied after this is not older than it */
static void fusex_attr_changed(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	spin_lock(&fi->lock);
	fi->attr_version = atomic64_inc_return(&get_fuse_conn(inode)->attr_version);
	spin_unlock(&fi->lock);
}

/*
 * Writers share i_rwsem and a fetch doesn't take it.  After a notify during the
 * request the server can have truncated later: @size is no lower bound for a
 * fetch then.  Returns the old size.
 */
static loff_t fusex_grow_size(struct inode *inode, loff_t size, u64 attr_version)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	loff_t old_size;

	spin_lock(&fi->lock);
	old_size = inode->i_size;
	if (size > old_size)
		i_size_write(inode, size);
	if (fi->attr_version > attr_version)
		fuse_invalidate_attr_mask(inode, STATX_SIZE);
	else
		fi->write_end = max(fi->write_end, size);
	spin_unlock(&fi->lock);

	return old_size;
}

static ssize_t fusex_send_read(struct file *file, struct fuse_args_pages *ap,
			       loff_t pos, size_t len, bool zero_copy)
{
	struct fuse_read_in inarg;

	memset(&inarg, 0, sizeof(inarg));
	inarg.offset = pos;
	inarg.size = len;
	inarg.flags = file->f_flags;

	memset(&ap->args, 0, sizeof(ap->args));
	ap->args.opcode = FUSE_READ;
	ADD_IN_ARG_S(ap->args, &inarg);
	ADD_OUT_ARG(ap->args, len, NULL);
	ap->args.out_argvar = true;
	ap->args.out_pages = true;
	ap->args.zero_copy = zero_copy;

	return fusex_inode_request(file_inode(file), &ap->args);
}

/* Writeback has no @file */
static ssize_t fusex_send_write(struct inode *inode, struct file *file,
				struct fuse_args_pages *ap, loff_t pos, size_t len,
				bool zero_copy)
{
	struct fuse_write_in inarg;
	struct fuse_write_out outarg;
	int err;

	memset(&inarg, 0, sizeof(inarg));
	inarg.offset = pos;
	inarg.size = len;
	inarg.flags = file ? file->f_flags : 0;

	memset(&ap->args, 0, sizeof(ap->args));
	ap->args.opcode = FUSE_WRITE;
	/* A signal to whoever flushes must not lose somebody else's write */
	ap->args.force = !file;
	ap->args.nocreds = !file;
	ADD_IN_ARG_S(ap->args, &inarg);
	ADD_IN_ARG(ap->args, len, NULL);
	ap->args.in_pages = true;
	ap->args.zero_copy = zero_copy;
	ADD_OUT_ARG_S(ap->args, &outarg);

	err = fusex_inode_request(inode, &ap->args);
	if (err)
		return err;

	if (!outarg.size || outarg.size > len)
		return -EIO;

	return outarg.size;
}

/* Fills @ap with up to @max_pages pages holding up to @count bytes of @iter */
static ssize_t fusex_get_pages(struct fuse_args_pages *ap, struct page **pages,
			       struct iov_iter *iter, size_t count,
			       unsigned int max_pages)
{
	size_t nbytes = 0;

	ap->num_folios = 0;
	while (nbytes < count && ap->num_folios < max_pages) {
		unsigned int i;
		size_t off;
		ssize_t len;

		len = iov_iter_extract_pages(iter, &pages, count - nbytes,
					     max_pages - ap->num_folios, 0, &off);
		if (len <= 0)
			return nbytes ?: len;

		nbytes += len;
		for (i = 0; len; i++) {
			struct folio *folio = page_folio(pages[i]);
			unsigned int part = umin(len, PAGE_SIZE - off);

			ap->folios[ap->num_folios] = folio;
			ap->descs[ap->num_folios].offset =
				off + folio_page_idx(folio, pages[i]) * PAGE_SIZE;
			ap->descs[ap->num_folios].length = part;
			ap->num_folios++;
			off = 0;
			len -= part;
		}
	}

	return nbytes;
}

static void fusex_put_pages(struct fuse_args_pages *ap, struct iov_iter *iter, bool dirty)
{
	unsigned int i;

	if (!iov_iter_extract_will_pin(iter))
		return;

	for (i = 0; i < ap->num_folios; i++) {
		if (dirty)
			folio_mark_dirty_lock(ap->folios[i]);
		unpin_folio(ap->folios[i]);
	}
}

/* Sends @count bytes of @iter to or from the server at iocb->ki_pos */
static ssize_t fusex_direct_io(struct kiocb *iocb, struct iov_iter *iter, size_t count)
{
	struct file *file = iocb->ki_filp;
	struct fuse_conn *fc = get_fuse_conn(file_inode(file));
	bool write = iov_iter_rw(iter) == WRITE;
	/* Zero copy takes page references, kernel memory can be slab */
	bool zero_copy = iov_iter_extract_will_pin(iter);
	size_t max_len = zero_copy ? SIZE_MAX : fuse_uring_max_payload(fc->chan);
	unsigned int max_pages = iov_iter_npages(iter, fc->max_pages);
	struct fuse_args_pages ap = {};
	size_t done = 0;
	ssize_t res = 0;

	struct page **pages __free(kfree) = kzalloc_objs(struct page *, max_pages);
	struct folio **folios __free(kfree) =
		fuse_folios_alloc(max_pages, GFP_KERNEL, &ap.descs);

	if (!pages || !folios)
		return -ENOMEM;

	ap.folios = folios;

	if (write)
		max_len = umin(max_len, fc->max_write);

	while (done < count) {
		size_t len = umin(count - done, max_len);
		loff_t pos = iocb->ki_pos + done;
		ssize_t got = fusex_get_pages(&ap, pages, iter, len, max_pages);

		if (got <= 0) {
			res = got;
			break;
		}

		res = write ? fusex_send_write(file_inode(file), file, &ap, pos, got, zero_copy) :
			      fusex_send_read(file, &ap, pos, got, zero_copy);
		fusex_put_pages(&ap, iter, !write && res > 0);

		if (res < got)
			iov_iter_revert(iter, got - max_t(ssize_t, res, 0));
		if (res > 0)
			done += res;
		if (res < got)
			break;
	}
	iocb->ki_pos += done;

	return done ?: res;
}

static ssize_t fusex_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	int err = fusex_refresh_attr(inode, STATX_SIZE);
	loff_t size = i_size_read(inode);
	size_t count;
	ssize_t res;

	if (err)
		return err;

	if (!iov_iter_count(to) || iocb->ki_pos >= size)
		return 0;

	count = umin(iov_iter_count(to), size - iocb->ki_pos);

	/* A dirty folio has what this should read */
	res = kiocb_write_and_wait(iocb, count);
	if (!res)
		res = fusex_direct_io(iocb, to, count);
	fuse_invalidate_atime(inode);

	return res;
}

static ssize_t fusex_direct_write(struct kiocb *iocb, struct iov_iter *from, size_t count)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	u64 attr_version = fuse_get_attr_version(get_fuse_conn(inode));
	loff_t size = i_size_read(inode);
	loff_t pos = iocb->ki_pos;
	ssize_t res;

	/*
	 * The writeback of a dirty folio must not overwrite this later.  -EBUSY
	 * leaves a stale folio at worst, the server gets the data regardless.
	 */
	res = kiocb_invalidate_pages(iocb, count);
	if (res && res != -EBUSY)
		return res;

	/*
	 * A hole exposes the rest of the folio at EOF.  Write it back while the
	 * size still leaves out what was mapped past EOF.  Zeroing it later
	 * could hit another writer's data in the hole.
	 */
	if (pos > size) {
		res = invalidate_inode_pages2_range(inode->i_mapping, size >> PAGE_SHIFT,
						    (pos - 1) >> PAGE_SHIFT);
		if (res && res != -EBUSY)
			return res;
	}

	res = fusex_direct_io(iocb, from, count);
	if (res <= 0)
		return res;

	/* Before the invalidation: a fault after it must see the new size */
	fusex_grow_size(inode, iocb->ki_pos, attr_version);

	/* A fault during the write can have read the old data */
	invalidate_inode_pages2_range(inode->i_mapping, pos >> PAGE_SHIFT,
				      (iocb->ki_pos - 1) >> PAGE_SHIFT);
	fuse_invalidate_attr_mask(inode, FUSE_STATX_MODIFY);

	return res;
}

/*
 * The data goes to the server, which orders the writes.  Only append needs EOF
 * under the lock, and removing privileges can't run next to other writers.
 */
static ssize_t fusex_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	bool append = iocb->ki_flags & IOCB_APPEND;
	bool excl;
	ssize_t res;

	/* After a notify: the mode picks the lock, EOF what a hole exposes */
	res = fusex_refresh_attr(inode, STATX_SIZE | FUSEX_ATTR_PERM);
	if (res)
		return res;

	excl = append || !IS_NOSEC(inode);
	if (!excl) {
		inode_lock_shared(inode);
		if (!IS_NOSEC(inode)) {
			inode_unlock_shared(inode);
			excl = true;
		}
	}
	if (excl)
		inode_lock(inode);
	if (append)
		res = fusex_refresh_attr(inode, STATX_SIZE);
	if (!res)
		res = generic_write_checks(iocb, from);
	if (res > 0) {
		size_t count = res;

		/* The times are the server's, this is only about privileges */
		res = excl ? file_modified(file) : 0;
		if (!res)
			res = fusex_direct_write(iocb, from, count);
	}
	if (excl)
		inode_unlock(inode);
	else
		inode_unlock_shared(inode);

	return res > 0 ? generic_write_sync(iocb, res) : res;
}

static loff_t fusex_file_llseek(struct file *file, loff_t offset, int whence)
{
	if (whence != SEEK_SET && whence != SEEK_CUR) {
		int err = fusex_refresh_attr(file_inode(file), STATX_SIZE);

		if (err)
			return err;
	}

	return generic_file_llseek(file, offset, whence);
}

static long fusex_file_fallocate(struct file *file, int mode, loff_t offset, loff_t length)
{
	struct inode *inode = file_inode(file);
	FUSE_ARGS(args);
	struct fuse_fallocate_in inarg = {
		.offset = offset,
		.length = length,
		.mode = mode
	};
	off_t end = offset + length;
	u64 attr_version;
	int err;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
		     FALLOC_FL_ZERO_RANGE))
		return -EOPNOTSUPP;

	guard(rwsem_write)(&inode->i_rwsem);

	err = fusex_refresh_attr(inode, ~0U);
	if (err)
		return err;

	if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE)) {
		err = filemap_write_and_wait_range(inode->i_mapping, offset, end - 1);
		if (err)
			return err;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && end > i_size_read(inode)) {
		err = inode_newsize_ok(inode, end);
		if (err)
			return err;
	}

	err = file_modified(file);
	if (err)
		return err;

	attr_version = fuse_get_attr_version(get_fuse_conn(inode));
	args.opcode = FUSE_FALLOCATE;
	ADD_IN_ARG_S(args, &inarg);
	err = fusex_inode_request(inode, &args);
	if (err)
		return err;

	if (!(mode & FALLOC_FL_KEEP_SIZE)) {
		loff_t old_size = fusex_grow_size(inode, end, attr_version);

		fusex_extend_file(inode, old_size, end);
	}

	if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE))
		truncate_pagecache_range(inode, offset, end - 1);

	fuse_invalidate_attr_mask(inode, FUSE_STATX_MODIFY);

	return 0;
}

/* Mapped data goes to the server, and only the server can make it durable */
static int fusex_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file_inode(file);
	FUSE_ARGS(args);
	struct fuse_fsync_in inarg;
	int err;

	err = file_write_and_wait_range(file, start, end);
	if (err)
		return err;

	memset(&inarg, 0, sizeof(inarg));
	inarg.fsync_flags = datasync ? FUSE_FSYNC_FDATASYNC : 0;
	if (S_ISDIR(inode->i_mode)) {
		inarg.fh = ((struct fuse_file *) file->private_data)->fh;
		args.opcode = FUSE_FSYNCDIR;
	} else {
		args.opcode = FUSE_FSYNC;
	}
	ADD_IN_ARG_S(args, &inarg);
	err = fusex_inode_request(inode, &args);

	return err == -ENOSYS ? 0 : err;
}

/*
 * The server stamps the times when the data gets there.  After the folio is
 * dirty: a fetch that clears this flushes the folio first.
 */
static vm_fault_t fusex_page_mkwrite(struct vm_fault *vmf)
{
	vm_fault_t ret = filemap_page_mkwrite(vmf);

	fuse_invalidate_attr_mask(file_inode(vmf->vma->vm_file), FUSE_STATX_MODIFY);

	return ret;
}

static const struct vm_operations_struct fusex_file_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= fusex_page_mkwrite,
};

static int fusex_file_mmap_prepare(struct vm_area_desc *desc)
{
	desc->vm_ops = &fusex_file_vm_ops;

	return 0;
}

static const struct file_operations fusex_file_operations = {
	.fop_flags	= FOP_DIO_PARALLEL_WRITE,
	.read_iter	= fusex_file_read_iter,
	.write_iter	= fusex_file_write_iter,
	.splice_read	= copy_splice_read,
	.splice_write	= iter_file_splice_write,
	.llseek		= fusex_file_llseek,
	.mmap_prepare	= fusex_file_mmap_prepare,
	.fsync		= fusex_fsync,
	.fallocate	= fusex_file_fallocate,
};

static int fusex_read_folio(struct file *file, struct folio *folio)
{
	struct inode *inode = folio->mapping->host;
	struct fuse_folio_desc desc = {};
	struct fuse_args_pages ap = {
		.folios = &folio, .descs = &desc, .num_folios = 1,
	};
	loff_t pos = folio_pos(folio);
	loff_t i_size = i_size_read(inode);
	ssize_t res = 0;

	/* A racing truncate can leave the folio beyond EOF */
	if (pos < i_size) {
		desc.length = min_t(loff_t, folio_size(folio), i_size - pos);
		res = fusex_send_read(file, &ap, pos, desc.length, false);
	}
	if (res >= 0) {
		folio_zero_segment(folio, res, folio_size(folio));
		folio_mark_uptodate(folio);
		fuse_invalidate_atime(inode);
		res = 0;
	}
	folio_unlock(folio);

	return res;
}

static int fusex_write_folio(struct folio *folio)
{
	struct inode *inode = folio->mapping->host;
	struct fuse_folio_desc desc = {};
	struct fuse_args_pages ap = {
		.folios = &folio, .descs = &desc, .num_folios = 1,
	};
	loff_t pos = folio_pos(folio);
	loff_t i_size = i_size_read(inode);
	int err = 0;

	/* This is what clears the dirty tag */
	folio_start_writeback(folio);

	if (pos < i_size) {
		ssize_t res;

		desc.length = min_t(loff_t, folio_size(folio), i_size - pos);
		res = fusex_send_write(inode, NULL, &ap, pos, desc.length, false);
		if (res != desc.length)
			err = res < 0 ? res : -EIO;
		if (err)
			mapping_set_error(folio->mapping, err);
	}

	folio_end_writeback(folio);

	return err;
}

static int fusex_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	struct folio *folio = NULL;
	int err;

	while ((folio = writeback_iter(mapping, wbc, folio, &err))) {
		err = fusex_write_folio(folio);
		folio_unlock(folio);
	}

	return err;
}

/* An invalidation from the server must not lose a dirty folio */
static int fusex_launder_folio(struct folio *folio)
{
	if (!folio_clear_dirty_for_io(folio))
		return 0;

	return fusex_write_folio(folio);
}

/* Only mappings use the page cache, read(2) and write(2) are direct */
static const struct address_space_operations fusex_file_aops = {
	.read_folio	= fusex_read_folio,
	.writepages	= fusex_writepages,
	.launder_folio	= fusex_launder_folio,
	/* open() needs this for O_DIRECT */
	.direct_IO	= noop_direct_IO,
	.dirty_folio	= filemap_dirty_folio,
	.migrate_folio	= filemap_migrate_folio,
};

/* The server keeps the times, it stamps what it is asked to do */
static void fusex_dir_modified(struct inode *dir)
{
	fusex_attr_changed(dir);
	fuse_invalidate_attr_mask(dir, FUSE_STATX_MODDIR);
}

static void fusex_ctime_changed(struct inode *inode)
{
	fuse_invalidate_attr_mask(inode, STATX_CTIME);
}

static struct inode *fusex_do_lookup(struct inode *base, const struct qstr *name)
{
	FUSE_ARGS(args);
	struct fuse_entryx_out outarg;
	struct fusex_id id;
	int err;

	args.opcode = FUSE_LOOKUPX;
	ADD_IN_ARG_ZERO(args);
	ADD_IN_ARG(args, name->len + 1, name->name);
	ADD_OUT_ARG_S(args, &outarg);

	err = fusex_inode_request(base, &args);
	if (err < 0)
		return ERR_PTR(err);

	if (outarg.flags & FUSE_ENTRYX_NEGATIVE) {
		if (err > 0)
			return ERR_PTR(-EIO);
		return NULL;
	}

	err = fusex_id_from_args(&args, &id);
	if (err)
		return ERR_PTR(err);

	return fusex_get_inode(base->i_sb, &id);
}


static struct dentry *fusex_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct inode *inode = fusex_do_lookup(dir, &dentry->d_name);

	return d_splice_alias(inode, dentry);
}

static int fusex_getattr(struct mnt_idmap *idmap, const struct path *path, struct kstat *stat,
			 u32 request_mask, unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err;

	if (!fuse_allow_current_process(get_fuse_conn(inode))) {
		if (!request_mask) {
			/* Asking for nothing only gets st_dev */
			stat->result_mask = 0;
			stat->dev = inode->i_sb->s_dev;
			return 0;
		}
		return -EACCES;
	}

	if ((flags & AT_STATX_SYNC_TYPE) != AT_STATX_DONT_SYNC) {
		err = fusex_refresh_attr(inode, request_mask);
		if (err)
			return err;
	}

	generic_fillattr(idmap, request_mask, inode, stat);
	stat->ino = fi->orig_ino;
	stat->blksize = 1 << fi->cached_i_blkbits;
	if (test_bit(FUSE_I_BTIME, &fi->state)) {
		stat->btime = fi->i_btime;
		stat->result_mask |= STATX_BTIME;
	}

	return 0;
}

static void *fusex_send_lgxattr(struct inode *inode, const char *name, size_t *sizep)
{
	FUSE_ARGS(args);
	struct fuse_getxattr_in inarg;
	ssize_t res;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = min_t(size_t, name ? XATTR_SIZE_MAX : XATTR_LIST_MAX,
			   fuse_uring_max_payload(get_fuse_conn(inode)->chan));

	args.opcode = name ? FUSE_GETXATTR : FUSE_LISTXATTR;
	ADD_IN_ARG_S(args, &inarg);
	if (name)
		ADD_IN_ARG(args, strlen(name) + 1, name);
	ADD_OUT_ARG(args, inarg.size, NULL);
	args.out_argvar = true;
	args.out_var_alloc = true;

	res = fusex_inode_request(inode, &args);
	if (res < 0) {
		kvfree(args.out_args[0].value);
		if (res == -ENOSYS)
			res = -EOPNOTSUPP;
		return ERR_PTR(res);
	}

	*sizep = res;

	return args.out_args[0].value;
}

static bool fusex_verify_xattr_list(char *list, size_t size)
{
	while (size) {
		size_t thislen = strnlen(list, size);

		if (!thislen || thislen == size)
			return false;

		size -= thislen + 1;
		list += thislen + 1;
	}
	return true;
}

static char *fusex_send_listxattr(struct inode *inode, size_t *gotsize)
{
	char *list = fusex_send_lgxattr(inode, NULL, gotsize);

	if (IS_ERR(list))
		return list;

	if (!fusex_verify_xattr_list(list, *gotsize)) {
		kvfree(list);
		return ERR_PTR(-EIO);
	}

	return list;
}

static ssize_t fusex_listxattr(struct dentry *dentry, char *list, size_t size)
{
	struct inode *inode = d_inode(dentry);
	ssize_t res;

	if (!fuse_allow_current_process(get_fuse_conn(inode)))
		return -EACCES;

	char *gotlist __free(kvfree) = fusex_send_listxattr(inode, &res);

	if (IS_ERR(gotlist))
		return PTR_ERR(gotlist);

	if (size) {
		if (size < res)
			res = -ERANGE;
		else
			memcpy(list, gotlist, res);
	}

	return res;
}

static struct posix_acl *fusex_get_acl(struct inode *inode, int type, bool rcu)
{
	struct user_namespace *user_ns = i_user_ns(inode);
	const char *name = posix_acl_xattr_name(type);
	size_t size;
	void *value __free(kvfree) = fusex_send_lgxattr(inode, name, &size);
	struct posix_acl *acl = NULL;

	WARN_ON(rcu);

	if (IS_ERR(value)) {
		switch (PTR_ERR(value)) {
		case -ENODATA:
		case -EOPNOTSUPP:
			value = NULL;
			break;
		default:
			return ERR_CAST(value);
		}
	}
	if (value)
		acl = posix_acl_from_xattr(user_ns, value, size);

	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	return acl;
}

static void fusex_fill_setxattr(struct fuse_args *args, struct fuse_setxattr_in *inarg,
				const char *name, const void *value, size_t size, int flags)
{
	if (value) {
		memset(inarg, 0, sizeof(*inarg));
		inarg->size = size;
		inarg->flags = flags;

		args->opcode = FUSE_SETXATTR;
		ADD_IN_ARG_S(*args, inarg);
		ADD_IN_ARG(*args, strlen(name) + 1, name);
		ADD_IN_ARG(*args, size, value);
	} else {
		args->opcode = FUSE_REMOVEXATTR;
		ADD_IN_ARG_ZERO(*args);
		ADD_IN_ARG(*args, strlen(name) + 1, name);
	}
}


static int fusex_send_setxattr(struct inode *inode, const char *name, const void *value,
			       size_t size, int flags)
{
	FUSE_ARGS(args);
	struct fuse_setxattr_in inarg;
	int err;

	fusex_fill_setxattr(&args, &inarg, name, value, size, flags);
	err = fusex_inode_request(inode, &args);
	if (err) {
		if (err == -ENOSYS)
			err = -EOPNOTSUPP;
		return err;
	}

	fusex_ctime_changed(inode);

	return 0;
}

static int fusex_send_setacl(struct inode *inode, int type, struct posix_acl *acl)
{
	struct user_namespace *user_ns = i_user_ns(inode);
	const char *name = posix_acl_xattr_name(type);
	size_t size;

	if (!acl)
		return fusex_send_setxattr(inode, name, NULL, 0, 0);

	void *value __free(kfree) = posix_acl_to_xattr(user_ns, acl, &size, GFP_KERNEL);
	if (!value)
		return -ENOMEM;

	return fusex_send_setxattr(inode, name, value, size, 0);
}

static int fusex_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
			 struct posix_acl *acl, int type)
{
	struct inode *inode = d_inode(dentry);
	umode_t mode = inode->i_mode;
	bool update_mode = false;
	int err;

	if (type == ACL_TYPE_ACCESS && acl) {
		err = posix_acl_update_mode(idmap, inode, &mode, &acl);
		if (err)
			return err;
		update_mode = true;
	}

	err = fusex_send_setacl(inode, type, acl);
	if (err)
		return err;

	fusex_attr_changed(inode);
	set_cached_acl(inode, type, acl);
	if (update_mode) {
		struct fuse_setstatx_in inarg;

		memset(&inarg, 0, sizeof(inarg));
		inarg.stat.mask |= STATX_MODE;
		inarg.stat.mode = mode & 07777;

		/* Like setattr: a fetch that has the old mode must not apply */
		err = fusex_send_setstatx(inode, &inarg);
		if (err)
			return err;

		fusex_attr_changed(inode);
		inode->i_mode = mode;
	}

	return 0;
}

static int fusex_send_mkobjx(struct inode *dir, struct inode *inode,
			     const struct qstr *name, const char *link_body, struct fusex_id *id)
{
	FUSE_ARGS(args);
	struct fuse_mkobjx_in inarg;
	struct fuse_entryx_out outarg;
	struct user_namespace *u = i_user_ns(inode);
	int flags = 0;
	int err;

	if (!name->len) {
		WARN_ON((inode->i_mode & S_IFMT) != S_IFREG);
		flags |= FUSE_MKOBJX_TMPFILE;
	}

	memset(&inarg, 0, sizeof(inarg));
	inarg.namesize = name->len + 1;
	inarg.stat.mask = STATX_UID | STATX_GID | STATX_MODE | STATX_TYPE | STATX_BTIME;
	inarg.stat.uid = from_kuid(u, inode->i_uid);
	inarg.stat.gid = from_kgid(u, inode->i_gid);
	inarg.stat.rdev_major = MAJOR(inode->i_rdev);
	inarg.stat.rdev_minor = MINOR(inode->i_rdev);
	inarg.stat.mode = inode->i_mode;
	fusex_get_atime(inode, &inarg.stat);
	fusex_get_mtime(inode, &inarg.stat);
	fusex_get_ctime(inode, &inarg.stat);
	inarg.stat.btime = inarg.stat.ctime;
	inarg.flags = flags;

	args.opcode = FUSE_MKOBJX;
	/* The first arg goes to the 128 byte op_in of the ring header */
	ADD_IN_ARG(args, offsetof(struct fuse_mkobjx_in, stat), &inarg);
	ADD_IN_ARG_S(args, &inarg.stat);
	ADD_IN_ARG(args, inarg.namesize, name->name);
	if (S_ISLNK(inode->i_mode))
		ADD_IN_ARG(args, strlen(link_body) + 1, link_body);
	ADD_OUT_ARG_S(args, &outarg);

	err = fusex_inode_request(dir, &args);
	if (err)
		return err;

	return fusex_id_from_args(&args, id);
}

static int fusex_set_initial_acl(struct inode *inode, const struct fusex_id *id, int type)
{
	struct posix_acl *acl = (type == ACL_TYPE_ACCESS) ? inode->i_acl : inode->i_default_acl;
	if (!acl)
		return 0;

	FUSE_ARGS(args);
	struct fuse_setxattr_in inarg;
	size_t size;
	const char *name = posix_acl_xattr_name(type);
	const void *value __free(kfree) =
		posix_acl_to_xattr(i_user_ns(inode), acl, &size, GFP_KERNEL);
	if (!value)
		return -ENOMEM;

	fusex_fill_setxattr(&args, &inarg, name, value, size, 0);

	return fusex_id_request(inode, id, &args);
}

static int fusex_do_mkobjx(struct inode *dir, struct inode *inode, const struct qstr *name,
			     const char *link_body, struct fuse_statx_out *outarg_sx)
{
	FUSE_ARGS(args_sx);
	struct fuse_statx_in inarg_sx;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct inode *old;
	struct fusex_id id;
	int err;

	err = fusex_send_mkobjx(dir, inode, name, link_body, &id);
	if (err)
		return err;

	/* Eviction forgets it, also when something below fails */
	fi->nodeid = id.nodeid;
	fi->nlookup = 1;

	err = fusex_set_initial_acl(inode, &id, ACL_TYPE_ACCESS);
	if (err)
		return err;

	err = fusex_set_initial_acl(inode, &id, ACL_TYPE_DEFAULT);
	if (err)
		return err;

	fusex_fill_statx(&args_sx, &inarg_sx, outarg_sx);
	err = fusex_id_request(inode, &id, &args_sx);
	if (err)
		return err;

	old = inode_insert5(inode, fusex_hash_id(&id), fusex_inode_eq, fusex_inode_set, &id);
	if (old != inode) {
		iput(old);
		return -EBUSY;
	}
	return 0;
}

static int fusex_setup_new_inode(struct inode *inode, struct fuse_statx *statx)
{
	struct fuse_inode *fi;

	if (inode->i_mode != statx->mode)
		return -EIO;
	if (!uid_eq(inode->i_uid, make_kuid(i_user_ns(inode), statx->uid)))
		return -EIO;
	if (!gid_eq(inode->i_gid, make_kgid(i_user_ns(inode), statx->gid)))
		return -EIO;
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		if (MKDEV(statx->rdev_major, statx->rdev_minor) != inode->i_rdev)
			return -EIO;
	}

	fi = get_fuse_inode(inode);
	inode->i_size = statx->size;
	inode->i_blocks = statx->blocks;
	inode->i_ino = fi->orig_ino = statx->ino;
	fusex_set_blkbits(inode, statx->blksize);
	fusex_set_times(inode, statx);

	return 0;
}

static struct inode *fusex_new_inode(struct mnt_idmap *idmap, struct inode *dir,
				     const struct qstr *name, umode_t mode, dev_t rdev,
				     const char *link_body)
{
	struct inode *inode;
	struct fuse_statx_out statx;
	int err;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode_init_owner(idmap, inode, dir, mode);
	if (S_ISCHR(mode) || S_ISBLK(mode))
		inode->i_rdev = rdev;

	simple_inode_init_ts(inode);
	fusex_init_inode(inode);
	inode->i_size = 0;

	err = posix_acl_create(dir, &inode->i_mode, &inode->i_default_acl, &inode->i_acl);
	if (err)
		goto out_iput;

	err = fusex_do_mkobjx(dir, inode, name, link_body, &statx);
	if (err)
		goto out_iput;

	err = fusex_setup_new_inode(inode, &statx.stat);
	if (err) {
		fusex_discard_new_inode(inode);
		return ERR_PTR(err);
	}

	return inode;

out_iput:
	iput(inode);
	return ERR_PTR(err);
}

static int fusex_mkobj(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode, dev_t rdev, const char *link_body)
{
	struct inode *inode = fusex_new_inode(idmap, dir, &dentry->d_name, mode, rdev, link_body);
	if (IS_ERR(inode)) {
		/* The server may have created it */
		d_drop(dentry);
		return PTR_ERR(inode);
	}

	fusex_dir_modified(dir);
	d_instantiate_new(dentry, inode);

	return 0;
}

static int fusex_create(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode)
{
	return fusex_mkobj(idmap, dir, dentry, mode, 0, NULL);
}

static int fusex_mknod(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode, dev_t rdev)
{
	return fusex_mkobj(idmap, dir, dentry, mode, rdev, NULL);
}

static struct dentry *fusex_mkdir(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode)
{
	int err = fusex_mkobj(idmap, dir, dentry, S_IFDIR | mode, 0, NULL);

	return ERR_PTR(err);
}

static int fusex_symlink(struct mnt_idmap *idmap, struct inode *dir,
			 struct dentry *dentry, const char *link_body)
{
	return fusex_mkobj(idmap, dir, dentry, S_IFLNK | 0777, 0, link_body);
}

static int fusex_tmpfile(struct mnt_idmap *idmap, struct inode *dir, struct file *file,
			 umode_t mode)
{
	struct inode *inode = fusex_new_inode(idmap, dir, &empty_name, mode, 0, NULL);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	d_tmpfile(file, inode);
	unlock_new_inode(inode);
	return finish_open_simple(file, 0);
}

static int fusex_remove(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	FUSE_ARGS(args);
	int err;

	rwsem_assert_held_write(&inode->i_rwsem);

	args.opcode = d_is_dir(dentry) ? FUSE_RMDIR : FUSE_UNLINK;
	ADD_IN_ARG_ZERO(args);
	ADD_IN_ARG(args, dentry->d_name.len + 1, dentry->d_name.name);

	err = fusex_inode_request(dir, &args);
	if (err)
		return err;

	fusex_attr_changed(inode);
	fuse_drop_nlink(inode);
	fusex_ctime_changed(inode);
	fusex_dir_modified(dir);

	return 0;
}

static int fusex_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = d_inode(dentry);
	struct user_namespace *user_ns = i_user_ns(inode);
	struct fuse_setstatx_in inarg;
	int err;

	if (!fuse_allow_current_process(get_fuse_conn(inode)))
		return -EACCES;

	err = fusex_refresh_attr(inode, ~0U);
	if (err)
		return err;

	err = setattr_prepare(idmap, dentry, iattr);
	if (err)
		return err;

	if ((iattr->ia_valid & ATTR_SIZE) && iattr->ia_size != i_size_read(inode))
		iattr->ia_valid |= ATTR_MTIME | ATTR_CTIME;

	memset(&inarg, 0, sizeof(inarg));
	if (iattr->ia_valid & ATTR_SIZE) {
		inarg.stat.mask |= STATX_SIZE;
		inarg.stat.size = iattr->ia_size;
	}
	if (iattr->ia_valid & ATTR_UID) {
		inarg.stat.mask |= STATX_UID;
		inarg.stat.uid = from_kuid(user_ns, from_vfsuid(idmap, user_ns, iattr->ia_vfsuid));
	}
	if (iattr->ia_valid & ATTR_GID) {
		inarg.stat.mask |= STATX_GID;
		inarg.stat.gid = from_kgid(user_ns, from_vfsgid(idmap, user_ns, iattr->ia_vfsgid));
	}
	if (iattr->ia_valid & ATTR_MODE) {
		inarg.stat.mask |= STATX_MODE;
		err = posix_acl_chmod(idmap, dentry, iattr->ia_mode);
		if (err)
			return err;

		inarg.stat.mode = iattr->ia_mode & 07777;
	}
	if (iattr->ia_valid & ATTR_ATIME) {
		inarg.stat.mask |= STATX_ATIME;
		inarg.stat.atime.tv_sec = iattr->ia_atime.tv_sec;
		inarg.stat.atime.tv_nsec = iattr->ia_atime.tv_nsec;
	}
	if (iattr->ia_valid & ATTR_CTIME) {
		inarg.stat.mask |= STATX_CTIME;
		inarg.stat.ctime.tv_sec = iattr->ia_ctime.tv_sec;
		inarg.stat.ctime.tv_nsec = iattr->ia_ctime.tv_nsec;
	}
	if (iattr->ia_valid & ATTR_MTIME) {
		inarg.stat.mask |= STATX_MTIME;
		inarg.stat.mtime.tv_sec = iattr->ia_mtime.tv_sec;
		inarg.stat.mtime.tv_nsec = iattr->ia_mtime.tv_nsec;
	}
	err = fusex_send_setstatx(inode, &inarg);
	if (err)
		return err;

	fusex_attr_changed(inode);
	setattr_copy(idmap, inode, iattr);
	if (iattr->ia_valid & ATTR_SIZE) {
		struct fuse_inode *fi = get_fuse_inode(inode);
		loff_t old_size;

		spin_lock(&fi->lock);
		old_size = inode->i_size;
		i_size_write(inode, iattr->ia_size);
		spin_unlock(&fi->lock);
		fuse_invalidate_attr_mask(inode, STATX_BLOCKS);
		fusex_extend_file(inode, old_size, iattr->ia_size);
		truncate_pagecache(inode, iattr->ia_size);
	}

	return 0;
}

static int fusex_rename(struct mnt_idmap *idmap, struct inode *olddir,
			struct dentry *olddentry, struct inode *newdir,
			struct dentry *newdentry, unsigned int flags)
{
	struct inode *oldinode = d_inode(olddentry);
	struct inode *newinode = d_inode(newdentry);
	struct fuse_rename2_in inarg;
	FUSE_ARGS(args);
	int err;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;

	memset(&inarg, 0, sizeof(inarg));
	inarg.newdir = get_node_id(newdir);
	inarg.flags = flags;

	args.opcode = FUSE_RENAME2;
	ADD_IN_ARG_S(args, &inarg);
	ADD_IN_ARG(args, olddentry->d_name.len + 1, olddentry->d_name.name);
	ADD_IN_ARG(args, newdentry->d_name.len + 1, newdentry->d_name.name);

	err = fusex_inode2_request(olddir, newdir, &args);
	if (err)
		return err;

	fusex_ctime_changed(oldinode);
	if (newinode) {
		fusex_attr_changed(newinode);
		if (!(flags & RENAME_EXCHANGE))
			fuse_drop_nlink(newinode);
		fusex_ctime_changed(newinode);
	}

	fusex_dir_modified(olddir);
	fusex_dir_modified(newdir);

	return 0;
}

static int fusex_link(struct dentry *dentry, struct inode *newdir, struct dentry *newdentry)
{
	struct fuse_link_in inarg;
	struct inode *inode = d_inode(dentry);
	FUSE_ARGS(args);
	int err;

	memset(&inarg, 0, sizeof(inarg));
	inarg.oldnodeid = get_node_id(inode);

	args.opcode = FUSE_LINK;
	ADD_IN_ARG_S(args, &inarg);
	ADD_IN_ARG(args, newdentry->d_name.len + 1, newdentry->d_name.name);

	err = fusex_inode2_request(newdir, inode, &args);
	if (err)
		return err;

	fusex_attr_changed(inode);
	ihold(inode);
	inc_nlink(inode);
	fusex_ctime_changed(inode);
	fusex_dir_modified(newdir);
	d_instantiate(newdentry, inode);

	return 0;
}

static int fusex_permission(struct mnt_idmap *idmap, struct inode *inode, int mask)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err;

	if (!fuse_allow_current_process(get_fuse_conn(inode)))
		return -EACCES;

	if (fusex_attr_stale(fi, FUSEX_ATTR_PERM)) {
		if (mask & MAY_NOT_BLOCK)
			return -ECHILD;

		err = fusex_refresh_attr(inode, FUSEX_ATTR_PERM);
		if (err)
			return err;
	}

	return generic_permission(idmap, inode, mask);
}

static const struct inode_operations fusex_file_inode_operations = {
	.permission	= fusex_permission,
	.getattr	= fusex_getattr,
	.setattr	= fusex_setattr,
	.get_inode_acl	= fusex_get_acl,
	.set_acl	= fusex_set_acl,
	.listxattr	= fusex_listxattr,
};

static const struct inode_operations fusex_dir_inode_operations = {
	.permission	= fusex_permission,
	.getattr	= fusex_getattr,
	.setattr	= fusex_setattr,
	.get_inode_acl	= fusex_get_acl,
	.set_acl	= fusex_set_acl,
	.listxattr	= fusex_listxattr,

	.lookup		= fusex_lookup,
	.create		= fusex_create,
	.tmpfile	= fusex_tmpfile,
	.mkdir		= fusex_mkdir,
	.mknod		= fusex_mknod,
	.symlink	= fusex_symlink,
	.unlink		= fusex_remove,
	.rmdir		= fusex_remove,
	.rename		= fusex_rename,
	.link		= fusex_link,
};

static const char *fusex_get_link(struct dentry *dentry, struct inode *inode,
				  struct delayed_call *callback)
{
	FUSE_ARGS(args);
	ssize_t res;
	char *link;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	link = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!link)
		return ERR_PTR(-ENOMEM);

	args.opcode = FUSE_READLINK;
	ADD_IN_ARG_ZERO(args);
	ADD_OUT_ARG(args, PAGE_SIZE - 1, link);
	args.out_argvar = true;
	res = fusex_inode_request(inode, &args);
	if (res < 0) {
		kfree(link);
		return ERR_PTR(res);
	}

	link[res] = '\0';
	set_delayed_call(callback, kfree_link, link);

	return link;
}

static const struct inode_operations fusex_symlink_inode_operations = {
	.permission	= fusex_permission,
	.getattr	= fusex_getattr,
	.setattr	= fusex_setattr,
	.get_link	= fusex_get_link,
	.listxattr	= fusex_listxattr,
};

struct fuse_release_args {
	struct fuse_args args;
	struct fuse_release_in inarg;
	struct inode *inode;
};

struct fusex_dir_file {
	struct fuse_file ff;
	struct fuse_release_args ra;
	struct work_struct release_work;
};

static struct fuse_file *fusex_file_alloc(void)
{
	struct fusex_dir_file *f = kzalloc_obj(*f, GFP_KERNEL_ACCOUNT);

	if (!f)
		return NULL;

	ADD_IN_ARG_S(f->ra.args, &f->ra.inarg);

	return &f->ff;
}

static int fusex_send_opendir(struct fuse_file *ff, struct inode *inode)
{
	struct fuse_open_in inarg;
	struct fuse_open_out outarg;
	FUSE_ARGS(args);
	int err;

	memset(&inarg, 0, sizeof(inarg));

	args.opcode = FUSE_OPENDIR;
	ADD_IN_ARG_S(args, &inarg);
	ADD_OUT_ARG_S(args, &outarg);

	err = fusex_inode_request(inode, &args);
	if (!err) {
		ff->fh = outarg.fh;
		ff->nodeid = get_node_id(inode);
	}
	return err;
}

static int fusex_dir_open(struct inode *inode, struct file *file)
{
	struct fuse_file *ff __free(kfree) = fusex_file_alloc();
	int err;

	if (!ff)
		return -ENOMEM;

	err = fusex_send_opendir(ff, inode);
	if (err)
		return err;

	file->private_data = no_free_ptr(ff);
	return 0;
}

static void fusex_release_work(struct work_struct *work)
{
	struct fusex_dir_file *f = container_of(work, struct fusex_dir_file, release_work);

	iput(f->ra.inode);
	kfree(f);
}

/* This runs on a server thread, and a final iput can wait for the server */
static void fusex_release_end(struct fuse_args *args, int error)
{
	struct fuse_release_args *ra = container_of(args, typeof(*ra), args);
	struct fusex_dir_file *f = container_of(ra, struct fusex_dir_file, ra);

	INIT_WORK(&f->release_work, fusex_release_work);
	queue_work(fusex_wq, &f->release_work);
}

static int fusex_dir_release(struct inode *inode, struct file *file)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_release_args *ra = &container_of(ff, struct fusex_dir_file, ff)->ra;

	ra->inarg.fh = ff->fh;

	ra->args.opcode = FUSE_RELEASEDIR;
	ra->args.nodeid = ff->nodeid;
	ra->args.force = true;
	ra->args.nocreds = true;
	ra->args.end = fusex_release_end;
	ra->inode = igrab(inode);

	if (fuse_simple_background(fm, &ra->args, GFP_KERNEL | __GFP_NOFAIL))
		fusex_release_end(&ra->args, -ENOTCONN);

	return 0;
}

static const struct file_operations fusex_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= fuse_readdir,
	.open		= fusex_dir_open,
	.release	= fusex_dir_release,
	.fsync		= fusex_fsync,
};

static void fusex_init_inode(struct inode *inode)
{
	inode->i_flags |= S_NOCMTIME;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &fusex_file_inode_operations;
		inode->i_fop = &fusex_file_operations;
		inode->i_data.a_ops = &fusex_file_aops;
		mapping_set_writeback_may_deadlock_on_reclaim(&inode->i_data);
		break;

	case S_IFDIR:
		inode->i_op = &fusex_dir_inode_operations;
		inode->i_fop = &fusex_dir_operations;
		break;

	case S_IFLNK:
		inode->i_op = &fusex_symlink_inode_operations;
		break;

	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		inode->i_op = &fusex_file_inode_operations;
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		break;

	default:
		WARN_ON(1);
	}
}

static int fusex_xattr_get(const struct xattr_handler *handler, struct dentry *dentry,
			   struct inode *inode, const char *name, void *buffer, size_t size)
{
	size_t attr_size;
	void *value __free(kvfree) =
		fusex_send_lgxattr(inode, name - strlen(handler->prefix), &attr_size);

	if (IS_ERR(value))
		return PTR_ERR(value);

	if (!size)
		return attr_size;

	if (size < attr_size)
		return -ERANGE;

	memcpy(buffer, value, attr_size);
	return attr_size;

}

static int fusex_xattr_set(const struct xattr_handler *handler, struct mnt_idmap *idmap,
			   struct dentry *dentry, struct inode *inode,
			   const char *name, const void *value, size_t size, int flags)
{
	return fusex_send_setxattr(inode, name - strlen(handler->prefix), value, size, flags);
}

const struct xattr_handler fusex_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.get	= fusex_xattr_get,
	.set	= fusex_xattr_set,
};

const struct xattr_handler fusex_xattr_handler = {
	.prefix	= "",
	.get	= fusex_xattr_get,
	.set	= fusex_xattr_set,
};

const struct xattr_handler *const fusex_xattr_handlers[] = {
	&fusex_xattr_user_handler,
	&fusex_xattr_handler,
	NULL,
};

static int fusex_send_init(struct fs_context *fsc, struct fuse_mount *fm,
			   struct fusex_id *id, struct fuse_statx_out *statx)
{
	FUSE_ARGS(args_in);
	FUSE_ARGS(args_lr);
	FUSE_ARGS(args_sx);
	struct fuse_init_in inarg_in;
	struct fuse_init_out outarg_in;
	struct fuse_entryx_out outarg_lr;
	struct fuse_statx_in inarg_sx;
	u64 flags = FUSE_INIT_EXT | FUSE_OVER_IO_URING;
	size_t max_payload;
	int err;

	memset(&inarg_in, 0, sizeof(inarg_in));
	inarg_in.major = FUSE_KERNEL_VERSION;
	inarg_in.minor = FUSE_KERNEL_MINOR_VERSION;
	inarg_in.flags = flags;
	inarg_in.flags2 = flags >> 32;
	args_in.opcode = FUSE_INIT;
	args_in.abort_on_kill = true;
	ADD_IN_ARG_S(args_in, &inarg_in);
	ADD_OUT_ARG_S(args_in, &outarg_in);
	err = fuse_simple_request(fm, &args_in);
	if (err)
		return err;

	flags = outarg_in.flags;
	if (!(flags & FUSE_INIT_EXT))
		return -EINVAL;

	flags |= (u64) outarg_in.flags2 << 32;
	if (!(flags & FUSE_OVER_IO_URING))
		return -EPROTONOSUPPORT;

	/* A read or write has to fit the payload buffer or be zero-copied */
	max_payload = fuse_uring_max_io(fm->fc->chan);
	if (outarg_in.max_write > max_payload)
		return invalfc(fsc, "max_write %u exceeds the ring payload buffer %zu",
			       outarg_in.max_write, max_payload);

	fm->fc->max_write = outarg_in.max_write;
	fm->fc->max_pages = min_t(size_t, max_payload >> PAGE_SHIFT,
				  min_t(unsigned int, fm->fc->max_pages_limit,
					max_t(unsigned int, outarg_in.max_pages, 1)));
	if (!fm->fc->max_pages)
		return -EINVAL;

	args_lr.opcode = FUSE_LOOKUP_ROOT;
	args_lr.abort_on_kill = true;
	ADD_OUT_ARG_S(args_lr, &outarg_lr);
	err = fuse_simple_request(fm, &args_lr);
	if (err)
		return err;

	err = fusex_id_from_args(&args_lr, id);
	if (err)
		return err;

	fusex_fill_statx(&args_sx, &inarg_sx, statx);
	args_sx.nodeid = id->nodeid;
	args_sx.abort_on_kill = true;
	err = fuse_simple_request(fm, &args_sx);
	if (err)
		return err;

	if (!S_ISDIR(statx->stat.mode) || !fuse_valid_size(statx->stat.size))
		return -EIO;

	return 0;
}

static int fusex_fill_super(struct super_block *sb, struct fs_context *fsc)
{
	struct fuse_mount *fm = get_fuse_mount_super(sb);
	struct fuse_conn *fc = fm->fc;
	struct inode *inode;
	struct fusex_id id;
	struct fuse_statx_out statx;
	int err;

	fm->sb = sb;
	fc->dev = sb->s_dev;

	scoped_guard(mutex, &fuse_mutex) {
		list_add_tail(&fc->entry, &fuse_conn_list);
		err = fuse_ctl_add_conn(fc);
		if (err)
			return err;
	}

	err = super_setup_bdi(sb);
	if (err)
		return err;

	sb->s_magic = FUSE_SUPER_MAGIC;
	sb->s_op = &fusex_super_operations;
	sb->s_xattr = fusex_xattr_handlers;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;
	sb->s_iflags |= SB_I_IMA_UNVERIFIABLE_SIGNATURE;
	if (sb->s_user_ns != &init_user_ns)
		sb->s_iflags |= SB_I_UNTRUSTED_MOUNTER;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_flags &= SB_RDONLY;
	sb->s_flags |= SB_POSIXACL | SB_NOATIME | SB_NOSEC;

	err = fusex_send_init(fsc, fm, &id, &statx);
	if (err)
		return err;

	inode = fusex_iget(sb, &id);
	if (inode) {
		WARN_ON(!(inode_state_read_once(inode) & I_NEW));
		get_fuse_inode(inode)->nlookup = 1;
		fusex_set_attr(inode, &statx.stat);
		fusex_init_inode(inode);
		unlock_new_inode(inode);
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	fc->destroy = true;

	return 0;
}

/*
 * FUSE_INIT goes over the ring, so the server registers ring entries between
 * setting the fd and CMD_CREATE.
 */
static int fusex_new_conn(struct fs_context *fsc, struct fuse_dev *fud)
{
	struct fuse_conn *fc __free(kfree) = kmalloc_obj(*fc);
	struct fuse_mount *fm __free(kfree) = kzalloc_obj(*fm);
	struct fuse_chan *fch __free(fuse_chan_free) = fuse_chan_new();
	int err;

	if (!fch || !fc || !fm)
		return -ENOMEM;

	err = fuse_uring_ring_only_init(fch);
	if (err)
		return err;

	fuse_conn_init(fc, fm, fsc->user_ns, fch);
	fsc->s_fs_info = fm;
	retain_and_null_ptr(fc);
	retain_and_null_ptr(fm);
	fuse_dev_install(fud, no_free_ptr(fch));

	return 0;
}

static int fusex_get_tree(struct fs_context *fsc)
{
	if (!fsc->s_fs_info)
		return invalfc(fsc, "fd not set");

	return get_tree_nodev(fsc, fusex_fill_super);
}

enum {
	FUSEX_OPT_FD,
};

static const struct fs_parameter_spec fusex_fs_parameters[] = {
	fsparam_fd("fd", FUSEX_OPT_FD),
	{}
};

static int fusex_parse_param(struct fs_context *fsc, struct fs_parameter *param)
{
	struct fs_parse_result result;
	struct fuse_dev *fud;
	int opt, err;

	if (fsc->purpose == FS_CONTEXT_FOR_RECONFIGURE)
		return invalfc(fsc, "No changes allowed in reconfigure");

	opt = fs_parse(fsc, fusex_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case FUSEX_OPT_FD:
		if (fsc->fs_private)
			return invalfc(fsc, "Multiple fd specified");
		if (param->type != fs_value_is_file)
			return invalfc(fsc, "FSCONFIG_SET_FD is required for fd");
		if (param->file->f_op != &fuse_dev_operations)
			return invalfc(fsc, "fd is not a fuse device");
		if (param->file->f_cred->user_ns != fsc->user_ns)
			return invalfc(fsc, "wrong user namespace for fuse device");

		fud = fuse_dev_grab(param->file);
		if (!fuse_dev_is_sync_init(fud)) {
			fuse_dev_put(fud);
			return invalfc(fsc, "synchronous INIT is mandatory");
		}
		if (fuse_dev_is_installed(fud)) {
			fuse_dev_put(fud);
			return invalfc(fsc, "fuse device already in use");
		}
		err = fusex_new_conn(fsc, fud);
		if (err) {
			fuse_dev_put(fud);
			return err;
		}
		fsc->fs_private = fud;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static void fusex_free_fsc(struct fs_context *fsc)
{
	struct fuse_dev *fud = fsc->fs_private;
	struct fuse_mount *fm = fsc->s_fs_info;

	/* No superblock took it over */
	if (fm) {
		fuse_conn_destroy(fm);
		fuse_mount_remove(fm);
		fuse_mount_destroy(fm);
	}
	if (fud)
		fuse_dev_put(fud);
}

static const struct fs_context_operations fusex_context_ops = {
	.get_tree	= fusex_get_tree,
	.parse_param	= fusex_parse_param,
	.free		= fusex_free_fsc,
};

static int fusex_init_fs_context(struct fs_context *fsc)
{
	fsc->ops = &fusex_context_ops;
	return 0;
}

static void fusex_kill_sb_anon(struct super_block *sb)
{
	struct fuse_mount *fm = get_fuse_mount_super(sb);

	/* No flush on close: write back and sync while the server is still there */
	if (sb->s_root)
		sync_filesystem(sb);

	fuse_mount_remove(fm);
	fuse_conn_destroy(fm);
	/* The requests are done: this gives back the inode references they held */
	flush_workqueue(fusex_wq);
	kill_anon_super(sb);
	fuse_mount_destroy(fm);
}

MODULE_ALIAS_FS("fusex");

static struct file_system_type fusex_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fusex",
	.fs_flags	= FS_USERNS_MOUNT | FS_ALLOW_IDMAP,
	.init_fs_context = fusex_init_fs_context,
	.kill_sb	= fusex_kill_sb_anon,
};

int __init fusex_init(void)
{
	int err;

	fusex_wq = alloc_workqueue("fusex", WQ_UNBOUND, 0);
	if (!fusex_wq)
		return -ENOMEM;

	err = register_filesystem(&fusex_fs_type);
	if (err)
		destroy_workqueue(fusex_wq);

	return err;
}

void __exit fusex_cleanup(void)
{
	unregister_filesystem(&fusex_fs_type);
	destroy_workqueue(fusex_wq);
}
