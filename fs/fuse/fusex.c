// SPDX-License-Identifier: GPL-2.0-only

#include "fusex.h"
#include "dev.h"
#include "fuse_i.h"
#include "fuse_dev_i.h"  /* fuse_dev_chan_get, FUSE_DEV_CHAN_DISCONNECTED */
#include "dev_uring_i.h" /* fuse_uring_send_forget, fuse_uring_queue_fuse_req */

#include <linux/fs_context.h>
#include <linux/miscdevice.h>
#include <linux/xxhash.h>
#include <linux/pagemap.h>
#include <linux/exportfs.h>
#include <linux/iversion.h>
#include <linux/posix_acl_xattr.h>
#include <linux/statfs.h>
#include <linux/falloc.h>
#include <linux/fs_parser.h>
#include <uapi/linux/magic.h>

static void fusex_init_inode(struct inode *inode);
static int fusex_file_open(struct inode *inode, struct file *file);
static int fusex_file_release(struct inode *inode, struct file *file);

/*
 * fusex I/O flavors.
 *
 * A flavor is a self-contained pair of (file_operations, address_space_
 * operations) that overrides only the callbacks that flavor needs.
 * Selection happens at inode setup (per-mount default) and is optionally
 * narrowed per-file at open() time (e.g. FOPEN_DIRECT_IO). Everything
 * else stays generic — no run-time branching inside the read/write/
 * writepages callbacks.
 *
 *   WRITEBACK   page-cached reads and writes; writeback flushes dirty
 *               folios out via fusex_writepages. Mount default when
 *               the daemon negotiated FUSE_WRITEBACK_CACHE.
 *
 *   DIRECT      neither reads nor writes touch the page cache; each
 *               iov_iter is shipped to the daemon as a multi-folio
 *               FUSE_READ/FUSE_WRITE batch. Selected per-file when the
 *               daemon returns FOPEN_DIRECT_IO or the open was O_DIRECT.
 */
enum fusex_io_flavor {
	FUSEX_IO_WRITEBACK,
	FUSEX_IO_DIRECT,
};

static const struct file_operations fusex_fops_writeback;
static const struct file_operations fusex_fops_direct;
static const struct address_space_operations fusex_aops_writeback;
static const struct address_space_operations fusex_aops_direct;

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

/*
 * Pull the daemon-minted fh out of a struct file's fuse_file slot.
 * Returns 0 for inode-only paths (no file context, e.g. writeback
 * writes, ATTR_FILE-less setattr) which the daemon must accept.
 */
static inline u64 fusex_file_fh(struct file *file)
{
	struct fuse_file *ff = file ? file->private_data : NULL;

	return ff ? ff->fh : 0;
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
	struct fuse_forget_link *forget __free(kfree) = fuse_alloc_forget();

	if (!forget)
		return NULL;

	fi = alloc_inode_sb(sb, fuse_inode_cachep, GFP_KERNEL);
	if (!fi)
		return NULL;

	/* Initialize private data (i.e. everything except fi->inode) */
	BUILD_BUG_ON(offsetof(struct fuse_inode, inode) != 0);
	memset((void *) fi + sizeof(fi->inode), 0, sizeof(*fi) - sizeof(fi->inode));
	spin_lock_init(&fi->lock);

	fi->forget = no_free_ptr(forget);
	return &fi->inode;
}

static void fusex_free_inode(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	kfree(fi->forget);
	kmem_cache_free(fuse_inode_cachep, fi);
}

static void fusex_evict_inode(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (fi->forget) {
		if (fi->nodeid)
			fuse_chan_queue_forget(fc->chan, fi->forget, fi->nodeid, 1);
		else
			kfree(fi->forget);
		fi->forget = NULL;
	}
}

static int fusex_send_setstatx(struct inode *inode, struct fuse_setstatx_in *inarg)
{
	FUSE_ARGS(args);
	struct fuse_statx_out outarg;

	args.opcode = FUSE_SETSTATX;
	/* Split header / stat so in_args[0] fits in io_uring's 128 B op_in */
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

static int fusex_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct fuse_setstatx_in inarg;

	memset(&inarg, 0, sizeof(inarg));

	fusex_get_atime(inode, &inarg.stat);
	fusex_get_mtime(inode, &inarg.stat);
	fusex_get_ctime(inode, &inarg.stat);

	return fusex_send_setstatx(inode, &inarg);
}

static int fusex_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	FUSE_ARGS(args);
	struct fuse_statfs_out outarg;
	int err;

	args.opcode = FUSE_STATFS;
	ADD_OUT_ARG_S(args, &outarg);
	err = fusex_inode_request(d_inode(dentry), &args);
	if (!err)
		fuse_convert_statfs(buf, &outarg.st);
	return err;
}

static const struct super_operations fusex_super_operations = {
	.alloc_inode    = fusex_alloc_inode,
	.free_inode     = fusex_free_inode,
	.evict_inode	= fusex_evict_inode,
	.write_inode	= fusex_write_inode,
	.umount_begin	= fuse_umount_begin,
	.statfs		= fusex_statfs,
};

/*
 * fusex_io_uring_ops
 *
 * Identical to the generic fuse_io_uring_ops registered by dev_uring.c
 * except .send_forget is routed through fuse_uring_send_forget() so
 * FUSE_FORGET travels over the rings. We install this on the channel's
 * iqueue in fusex_get_tree(), which runs after the daemon's REGISTER
 * cmds have completed (fuse_uring_register() has already swapped fiq->ops
 * to the generic table by that point — we overwrite it). Other
 * fuse-over-io_uring filesystems keep the generic ops and the legacy
 * enqueue-only FORGET behaviour.
 */
static const struct fuse_iqueue_ops fusex_io_uring_ops = {
	.send_forget    = fuse_uring_send_forget,
	.send_interrupt = fuse_dev_queue_interrupt,
	.send_req       = fuse_uring_queue_fuse_req,
};

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

static void fusex_set_attr(struct inode *inode, struct fuse_statx *attr)
{
	struct user_namespace *user_ns = i_user_ns(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	inode->i_mode = attr->mode;
	inode->i_size = attr->size;
	inode->i_blocks = attr->blocks;
	inode->i_ino = fi->orig_ino = attr->ino;
	inode->i_uid = make_kuid(user_ns, attr->uid);
	inode->i_gid = make_kgid(user_ns, attr->gid);
	fi->cached_i_blkbits = ilog2(attr->blksize);
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

static unsigned long fusex_hash_id(const struct fusex_id *id)
{
	return xxhash(&id->nodeid, sizeof(id->nodeid), 0);
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

/*
 * @prefetched: optional attributes already returned by a compound
 * (e.g. LOOKUPX+STATX). If non-NULL the caller has already validated
 * them; we skip the per-inode STATX round-trip.
 */
static struct inode *fusex_get_inode(struct super_block *sb, struct fusex_id *id,
				     struct fuse_statx *prefetched)
{
	struct inode *inode = fusex_iget(sb, id);
	struct fuse_statx_out statx;
	struct fuse_statx *attr;
	int err;

	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (inode_state_read_once(inode) & I_NEW) {
		/* I_NEW gives us exclusive ownership; i_lock not needed. */
		inode_state_set_raw(inode, I_DONTCACHE);
		if (prefetched) {
			attr = prefetched;
		} else {
			err = fusex_send_statx(inode, &statx);
			if (err) {
				discard_new_inode(inode);
				return ERR_PTR(err);
			}
			attr = &statx.stat;
		}
		fusex_set_attr(inode, attr);
		fusex_init_inode(inode);
		unlock_new_inode(inode);
	}
	return inode;
}

static void fusex_extend_file(struct inode *inode, loff_t old_size, loff_t new_size)
{
	WARN_ON(new_size > inode->i_size);

	if (old_size < new_size)
		truncate_pagecache_range(inode, old_size, new_size - 1);
}

static long fusex_file_fallocate(struct file *file, int mode, loff_t offset, loff_t length)
{
	struct inode *inode = file_inode(file);
	FUSE_ARGS(args);
	struct fuse_fallocate_in inarg = {
		.fh     = fusex_file_fh(file),
		.offset = offset,
		.length = length,
		.mode = mode
	};
	off_t end = offset + length;
	int err;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
		     FALLOC_FL_ZERO_RANGE))
		return -EOPNOTSUPP;

	guard(rwsem_write)(&inode->i_rwsem);

	if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE)) {
		err = filemap_write_and_wait_range(inode->i_mapping, offset, end - 1);
		if (err)
			return err;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && end > inode->i_size) {
		err = inode_newsize_ok(inode, end);
		if (err)
			return err;
	}

	err = file_modified(file);
	if (err)
		return err;

	args.opcode = FUSE_FALLOCATE;
	args.in_numargs = 1;
	ADD_IN_ARG_S(args, &inarg);
	err = fusex_inode_request(inode, &args);
	if (err)
		return err;

	if (!(mode & FALLOC_FL_KEEP_SIZE) && end > inode->i_size) {
		loff_t old_size = inode->i_size;

		i_size_write(inode, end);
		fusex_extend_file(inode, old_size, inode->i_size);
	}

	if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE))
		truncate_pagecache_range(inode, offset, end - 1);

	return 0;
}

/*
 * Writeback flavor — page-cached read/write path. read_iter and write_iter
 * go through the generic helpers, which exercise our aops below: reads via
 * read_folio/readahead, writes via write_begin/write_end and (asynchronously)
 * writepages. Splice and mmap are page-cache-based as well.
 */
static const struct file_operations fusex_fops_writeback = {
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.splice_read	= filemap_splice_read,
	.splice_write	= iter_file_splice_write,
	.llseek		= generic_file_llseek,
	.mmap_prepare	= generic_file_mmap_prepare,
	.fsync		= simple_fsync_noflush,
	.fallocate	= fusex_file_fallocate,
	.open		= fusex_file_open,
	.release	= fusex_file_release,
};

/*
 * Dispatch a FUSE_READ for one or more contiguous folios starting at
 * @pos, totalling @total_len bytes. Returns the actual number of bytes
 * the daemon delivered (may be < total_len at EOF); the caller is
 * responsible for zero-filling any short tail.
 */
static ssize_t fusex_send_reads(struct inode *inode, loff_t pos, u64 fh,
				unsigned int flags, struct folio **folios,
				struct fuse_folio_desc *descs,
				unsigned int nfolios, size_t total_len)
{
	struct fuse_args_pages ap = {};
	struct fuse_read_in inarg;
	ssize_t res;

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = fh;
	inarg.offset = pos;
	inarg.size = total_len;
	inarg.flags = flags;

	ap.args.opcode = FUSE_READ;
	ADD_IN_ARG_S(ap.args, &inarg);
	ADD_OUT_ARG(ap.args, total_len, NULL);
	ap.args.out_argvar = true;
	ap.args.out_pages = true;
	ap.num_folios = nfolios;
	ap.folios = folios;
	ap.descs = descs;

	res = fusex_inode_request(inode, &ap.args);
	if (res < 0)
		return res;
	WARN_ON(res > total_len);
	return res;
}

static int fusex_send_read(struct inode *inode, loff_t pos, struct file *file,
			   struct folio *folio, unsigned int off, unsigned int len)
{
	struct fuse_folio_desc desc = { .offset = off, .length = len };
	ssize_t res = fusex_send_reads(inode, pos, fusex_file_fh(file),
				       file ? file->f_flags : 0,
				       &folio, &desc, 1, len);

	if (res < 0)
		return res;
	if (res < len)
		folio_zero_segment(folio, off + res, off + len);
	return 0;
}

static int fusex_do_read_folio(struct file *file, struct folio *folio)
{
	struct inode *inode = folio->mapping->host;
	loff_t folio_start = folio_pos(folio);
	loff_t i_size = i_size_read(inode);
	size_t full_len = folio_size(folio), len = full_len;
	int err;

	WARN_ON(i_size <= folio_start);

	if (i_size < folio_start + full_len) {
		len = i_size - folio_start;
		folio_zero_segment(folio, len, full_len);
	}
	err = fusex_send_read(inode, folio_start, file, folio, 0, len);
	if (err)
		return err;

	folio_mark_uptodate(folio);

	return 0;
}

static int fusex_read_folio(struct file *file, struct folio *folio)
{
	int err = fusex_do_read_folio(file, folio);

	folio_unlock(folio);
	return err;
}

static void fusex_readahead(struct readahead_control *rac)
{
	struct inode *inode = rac->mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct file *file = rac->file;
	const u64 fh = fusex_file_fh(file);
	const unsigned int rflags = file ? file->f_flags : 0;
	const loff_t i_size = i_size_read(inode);
	const unsigned int max_folios = min_t(unsigned int, fc->max_pages, 256);
	struct folio **folios __free(kfree) =
		kmalloc_array(max_folios, sizeof(*folios), GFP_KERNEL);
	struct fuse_folio_desc *descs __free(kfree) =
		kmalloc_array(max_folios, sizeof(*descs), GFP_KERNEL);
	struct folio *folio;

	if (!folios || !descs)
		return;

	while ((folio = readahead_folio(rac)) != NULL) {
		loff_t batch_pos = folio_pos(folio);
		size_t batch_len;
		size_t full_len = folio_size(folio), len = full_len;
		unsigned int n;
		ssize_t got;

		if (batch_pos >= i_size) {
			folio_unlock(folio);
			continue;
		}
		if (i_size < batch_pos + full_len) {
			len = i_size - batch_pos;
			folio_zero_segment(folio, len, full_len);
		}
		folios[0] = folio;
		descs[0].offset = 0;
		descs[0].length = len;
		batch_len = len;
		n = 1;

		/* Coalesce as many contiguous follow-up folios as fit. */
		while (n < max_folios) {
			loff_t next_pos = batch_pos + (loff_t)batch_len;
			struct folio *nf;

			if (next_pos >= i_size)
				break;
			nf = readahead_folio(rac);
			if (!nf)
				break;
			full_len = folio_size(nf);
			len = full_len;
			if (i_size < next_pos + full_len) {
				len = i_size - next_pos;
				folio_zero_segment(nf, len, full_len);
			}
			folios[n] = nf;
			descs[n].offset = 0;
			descs[n].length = len;
			batch_len += len;
			n++;
		}

		got = fusex_send_reads(inode, batch_pos, fh, rflags,
				       folios, descs, n, batch_len);
		if (got < 0) {
			unsigned int i;
			for (i = 0; i < n; i++)
				folio_unlock(folios[i]);
			break;
		}
		/* Zero any tail the daemon didn't deliver. */
		if ((size_t)got < batch_len) {
			size_t consumed = 0;
			unsigned int i;
			for (i = 0; i < n; i++) {
				size_t flen = descs[i].length;
				if (consumed + flen <= (size_t)got) {
					consumed += flen;
					continue;
				}
				if (consumed < (size_t)got) {
					unsigned int part = (size_t)got - consumed;
					folio_zero_segment(folios[i], part, flen);
					consumed = got;
				} else {
					folio_zero_segment(folios[i], 0, flen);
				}
			}
		}
		for (unsigned int i = 0; i < n; i++) {
			folio_mark_uptodate(folios[i]);
			folio_unlock(folios[i]);
		}
	}
}

/*
 * Dispatch a FUSE_WRITE for one or more contiguous folios starting at
 * @pos, totalling @total_len bytes. Callers populate @folios[]/@descs[]
 * with the per-folio (offset, length) split.
 */
static int fusex_send_writes(struct inode *inode, loff_t pos, u64 fh,
			     struct folio **folios,
			     struct fuse_folio_desc *descs,
			     unsigned int nfolios, size_t total_len)
{
	struct fuse_args_pages ap = {};
	struct fuse_write_in inarg;
	struct fuse_write_out outarg;
	int err;

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = fh;
	inarg.offset = pos;
	inarg.size = total_len;

	ap.args.opcode = FUSE_WRITE;
	ADD_IN_ARG_S(ap.args, &inarg);
	ADD_IN_ARG(ap.args, total_len, NULL);
	ap.args.in_pages = true;
	ap.num_folios = nfolios;
	ap.folios = folios;
	ap.descs = descs;
	ADD_OUT_ARG_S(ap.args, &outarg);

	err = fusex_inode_request(inode, &ap.args);
	if (err)
		return err;

	if (outarg.size != total_len)
		return -EIO;

	return 0;
}

/*
 * Pick any writable opener's fh so writeback can use the daemon's
 * cached backing fd instead of re-resolving via /proc/self/fd on every
 * batch. Returns 0 if no writer is currently open (msync after close,
 * shrinker-triggered writeback, ...); daemons must tolerate that.
 */
static u64 fusex_writeback_fh(struct fuse_inode *fi)
{
	u64 fh = 0;

	spin_lock(&fi->lock);
	if (!list_empty(&fi->write_files)) {
		struct fuse_file *ff = list_first_entry(&fi->write_files,
							struct fuse_file,
							write_entry);
		fh = ff->fh;
	}
	spin_unlock(&fi->lock);
	return fh;
}

static int fusex_writepages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);
	const unsigned int max_folios = min_t(unsigned int, fc->max_pages, 256);
	const size_t max_size = fc->max_write;
	const u64 fh = fusex_writeback_fh(fi);
	struct folio **folios __free(kfree) =
		kmalloc_array(max_folios, sizeof(*folios), GFP_KERNEL);
	struct fuse_folio_desc *descs __free(kfree) =
		kmalloc_array(max_folios, sizeof(*descs), GFP_KERNEL);
	struct folio *folio = NULL;
	unsigned int n = 0;
	loff_t batch_pos = 0;
	size_t batch_len = 0;
	int err = 0;

	if (!folios || !descs)
		return -ENOMEM;

	while ((folio = writeback_iter(mapping, wbc, folio, &err))) {
		loff_t folio_start = folio_pos(folio);
		loff_t i_size = i_size_read(inode);
		size_t full_len = folio_size(folio), len = full_len;

		if (folio_start >= i_size) {
			folio_unlock(folio);
			continue;
		}
		if (i_size < folio_start + full_len)
			len = i_size - folio_start;

		/* Break the batch when the new folio isn't contiguous, the
		 * folio-count cap is reached, or max_write would be exceeded. */
		if (n &&
		    (folio_start != batch_pos + (loff_t)batch_len ||
		     n >= max_folios ||
		     batch_len + len > max_size)) {
			unsigned int i;
			int ferr = fusex_send_writes(inode, batch_pos, fh,
						     folios, descs, n,
						     batch_len);
			for (i = 0; i < n; i++)
				folio_unlock(folios[i]);
			n = 0;
			batch_len = 0;
			if (ferr) {
				err = ferr;
				folio_unlock(folio);
				break;
			}
		}

		if (!n)
			batch_pos = folio_start;
		folios[n] = folio;
		descs[n].offset = 0;
		descs[n].length = len;
		batch_len += len;
		n++;
	}

	if (n) {
		unsigned int i;
		int ferr = fusex_send_writes(inode, batch_pos, fh,
					     folios, descs, n, batch_len);
		for (i = 0; i < n; i++)
			folio_unlock(folios[i]);
		if (!err)
			err = ferr;
	}

	return err;
}

static int fusex_write_begin(const struct kiocb *iocb, struct address_space *mapping,
			     loff_t pos, unsigned int len,
			     struct folio **foliop, void **fsdata)
{
	struct folio *folio;

	folio = __filemap_get_folio(mapping, pos / PAGE_SIZE, FGP_WRITEBEGIN,
				    mapping_gfp_mask(mapping));
	if (IS_ERR(folio))
		return PTR_ERR(folio);

	if (!folio_test_uptodate(folio) && (len != folio_size(folio))) {
		if (folio->mapping->host->i_size <= folio_pos(folio)) {
			folio_zero_segment(folio, 0, folio_size(folio));
			folio_mark_uptodate(folio);
		} else {
			int err = fusex_do_read_folio(iocb->ki_filp, folio);
			if (err) {
				folio_unlock(folio);
				folio_put(folio);
				return err;
			}
		}
	}
	*foliop = folio;

	return 0;
}

static int fusex_write_end(const struct kiocb *iocb, struct address_space *mapping,
			    loff_t pos, unsigned int len, unsigned int copied,
			    struct folio *folio, void *fsdata)
{
	struct inode *inode = folio->mapping->host;
	loff_t old_size = inode->i_size;
	loff_t end_pos = pos + copied;
	int err = 0;

	if (!folio_test_uptodate(folio)) {
		if (copied < len) {
			size_t off = offset_in_folio(folio, end_pos);

			err = fusex_send_read(inode, end_pos, iocb->ki_filp, folio,
					      off, len - copied);
			if (err)
				goto out;
		}
		folio_mark_uptodate(folio);
	}
	if (end_pos > old_size)
		i_size_write(inode, end_pos);
out:
	folio_mark_dirty(folio);
	folio_unlock(folio);
	folio_put(folio);

	if (!err)
		fusex_extend_file(inode, old_size, pos);

	return err ? err : copied;
}

static ssize_t fusex_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct file *file = iocb->ki_filp;
	struct fuse_conn *fc = get_fuse_conn(inode);
	const bool is_write = (iov_iter_rw(iter) == WRITE);
	const bool will_pin = iov_iter_extract_will_pin(iter);
	const bool user_backed = user_backed_iter(iter);
	const u64 fh = fusex_file_fh(file);
	const unsigned int rflags = file->f_flags;
	const unsigned int max_pages = min_t(unsigned int, fc->max_pages, 256);
	const size_t max_size = is_write ? fc->max_write
					 : (size_t)max_pages * PAGE_SIZE;
	loff_t old_size = i_size_read(inode);
	loff_t pos = iocb->ki_pos;
	struct folio **folios __free(kfree) =
		kmalloc_array(max_pages, sizeof(*folios), GFP_KERNEL);
	struct fuse_folio_desc *descs __free(kfree) =
		kmalloc_array(max_pages, sizeof(*descs), GFP_KERNEL);
	int err = 0;

	if (!iov_iter_count(iter) || (!is_write && pos >= old_size))
		return 0;
	if (!folios || !descs)
		return -ENOMEM;

	while (iov_iter_count(iter)) {
		struct page **pages = NULL;
		size_t off, batch_len;
		ssize_t got;
		unsigned long npages;
		unsigned int n;

		got = iov_iter_extract_pages(iter, &pages, max_size,
					     max_pages, 0, &off);
		if (got <= 0) {
			err = got;
			break;
		}
		batch_len = got;
		if (!is_write && pos + (loff_t)batch_len > old_size)
			batch_len = old_size - pos;

		/*
		 * Pack the extracted pages into folios[]/descs[], merging
		 * runs that fall in the same folio at adjacent offsets so
		 * huge folios collapse to a single descriptor instead of one
		 * per 4 KiB page.
		 */
		n = 0;
		npages = 0;
		{
			size_t remaining = batch_len;
			size_t cur_off = off;

			while (remaining) {
				struct folio *f = page_folio(pages[npages]);
				size_t plen = min((size_t)(PAGE_SIZE - cur_off),
						  remaining);
				size_t fold_off =
					(size_t)folio_page_idx(f, pages[npages]) *
					PAGE_SIZE + cur_off;

				if (n > 0 && folios[n - 1] == f &&
				    descs[n - 1].offset + descs[n - 1].length ==
				    fold_off) {
					descs[n - 1].length += plen;
				} else {
					folios[n] = f;
					descs[n].offset = fold_off;
					descs[n].length = plen;
					n++;
				}
				remaining -= plen;
				cur_off = 0;
				npages++;
			}
			/* Account for tail pages beyond batch_len (capped read). */
			while (npages * PAGE_SIZE < (size_t)(got + off))
				npages++;
		}

		if (is_write) {
			int werr = fusex_send_writes(inode, pos, fh, folios,
						     descs, n, batch_len);
			if (werr)
				err = werr;
		} else {
			ssize_t got_back = fusex_send_reads(inode, pos, fh,
							    rflags, folios,
							    descs, n, batch_len);
			if (got_back < 0) {
				err = got_back;
			} else {
				if ((size_t)got_back < batch_len)
					batch_len = got_back;
				if (user_backed) {
					unsigned int i;
					for (i = 0; i < n; i++)
						folio_mark_dirty_lock(folios[i]);
				}
			}
		}

		if (will_pin)
			unpin_user_pages(pages, npages);
		kvfree(pages);

		if (err)
			break;
		pos += batch_len;
		if (!is_write && (size_t)got > batch_len)
			break;  /* hit EOF mid-batch */
	}

	if (pos > iocb->ki_pos) {
		if (is_write) {
			if (pos > old_size)
				i_size_write(inode, pos);
			fusex_extend_file(inode, old_size, iocb->ki_pos);
		}
	}

	return (pos - iocb->ki_pos) ?: err;
}

/*
 * Writeback flavor — address space operations. read_folio/readahead serve
 * the cache-population side; writepages + write_begin/write_end handle the
 * dirty-out side. direct_IO stays here for the legacy generic_*_iter ->
 * aops.direct_IO entry path, but new code reaches the same logic through
 * the direct flavor's read_iter/write_iter below.
 */
static const struct address_space_operations fusex_aops_writeback = {
	.read_folio	= fusex_read_folio,
	.readahead	= fusex_readahead,
	.writepages	= fusex_writepages,
	.write_begin	= fusex_write_begin,
	.write_end	= fusex_write_end,
	.direct_IO	= fusex_direct_IO,
	.dirty_folio	= filemap_dirty_folio,
	.migrate_folio	= filemap_migrate_folio,
};

/*
 * Direct flavor — uncached read/write. Wraps fusex_direct_IO so direct
 * files reach it through file->f_op->{read,write}_iter instead of the
 * legacy aops->direct_IO callback. The aops is intentionally empty so
 * nothing can sneak the file back into the page cache.
 */
static ssize_t fusex_direct_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	return fusex_direct_IO(iocb, to);
}

static ssize_t fusex_direct_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = fusex_direct_IO(iocb, from);
	inode_unlock(inode);
	return ret;
}

static const struct file_operations fusex_fops_direct = {
	.read_iter	= fusex_direct_read_iter,
	.write_iter	= fusex_direct_write_iter,
	.llseek		= generic_file_llseek,
	.fsync		= simple_fsync_noflush,
	.fallocate	= fusex_file_fallocate,
	.open		= fusex_file_open,
	.release	= fusex_file_release,
};

static const struct address_space_operations fusex_aops_direct = {
	/* No callbacks: I/O bypasses the page cache via the fops above. */
};

/*
 * Resolve the mount-default I/O flavor.
 */
static enum fusex_io_flavor fusex_mount_io_flavor(const struct fuse_conn *fc)
{
	return FUSEX_IO_WRITEBACK;
}

/*
 * Resolve the per-file I/O flavor. Starts from the mount default and
 * narrows to DIRECT when the daemon set FOPEN_DIRECT_IO or the open
 * was O_DIRECT.
 */
static enum fusex_io_flavor fusex_file_io_flavor(const struct file *file,
						 const struct fuse_file *ff)
{
	if ((file->f_flags & O_DIRECT) || (ff->open_flags & FOPEN_DIRECT_IO))
		return FUSEX_IO_DIRECT;
	return fusex_mount_io_flavor(get_fuse_conn(file_inode(file)));
}

static const struct file_operations *fusex_fops_for(enum fusex_io_flavor f)
{
	switch (f) {
	case FUSEX_IO_DIRECT:	 return &fusex_fops_direct;
	case FUSEX_IO_WRITEBACK: return &fusex_fops_writeback;
	}
	return &fusex_fops_writeback;
}

static const struct address_space_operations *
fusex_aops_for(enum fusex_io_flavor f)
{
	switch (f) {
	case FUSEX_IO_DIRECT:	 return &fusex_aops_direct;
	case FUSEX_IO_WRITEBACK: return &fusex_aops_writeback;
	}
	return &fusex_aops_writeback;
}

static void fusex_dir_modified(struct inode *dir)
{
	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
	inode_inc_iversion(dir);
	__mark_inode_dirty(dir, I_DIRTY_SYNC);
}

static void fusex_update_ctime(struct inode *inode)
{
	inode_set_ctime_current(inode);
	__mark_inode_dirty(inode, I_DIRTY_SYNC);
}

/*
 * LOOKUPX + STATX in one round-trip. The STATX subop depends on
 * LOOKUPX's nodeid (filled in by the compound dispatcher's
 * fuse_compound_propagate_nodeid); for a negative lookup the STATX
 * fires against nodeid 0 and errors out — we ignore that error since
 * the caller checks the NEGATIVE flag and discards the attrs.
 */
static struct inode *fusex_do_lookup(struct inode *base, const struct qstr *name)
{
	FUSE_ARGS(args_lr);
	FUSE_ARGS(args_sx);
	struct fuse_entryx_out outarg_lr;
	struct fuse_statx_out outarg_sx;
	struct fuse_statx_in inarg_sx;
	struct fuse_compound_arg ops[2];
	struct fusex_id id;
	int err_lr = 0, err_sx = 0;
	ssize_t ret;

	args_lr.opcode = FUSE_LOOKUPX;
	args_lr.nodeid = get_node_id(base);
	ADD_IN_ARG_ZERO(args_lr);
	ADD_IN_ARG(args_lr, name->len + 1, name->name);
	ADD_OUT_ARG_S(args_lr, &outarg_lr);

	fusex_fill_statx(&args_sx, &inarg_sx, &outarg_sx);

	ops[0] = (struct fuse_compound_arg){
		.arg = &args_lr,
		.error = &err_lr,
		.dep_index = FUSE_COMPOUND_NO_DEP,
	};
	ops[1] = (struct fuse_compound_arg){
		.arg = &args_sx,
		.error = &err_sx,
		.dep_index = 0,
	};

	ret = fuse_compound_send(get_fuse_mount(base), ops, 2);
	if (ret < 0)
		return ERR_PTR(ret);
	if (err_lr < 0)
		return ERR_PTR(err_lr);

	if (outarg_lr.flags & FUSE_ENTRYX_NEGATIVE)
		return NULL;

	if (err_sx < 0)
		return ERR_PTR(err_sx);
	if (!fuse_valid_type(outarg_sx.stat.mode) ||
	    !fuse_valid_size(outarg_sx.stat.size))
		return ERR_PTR(-EIO);

	err_lr = fusex_id_from_args(&args_lr, &id);
	if (err_lr)
		return ERR_PTR(err_lr);

	return fusex_get_inode(base->i_sb, &id, &outarg_sx.stat);
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
	inarg.size = name ? XATTR_SIZE_MAX : XATTR_LIST_MAX;

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

	fusex_update_ctime(inode);

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
	bool update_mode;
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

	set_cached_acl(inode, type, acl);
	inode_set_ctime_current(inode);
	if (update_mode) {
		struct fuse_setstatx_in inarg;

		inode->i_mode = mode;
		memset(&inarg, 0, sizeof(inarg));
		inarg.stat.mask |= STATX_MODE;
		inarg.stat.mode = inode->i_mode & 07777;
		fusex_get_ctime(inode, &inarg.stat);

		err = fusex_send_setstatx(inode, &inarg);
	} else {
		__mark_inode_dirty(inode, I_DIRTY_SYNC);
	}

	return err;
}

/*
 * Compound dispatch for object creation. We always have MKOBJX and the
 * post-create STATX; if the parent dir contributed ACLs we also have one
 * or two SETXATTR subops. The STATX and the SETXATTRs all carry
 * dep_index = MKOBJX so the dispatcher (or the legacy fallback) fills in
 * the freshly minted nodeid before they run.
 */
static int fusex_do_mkobjx(struct inode *dir, struct inode *inode, const struct qstr *name,
			   const char *link_body, struct fuse_statx_out *outarg_sx)
{
	FUSE_ARGS(args_mk);
	FUSE_ARGS(args_xa_access);
	FUSE_ARGS(args_xa_default);
	FUSE_ARGS(args_sx);
	/* inarg_mk embeds a fuse_statx; together with the four FUSE_ARGS
	 * blocks on the stack the frame would exceed 1024 B, so heap it.
	 */
	struct fuse_mkobjx_in *inarg_mk __free(kfree) =
		kzalloc(sizeof(*inarg_mk), GFP_KERNEL);
	struct fuse_entryx_out outarg_mk;
	struct fuse_setxattr_in inarg_xa_access, inarg_xa_default;
	struct fuse_statx_in inarg_sx;
	void *acl_access __free(kfree) = NULL;
	void *acl_default __free(kfree) = NULL;
	size_t acl_access_size = 0, acl_default_size = 0;
	struct fuse_compound_arg ops[4];
	int err[4] = { 0 };
	unsigned int count = 0;
	const unsigned int mkobjx_idx = 0;
	struct user_namespace *u = i_user_ns(inode);
	struct fusex_id id;
	struct inode *old;
	int mk_flags = 0;
	ssize_t ret;
	int rc;
	unsigned int i;

	if (!inarg_mk)
		return -ENOMEM;

	/* --- MKOBJX --- */
	if (!name->len) {
		WARN_ON((inode->i_mode & S_IFMT) != S_IFREG);
		mk_flags |= FUSE_MKOBJX_TMPFILE;
	}
	inarg_mk->namesize = name->len + 1;
	inarg_mk->stat.mask = STATX_UID | STATX_GID | STATX_MODE | STATX_TYPE | STATX_BTIME;
	inarg_mk->stat.uid = from_kuid(u, inode->i_uid);
	inarg_mk->stat.gid = from_kgid(u, inode->i_gid);
	inarg_mk->stat.rdev_major = MAJOR(inode->i_rdev);
	inarg_mk->stat.rdev_minor = MINOR(inode->i_rdev);
	inarg_mk->stat.mode = inode->i_mode;
	fusex_get_atime(inode, &inarg_mk->stat);
	fusex_get_mtime(inode, &inarg_mk->stat);
	fusex_get_ctime(inode, &inarg_mk->stat);
	inarg_mk->stat.btime = inarg_mk->stat.ctime;
	inarg_mk->flags = mk_flags;

	args_mk.opcode = FUSE_MKOBJX;
	args_mk.nodeid = get_node_id(dir);
	/* Split header / stat so in_args[0] fits in io_uring's 128 B op_in */
	ADD_IN_ARG(args_mk, offsetof(struct fuse_mkobjx_in, stat), inarg_mk);
	ADD_IN_ARG_S(args_mk, &inarg_mk->stat);
	ADD_IN_ARG(args_mk, inarg_mk->namesize, name->name);
	if (S_ISLNK(inode->i_mode))
		ADD_IN_ARG(args_mk, strlen(link_body) + 1, link_body);
	ADD_OUT_ARG_S(args_mk, &outarg_mk);

	ops[count++] = (struct fuse_compound_arg){
		.arg = &args_mk,
		.error = &err[mkobjx_idx],
		.dep_index = FUSE_COMPOUND_NO_DEP,
	};

	/* --- ACL setxattrs (optional) --- */
	if (inode->i_acl) {
		acl_access = posix_acl_to_xattr(u, inode->i_acl,
						&acl_access_size, GFP_KERNEL);
		if (!acl_access)
			return -ENOMEM;
		fusex_fill_setxattr(&args_xa_access, &inarg_xa_access,
				    posix_acl_xattr_name(ACL_TYPE_ACCESS),
				    acl_access, acl_access_size, 0);
		ops[count] = (struct fuse_compound_arg){
			.arg = &args_xa_access,
			.error = &err[count],
			.dep_index = mkobjx_idx,
		};
		count++;
	}
	if (inode->i_default_acl) {
		acl_default = posix_acl_to_xattr(u, inode->i_default_acl,
						 &acl_default_size, GFP_KERNEL);
		if (!acl_default)
			return -ENOMEM;
		fusex_fill_setxattr(&args_xa_default, &inarg_xa_default,
				    posix_acl_xattr_name(ACL_TYPE_DEFAULT),
				    acl_default, acl_default_size, 0);
		ops[count] = (struct fuse_compound_arg){
			.arg = &args_xa_default,
			.error = &err[count],
			.dep_index = mkobjx_idx,
		};
		count++;
	}

	/* --- STATX --- */
	fusex_fill_statx(&args_sx, &inarg_sx, outarg_sx);
	ops[count] = (struct fuse_compound_arg){
		.arg = &args_sx,
		.error = &err[count],
		.dep_index = mkobjx_idx,
	};
	count++;

	ret = fuse_compound_send(get_fuse_mount(dir), ops, count);
	if (ret < 0)
		return ret;

	if (err[mkobjx_idx])
		return err[mkobjx_idx];

	/*
	 * MKOBJX succeeded: the server minted a nodeid. Record it on the
	 * inode now so that any failure below still leaves the eviction
	 * path able to send FORGET and reclaim the server-side reference.
	 */
	rc = fusex_id_from_args(&args_mk, &id);
	if (rc)
		return rc;
	get_fuse_inode(inode)->nodeid = id.nodeid;

	for (i = 0; i < count; i++) {
		if (i == mkobjx_idx)
			continue;
		if (err[i])
			return err[i];
	}

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
	fi->cached_i_blkbits = ilog2(statx->blksize);
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
		goto iput_noforget;

	err = fusex_do_mkobjx(dir, inode, name, link_body, &statx);
	if (err)
		goto iput;

	err = fusex_setup_new_inode(inode, &statx.stat);
	if (err) {
		discard_new_inode(inode);
		return ERR_PTR(err);
	}

	return inode;

iput_noforget:
	{
		struct fuse_inode *fi = get_fuse_inode(inode);

		kfree(fi->forget);
		fi->forget = NULL;
	}
iput:
	/*
	 * If MKOBJX succeeded fi->nodeid is set; eviction will FORGET it.
	 * If MKOBJX itself failed fi->nodeid is 0 and evict skips FORGET.
	 */
	iput(inode);
	return ERR_PTR(err);
}

static int fusex_mkobj(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode, dev_t rdev, const char *link_body)
{
	struct inode *inode = fusex_new_inode(idmap, dir, &dentry->d_name, mode, rdev, link_body);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	fusex_dir_modified(dir);
	d_instantiate_new(dentry, inode);

	return 0;
}

static int fusex_create(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode, bool excl)
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

	drop_nlink(inode);
	fusex_update_ctime(inode);
	fusex_dir_modified(dir);

	return 0;
}

static int fusex_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = d_inode(dentry);
	struct user_namespace *user_ns = i_user_ns(inode);
	struct fuse_setstatx_in inarg;
	int err;

	err = setattr_prepare(idmap, dentry, iattr);
	if (err)
		return err;

	if ((iattr->ia_valid & ATTR_SIZE) && iattr->ia_size != inode->i_size)
		iattr->ia_valid |= ATTR_MTIME | ATTR_CTIME;

	memset(&inarg, 0, sizeof(inarg));
	if (iattr->ia_valid & ATTR_FILE)
		inarg.fh = fusex_file_fh(iattr->ia_file);
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

	setattr_copy(idmap, inode, iattr);
	if (iattr->ia_valid & ATTR_SIZE) {
		loff_t old_size = inode->i_size;

		i_size_write(inode, iattr->ia_size);
		fusex_extend_file(inode, old_size, inode->i_size);
		truncate_pagecache(inode, inode->i_size);
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

	fusex_update_ctime(oldinode);
	if (newinode) {
		if (!(flags & RENAME_EXCHANGE))
			drop_nlink(newinode);
		fusex_update_ctime(newinode);
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

	ihold(inode);
	inc_nlink(inode);
	fusex_update_ctime(inode);
	fusex_dir_modified(newdir);
	d_instantiate(newdentry, inode);

	return 0;
}

static const struct inode_operations fusex_file_inode_operations = {
	.getattr	= fusex_getattr,
	.setattr	= fusex_setattr,
	.get_inode_acl	= fusex_get_acl,
	.set_acl	= fusex_set_acl,
	.listxattr	= fusex_listxattr,
};

static const struct inode_operations fusex_dir_inode_operations = {
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

static const struct inode_operations fusex_symlink_inode_operations = {
	.getattr	= fusex_getattr,
	.get_link	= page_get_link,
	.listxattr	= fusex_listxattr,
};

static struct fuse_file *fusex_file_alloc(void)
{
	struct fuse_file *ff;

	ff = kzalloc(sizeof(*ff) + sizeof(*ff->args), GFP_KERNEL_ACCOUNT);
	if (ff)
		ff->args = (void *)(ff + 1);

	return ff;
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
		ff->open_flags = FOPEN_CACHE_DIR;
		ff->nodeid = get_node_id(inode);
	}
	return err;
}

static int fusex_dir_open(struct inode *inode, struct file *file)
{
	struct fuse_file *ff __free(kfree) = fusex_file_alloc();
	struct fuse_release_args *ra;
	int err;

	if (!ff)
		return -ENOMEM;

	ra = &ff->args->release_args;
	ADD_IN_ARG_S(ra->args, &ra->inarg);

	err = fusex_send_opendir(ff, inode);
	if (err)
		return err;

	file->private_data = no_free_ptr(ff);
	return 0;
}

struct fusex_iput_work {
	struct work_struct	work;
	struct inode		*inode;
};

static struct workqueue_struct *fusex_iput_wq;

static void fusex_iput_worker(struct work_struct *w)
{
	struct fusex_iput_work *iw = container_of(w, struct fusex_iput_work,
						  work);

	iput(iw->inode);
	kfree(iw);
}

static void fusex_release_end(struct fuse_args *args, int error)
{
	struct fuse_release_args *ra = container_of(args, typeof(*ra), args);
	struct fuse_file *ff = (struct fuse_file *) ra - 1;
	struct fusex_iput_work *iw;

	/*
	 * Reached from fuse_uring_cmd's COMMIT_AND_FETCH path while the
	 * daemon is sitting in io_uring_enter. iput() may evict and block
	 * on inode_wait_for_writeback(); writeback needs the daemon to
	 * service FUSE_WRITE on the same task -> self-deadlock. Push the
	 * iput to a kworker so the daemon's submit task returns promptly.
	 * fusex_kill_sb_anon() drains fusex_iput_wq before kill_anon_super()
	 * to keep the deferred iput from racing the superblock teardown.
	 */
	iw = kmalloc(sizeof(*iw), GFP_NOFS);
	if (likely(iw)) {
		iw->inode = ra->inode;
		INIT_WORK(&iw->work, fusex_iput_worker);
		queue_work(fusex_iput_wq, &iw->work);
	} else {
		iput(ra->inode);
	}
	kfree(ff);
}

static int fusex_dir_release(struct inode *inode, struct file *file)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_release_args *ra = &ff->args->release_args;

	ra->inarg.fh = ff->fh;

	ra->args.opcode = FUSE_RELEASEDIR;
	ra->args.force = true;
	ra->args.nocreds = true;
	ra->args.end = fusex_release_end;
	ra->inode = igrab(inode);

	if (fuse_simple_background(fm, &ra->args, GFP_KERNEL | __GFP_NOFAIL))
		fusex_release_end(&ra->args, -ENOTCONN);

	return 0;
}

static int fusex_send_open(struct fuse_file *ff, struct inode *inode,
			   unsigned int flags)
{
	struct fuse_open_in inarg;
	struct fuse_open_out outarg;
	FUSE_ARGS(args);
	int err;

	memset(&inarg, 0, sizeof(inarg));
	/* O_NOCTTY is tty-only and meaningless to a userspace daemon;
	 * matches what mainline FUSE strips before forwarding.
	 */
	inarg.flags = flags & ~O_NOCTTY;

	args.opcode = FUSE_OPEN;
	ADD_IN_ARG_S(args, &inarg);
	ADD_OUT_ARG_S(args, &outarg);

	err = fusex_inode_request(inode, &args);
	if (!err) {
		ff->fh = outarg.fh;
		ff->open_flags = outarg.open_flags;
		ff->nodeid = get_node_id(inode);
	}
	return err;
}

static int fusex_file_open(struct inode *inode, struct file *file)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_file *ff __free(kfree) = fusex_file_alloc();
	struct fuse_release_args *ra;
	int err;

	if (!ff)
		return -ENOMEM;

	ra = &ff->args->release_args;
	ADD_IN_ARG_S(ra->args, &ra->inarg);

	err = fusex_send_open(ff, inode, file->f_flags);
	if (err)
		return err;

	/* Narrow to DIRECT per-fd if asked. Only file->f_op is swapped;
	 * the inode's i_fop / a_ops stay on the mount default. */
	if (fusex_file_io_flavor(file, ff) == FUSEX_IO_DIRECT)
		file->f_op = fusex_fops_for(FUSEX_IO_DIRECT);

	/*
	 * Writeback runs without a struct file, so fusex_writepages picks
	 * an fh off this list. Any writable opener is fair game.
	 */
	if (file->f_mode & FMODE_WRITE) {
		spin_lock(&fi->lock);
		list_add_tail(&ff->write_entry, &fi->write_files);
		spin_unlock(&fi->lock);
	}

	file->private_data = no_free_ptr(ff);
	return 0;
}

static int fusex_file_release(struct inode *inode, struct file *file)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_release_args *ra = &ff->args->release_args;

	if (file->f_mode & FMODE_WRITE) {
		spin_lock(&fi->lock);
		list_del(&ff->write_entry);
		spin_unlock(&fi->lock);
	}

	ra->inarg.fh = ff->fh;
	ra->inarg.flags = file->f_flags;

	ra->args.opcode = FUSE_RELEASE;
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
	.fsync		= simple_fsync_noflush,
};

static int fusex_symlink_read_folio(struct file *null, struct folio *folio)
{
	struct inode *inode = folio->mapping->host;
	struct fuse_folio_desc desc = { .length = folio_size(folio) - 1 };
	struct fuse_args_pages ap = {};
	ssize_t res;

	ap.args.opcode = FUSE_READLINK;
	ADD_IN_ARG_ZERO(ap.args);
	ADD_OUT_ARG(ap.args, desc.length, NULL);
	ap.args.out_pages = true;
	ap.args.out_argvar = true;
	ap.args.page_zeroing = true;
	ap.num_folios = 1;
	ap.folios = &folio;
	ap.descs = &desc;
	res = fusex_inode_request(inode, &ap.args);
	if (res >= 0) {
		folio_mark_uptodate(folio);
		res = 0;
	}
	folio_unlock(folio);
	return res;
}

static const struct address_space_operations fusex_symlink_aops = {
	.read_folio	= fusex_symlink_read_folio,
};

static void fusex_init_inode(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		INIT_LIST_HEAD(&fi->write_files);
		inode->i_op = &fusex_file_inode_operations;
		{
			struct fuse_conn *fc = get_fuse_conn(inode);
			enum fusex_io_flavor f = fusex_mount_io_flavor(fc);

			inode->i_fop = fusex_fops_for(f);
			inode->i_data.a_ops = fusex_aops_for(f);
		}
		mapping_set_writeback_may_deadlock_on_reclaim(&inode->i_data);
		break;

	case S_IFDIR:
		spin_lock_init(&fi->rdc.lock);
		inode->i_op = &fusex_dir_inode_operations;
		inode->i_fop = &fusex_dir_operations;
		break;

	case S_IFLNK:
		inode->i_op = &fusex_symlink_inode_operations;
		inode->i_data.a_ops = &fusex_symlink_aops;
		inode_nohighmem(inode);
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

static int fusex_send_init(struct fuse_mount *fm, struct fusex_id *id,
			   struct fuse_statx_out *statx)
{
	FUSE_ARGS(args_in);
	FUSE_ARGS(args_lr);
	FUSE_ARGS(args_sx);
	struct fuse_init_in inarg_in;
	struct fuse_init_out outarg_in;
	struct fuse_entryx_out outarg_lr;
	struct fuse_statx_in inarg_sx;
	u64 flags = FUSE_INIT_EXT | FUSE_OVER_IO_URING | FUSE_WRITEBACK_CACHE;
	int err;

	memset(&inarg_in, 0, sizeof(inarg_in));
	inarg_in.major = FUSE_KERNEL_VERSION;
	inarg_in.minor = FUSE_KERNEL_MINOR_VERSION;
	inarg_in.flags = flags;
	inarg_in.flags2 = flags >> 32;
	args_in.opcode = FUSE_INIT;
	ADD_IN_ARG_S(args_in, &inarg_in);
	ADD_OUT_ARG_S(args_in, &outarg_in);
	err = fuse_simple_request(fm, &args_in);
	if (err)
		return err;

	flags = outarg_in.flags;
	if (!(flags & FUSE_INIT_EXT))
		return -EINVAL;

	flags |= (u64) outarg_in.flags2 << 32;

	fm->fc->minor = outarg_in.minor;
	fm->fc->max_write = outarg_in.max_write;
	fm->fc->max_pages = min_t(unsigned int, fm->fc->max_pages_limit,
				  max_t(unsigned int, outarg_in.max_pages, 1));

	args_lr.opcode = FUSE_LOOKUP_ROOT;
	ADD_OUT_ARG_S(args_lr, &outarg_lr);
	err = fuse_simple_request(fm, &args_lr);
	if (err)
		return err;

	err = fusex_id_from_args(&args_lr, id);
	if (err)
		return err;

	fusex_fill_statx(&args_sx, &inarg_sx, statx);
	args_sx.nodeid = id->nodeid;
	err = fuse_simple_request(fm, &args_sx);
	if (err)
		return err;

	if (!(flags & FUSE_OVER_IO_URING))
		return -EPROTONOSUPPORT;

	return 0;
}

static int fusex_fill_super(struct super_block *sb, struct fs_context *fsc)
{
	struct fuse_mount *fm = get_fuse_mount_super(sb);
	struct fuse_conn *fc = fm->fc;
	struct inode *inode;
	struct fusex_id id;
	struct fuse_statx_out statx;
	struct fuse_chan_param cp;
	int err;

	/* Dropped in fuse_mount_destroy() */
	fuse_conn_get(fc);
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
	sb->s_flags |= SB_POSIXACL;

	err = fusex_send_init(fm, &id, &statx);
	if (err)
		return err;

	inode = fusex_iget(sb, &id);
	if (inode) {
		WARN_ON(!(inode_state_read_once(inode) & I_NEW));
		fusex_set_attr(inode, &statx.stat);
		fusex_init_inode(inode);
		unlock_new_inode(inode);
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	fc->parallel_dirops = true;
	fc->destroy = true;

	cp.minor = fc->minor;
	cp.max_write = fc->max_write;
	cp.max_pages = fc->max_pages;
	fuse_chan_set_initialized(fc->chan, &cp);

	return 0;
}

static int fusex_get_tree(struct fs_context *fsc)
{
	struct fuse_dev *fud = fsc->fs_private;
	struct fuse_conn *fc __free(kfree) = kmalloc_obj(*fc);
	struct fuse_mount *fm __free(kfree) = kzalloc_obj(*fm);
	struct fuse_chan *fch;

	/* Legacy mount(2) bypasses fsconfig() so the FSCONFIG_SET_FD case in
	 * fusex_parse_param() never ran and fs_private is NULL. Reject cleanly
	 * instead of dereferencing it in fuse_dev_chan_get() below.
	 */
	if (!fud)
		return invalfc(fsc, "fusex requires fsconfig(FSCONFIG_SET_FD); legacy mount(2) is not supported");

	/* Channel was installed at SET_FD so the daemon could pre-register
	 * io_uring entries; pick it up and bind it to the freshly allocated fc.
	 */
	fch = fuse_dev_chan_get(fud);

	if (!fc || !fm)
		return -ENOMEM;
	if (!fch || fch == FUSE_DEV_CHAN_DISCONNECTED)
		return -EIO;

	fc->release = fuse_free_conn;
	fsc->s_fs_info = fm;
	fuse_conn_init(no_free_ptr(fc), no_free_ptr(fm), fsc->user_ns, fch);
	fuse_chan_set_initialized(fch, NULL);
	/* Take the conn reference that fuse_dev_install() skipped at SET_FD */
	fuse_conn_get(fch->conn);

	/*
	 * Override the generic fuse-over-io_uring iqueue ops so FORGETs
	 * travel through the rings instead of accumulating on the legacy
	 * fiq->forget_list. fuse_uring_register() set fch->iq.ops while
	 * the daemon was REGISTERing entries; that swap is complete by the
	 * time the daemon issues CMD_CREATE (which is what triggers this
	 * function), so this write races with nothing. No FORGETs can
	 * fire yet either — fusex_fill_super() has not even sent INIT.
	 */
	if (fuse_uring_ready(fch))
		WRITE_ONCE(fch->iq.ops, &fusex_io_uring_ops);

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
	int opt;

	if (fsc->purpose == FS_CONTEXT_FOR_RECONFIGURE)
		return invalfc(fsc, "No changes allowed in reconfigure");

	opt = fs_parse(fsc, fusex_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case FUSEX_OPT_FD: {
		struct fuse_chan *fch;

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
			return invalfc(fsc, "device already attached to a mount");
		}

		/* Install channel now so the daemon can pre-register io_uring
		 * entries before CMD_CREATE; conn is bound in fusex_get_tree().
		 * fusex always runs over io_uring, so flip the channel's bit
		 * up front: this bypasses the `enable_uring` module-param gate
		 * in the REGISTER cmd path so daemons don't have to twiddle a
		 * sysfs knob just to mount.
		 */
		fch = fuse_dev_chan_new();
		if (!fch) {
			fuse_dev_put(fud);
			return -ENOMEM;
		}
		fuse_dev_install(fud, fch);
		fuse_chan_io_uring_enable(fch);
		fsc->fs_private = fud;
		break;
	}

	default:
		return -EINVAL;
	}

	return 0;
}

static void fusex_free_fsc(struct fs_context *fsc)
{
	struct fuse_dev *fud = fsc->fs_private;

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

	if (sb->s_root) {
		if (fuse_mount_remove(fm))
			fuse_conn_destroy(fm);
	}
	/*
	 * fusex_release_end() defers iput() to fusex_iput_wq. Drain it
	 * here so any in-flight iput finishes (and releases its inode
	 * reference) before kill_anon_super() tears the superblock down.
	 */
	flush_workqueue(fusex_iput_wq);
	kill_anon_super(sb);
	fuse_mount_destroy(fm);
}

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

	fusex_iput_wq = alloc_workqueue("fusex_iput", WQ_UNBOUND, 0);
	if (!fusex_iput_wq)
		return -ENOMEM;

	err = register_filesystem(&fusex_fs_type);
	if (err) {
		destroy_workqueue(fusex_iput_wq);
		fusex_iput_wq = NULL;
	}
	return err;
}

void __exit fusex_cleanup(void)
{
	unregister_filesystem(&fusex_fs_type);
	destroy_workqueue(fusex_iput_wq);
}
