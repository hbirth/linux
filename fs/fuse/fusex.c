// SPDX-License-Identifier: GPL-2.0-only

#include "fusex.h"
#include "dev.h"
#include "fuse_i.h"
#include "fuse_dev_i.h"  /* fuse_dev_chan_get, FUSE_DEV_CHAN_DISCONNECTED */

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

static const struct file_operations fusex_file_operations = {
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.splice_read	= filemap_splice_read,
	.splice_write	= iter_file_splice_write,
	.llseek		= generic_file_llseek,
	.mmap_prepare	= generic_file_mmap_prepare,
	.fsync		= simple_fsync_noflush,
	.fallocate	= fusex_file_fallocate,
};

static int fusex_send_read(struct inode *inode, loff_t pos, struct file *file,
			   struct folio *folio, unsigned int off, unsigned int len)
{
	struct fuse_args_pages ap = {};
	struct fuse_folio_desc desc = { .offset = off, .length = len };
	struct fuse_read_in inarg;
	ssize_t res;

	memset(&inarg, 0, sizeof(inarg));
	inarg.offset = pos;
	inarg.size = len;
	inarg.flags = file->f_flags;
	ap.args.opcode = FUSE_READ;
	ADD_IN_ARG_S(ap.args, &inarg);
	ADD_OUT_ARG(ap.args, len, NULL);
	ap.args.out_argvar = true;
	ap.args.out_pages = true;
	ap.num_folios = 1;
	ap.folios = &folio;
	ap.descs = &desc;

	res = fusex_inode_request(inode, &ap.args);
	if (res < 0)
		return res;

	WARN_ON(res > len);
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

static int fusex_send_write(struct inode *inode, loff_t pos,
			     struct folio *folio, unsigned int off, unsigned int len)
{
	struct fuse_args_pages ap = {};
	struct fuse_folio_desc desc = { .offset = off, .length = len };
	struct fuse_write_in inarg;
	struct fuse_write_out outarg;
	int err;

	memset(&inarg, 0, sizeof(inarg));
	inarg.offset = pos;
	inarg.size = len;

	ap.args.opcode = FUSE_WRITE;
	ADD_IN_ARG_S(ap.args, &inarg);
	ADD_IN_ARG(ap.args, len, NULL);
	ap.args.in_pages = true;
	ap.num_folios = 1;
	ap.folios = &folio;
	ap.descs = &desc;
	ADD_OUT_ARG_S(ap.args, &outarg);

	err = fusex_inode_request(inode, &ap.args);
	if (err)
		return err;

	if (outarg.size != len)
		return -EIO;

	return 0;
}

static int fusex_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	struct folio *folio = NULL;
	int err;

	while ((folio = writeback_iter(mapping, wbc, folio, &err))) {
		struct inode *inode = folio->mapping->host;
		loff_t folio_start = folio_pos(folio);
		loff_t i_size = i_size_read(inode);
		size_t full_len = folio_size(folio), len = full_len;

		if (folio_start < i_size) {
			if (i_size < folio_start + full_len)
				len = i_size - folio_start;

			err = fusex_send_write(inode, folio_start, folio, 0, len);
		}
		folio_unlock(folio);
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
	loff_t old_size = i_size_read(inode);
	loff_t pos = iocb->ki_pos;
	int err = 0;

	if (!iov_iter_count(iter) || (iov_iter_rw(iter) == READ && pos >= old_size))
		return 0;

	for (;;) {
		struct page **pages = NULL;
		struct folio *folio;
		ssize_t len;
		size_t off;

		len = iov_iter_extract_pages(iter, &pages, PAGE_SIZE, 1, 0, &off);
		if (len <= 0) {
			err = len;
			break;
		}

		folio = page_folio(pages[0]);
		off += folio_page_idx(folio, pages[0]) * PAGE_SIZE;
		kvfree(pages);

		if (iov_iter_rw(iter) == WRITE) {
			err = fusex_send_write(inode, pos, folio, off, len);
		} else {
			if (pos + len > old_size)
				len = old_size - pos;

			err = fusex_send_read(inode, pos, iocb->ki_filp, folio, off, len);
			if (!err && user_backed_iter(iter))
				folio_mark_dirty_lock(folio);
		}
		if (iov_iter_extract_will_pin(iter))
			unpin_folio(folio);

		if (err || !len)
			break;
		pos += len;
	}
	if (pos > iocb->ki_pos) {
		if (iov_iter_rw(iter) == WRITE) {
			if (pos > old_size)
				i_size_write(inode, pos);
			fusex_extend_file(inode, old_size, iocb->ki_pos);
		}
	}

	return (pos - iocb->ki_pos) ?: err;
}

static const struct address_space_operations fusex_file_aops  = {
	.read_folio	= fusex_read_folio,
	.writepages	= fusex_writepages,
	.write_begin	= fusex_write_begin,
	.write_end	= fusex_write_end,
	.direct_IO	= fusex_direct_IO,
	.dirty_folio	= filemap_dirty_folio,
	.migrate_folio	= filemap_migrate_folio,
};

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

static void fusex_release_end(struct fuse_args *args, int error)
{
	struct fuse_release_args *ra = container_of(args, typeof(*ra), args);
	struct fuse_file *ff = (struct fuse_file *) ra - 1;

	iput(ra->inode);
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
		inode->i_op = &fusex_file_inode_operations;
		inode->i_fop = &fusex_file_operations;
		inode->i_data.a_ops = &fusex_file_aops;
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
	u64 flags = FUSE_INIT_EXT;
	int err;

	if (fuse_uring_enabled())
		flags |= FUSE_OVER_IO_URING;

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

	if (flags & FUSE_OVER_IO_URING && fuse_uring_enabled())
		fuse_chan_io_uring_enable(fm->fc->chan);

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
	/* Channel was installed at SET_FD so the daemon could pre-register
	 * io_uring entries; pick it up and bind it to the freshly allocated fc.
	 */
	struct fuse_chan *fch = fuse_dev_chan_get(fud);

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
		 */
		fch = fuse_dev_chan_new();
		if (!fch) {
			fuse_dev_put(fud);
			return -ENOMEM;
		}
		fuse_dev_install(fud, fch);
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

	kill_anon_super(sb);
	fuse_conn_destroy(fm);
	fuse_mount_remove(fm);
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
	return register_filesystem(&fusex_fs_type);
}

void __exit fusex_cleanup(void)
{
	unregister_filesystem(&fusex_fs_type);
}
