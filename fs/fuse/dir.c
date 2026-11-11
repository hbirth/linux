// SPDX-License-Identifier: GPL-2.0
/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
*/

#include "fuse_i.h"

#include <linux/moduleparam.h>
#include <linux/namei.h>

static bool __read_mostly allow_sys_admin_access;
module_param(allow_sys_admin_access, bool, 0644);
MODULE_PARM_DESC(allow_sys_admin_access,
		 "Allow users with CAP_SYS_ADMIN in initial userns to bypass the user namespace check");

void fuse_invalidate_attr_mask(struct inode *inode, u32 mask)
{
	set_mask_bits(&get_fuse_inode(inode)->inval_mask, 0, mask);
}

/*
 * Mark the attributes as stale, so that at the next call to
 * ->getattr() they will be fetched from userspace
 */
void fuse_invalidate_attr(struct inode *inode)
{
	fuse_invalidate_attr_mask(inode, STATX_BASIC_STATS);
}

/* A fetch sets nlink under fi->lock */
void fuse_drop_nlink(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	spin_lock(&fi->lock);
	if (inode->i_nlink)
		drop_nlink(inode);
	spin_unlock(&fi->lock);
}

static void fuse_dir_changed(struct inode *dir)
{
	fuse_invalidate_attr_mask(dir, FUSE_STATX_MODDIR);
}

/*
 * Mark the attributes as stale due to an atime change.  Avoid the invalidate if
 * atime is not used.
 */
void fuse_invalidate_atime(struct inode *inode)
{
	if (!IS_RDONLY(inode))
		fuse_invalidate_attr_mask(inode, STATX_ATIME);
}

int fuse_valid_type(int m)
{
	return S_ISREG(m) || S_ISDIR(m) || S_ISLNK(m) || S_ISCHR(m) ||
		S_ISBLK(m) || S_ISFIFO(m) || S_ISSOCK(m);
}

bool fuse_valid_size(u64 size)
{
	return size <= LLONG_MAX;
}

int fuse_reverse_inval_entry(struct fuse_conn *fc, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name)
{
	int err = -ENOTDIR;
	struct inode *parent;
	struct dentry *dir;
	struct dentry *entry;

	parent = fuse_ilookup(fc, parent_nodeid);
	if (!parent)
		return -ENOENT;

	inode_lock_nested(parent, I_MUTEX_PARENT);
	if (!S_ISDIR(parent->i_mode))
		goto unlock;

	err = -ENOENT;
	dir = d_find_alias(parent);
	if (!dir)
		goto unlock;

	name->hash = full_name_hash(dir, name->name, name->len);
	entry = d_lookup(dir, name);
	dput(dir);
	if (!entry)
		goto unlock;

	fuse_dir_changed(parent);
	/* There is no revalidation, so an entry can't just expire */
	d_invalidate(entry);

	if (child_nodeid != 0 && d_really_is_positive(entry)) {
		inode_lock(d_inode(entry));
		if (get_node_id(d_inode(entry)) != child_nodeid) {
			err = -ENOENT;
			goto badentry;
		}
		if (d_mountpoint(entry)) {
			err = -EBUSY;
			goto badentry;
		}
		if (d_is_dir(entry)) {
			shrink_dcache_parent(entry);
			if (!simple_empty(entry)) {
				err = -ENOTEMPTY;
				goto badentry;
			}
			d_inode(entry)->i_flags |= S_DEAD;
		}
		dont_mount(entry);
		/* It can have other names, the attributes tell */
		fuse_drop_nlink(d_inode(entry));
		fuse_invalidate_attr(d_inode(entry));
		err = 0;
 badentry:
		inode_unlock(d_inode(entry));
		if (!err)
			d_delete(entry);
	} else {
		err = 0;
	}
	dput(entry);

 unlock:
	inode_unlock(parent);
	iput(parent);
	return err;
}

/*
 * Calling into a user-controlled filesystem gives the filesystem
 * daemon ptrace-like capabilities over the current process.  This
 * means, that the filesystem daemon is able to record the exact
 * filesystem operations performed, and can also control the behavior
 * of the requester process in otherwise impossible ways.  For example
 * it can delay the operation for arbitrary length of time allowing
 * DoS against the requester.
 *
 * For this reason only those processes can call into the filesystem,
 * for which the owner of the mount has ptrace privilege.  This
 * excludes processes started by other users, suid or sgid processes.
 */
bool fuse_allow_current_process(struct fuse_conn *fc)
{
	bool allow = current_in_userns(fc->user_ns);

	if (!allow && allow_sys_admin_access && capable(CAP_SYS_ADMIN))
		allow = true;

	return allow;
}
