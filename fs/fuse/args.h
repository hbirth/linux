/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _FS_FUSE_ARGS_H
#define _FS_FUSE_ARGS_H

#include <linux/types.h>

/** One input argument of a request */
struct fuse_in_arg {
	unsigned size;
	const void *value;
};

/** One output argument of a request */
struct fuse_arg {
	unsigned size;
	void *value;
};

struct fuse_args {
	u64 nodeid;
	u32 opcode;
	u32 uid;
	u32 gid;
	u32 pid;
	u8 in_numargs;
	u8 out_numargs;
	bool force:1;
	bool nocreds:1;
	bool in_pages:1;
	bool out_pages:1;
	bool out_argvar:1;
	bool out_var_alloc:1;
	bool abort_on_kill:1;
	/* the pages can take a reference, for io-uring zero copy */
	bool zero_copy:1;
	struct fuse_in_arg in_args[4];
	struct fuse_arg out_args[2];
	void (*end)(struct fuse_args *args, int error);
};

/** FUSE folio descriptor */
struct fuse_folio_desc {
	unsigned int length;
	unsigned int offset;
};

struct fuse_args_pages {
	struct fuse_args args;
	struct folio **folios;
	struct fuse_folio_desc *descs;
	unsigned int num_folios;
};

#endif /* _FS_FUSE_ARGS_H */
