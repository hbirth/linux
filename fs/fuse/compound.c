// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025-2026
 *
 * Compound operations for FUSE - batch multiple operations into a single
 * request to reduce round trips between kernel and userspace.
 */

#include "fuse_i.h"

/*
 * Fill in arguments for a dependent operation from the output of a previous operation.
 *
 * This function extracts data from the output of a dependency operation and uses it
 * to populate the input arguments of the dependent operation. The specific data
 * extracted depends on the opcode of the dependency operation.
 */
static void fill_in_args_from_out(struct fuse_args *dep_args,
				   const struct fuse_args *entry_args)
{
	if (entry_args->out_numargs == 0)
		return;

	/*
	 * Different operations return different output structures.
	 * Extract the appropriate data based on the operation type.
	 */
	switch (entry_args->opcode) {
	case FUSE_LOOKUP:
	case FUSE_MKNOD:
	case FUSE_MKDIR:
	case FUSE_SYMLINK:
	case FUSE_LINK:
	case FUSE_CREATE:
	case FUSE_TMPFILE: {
		/*
		 * These operations return fuse_entry_out with nodeid as first
		 * field. CREATE/TMPFILE also return fuse_open_out as second.
		 */
		const struct fuse_entry_out *entry_out;

		entry_out = entry_args->out_args[0].value;
		if (entry_out)
			dep_args->nodeid = entry_out->nodeid;
		break;
	}
	default:
		/* this is an error in the compound request setup */
		WARN_ON(1);
		break;
	}
}

static ssize_t fuse_compound_send_legacy(struct fuse_mount *fm,
					 struct fuse_compound_arg *arg,
					 unsigned int count)
{
	ssize_t ret = 0;
	unsigned int i;

	/* Send each operation as a separate request */
	for (i = 0; i < count; i++) {
		struct fuse_compound_arg *cur = &arg[i];
		struct fuse_compound_req_in *cur_req = cur->req;

		if (cur_req->flags & FUSE_COMPOUND_SUB_IS_DEP) {
			struct fuse_compound_arg *dep = &arg[cur_req->sub_dep_index];
			struct fuse_compound_req_in *dep_req = dep->req;

			/*
			 * This operation depends on a previous one.
			 * Check if the dependency succeeded before proceeding.
			 */
			if (*dep->error == 0 &&
			    dep_req->flags & FUSE_COMPOUND_SUB_IS_ENTRY) {
				/* Dependency succeeded, fill in arguments */
				fill_in_args_from_out(cur->arg, dep->arg);
			} else {
				/* Dependency failed, skip this operation */
				*cur->error = *dep->error;
				continue;
			}
		}
		ret = fuse_simple_request(fm, cur->arg);
		*cur->error = ret;
	}

	return ret;
}

ssize_t fuse_compound_send(struct fuse_mount *fm,
			   struct fuse_compound_arg *arg, unsigned int count)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_compound_args compound_args = {
		.args = {
			.opcode = FUSE_COMPOUND,
			.in_numargs = 1,
			.out_numargs = 1,
			.out_argvar = false,
		},
		.ops = arg,
		.count = count,
		.in_header = {
			.reserved = {0, 0},
		},
	};
	ssize_t ret;

	/* we have no compounds support, no point in trying */
	if (fc->compound_ops == 0)
		return fuse_compound_send_legacy(fm, arg, count);

	/* Set up input args - the compound header is visible here */
	compound_args.args.in_args[0].size = sizeof(compound_args.in_header);
	compound_args.args.in_args[0].value = &compound_args.in_header;

	/* Set up output args - only the compound header, no buffer needed */
	compound_args.args.out_args[0].size = sizeof(compound_args.out_header);
	compound_args.args.out_args[0].value = &compound_args.out_header;

	/* Send compound request and wait for response */
	ret = fuse_send_compound_request(&invalid_mnt_idmap, fm,
					 &compound_args);
	if (ret < 0) {
		if (ret == -ENOSYS) {
			fc->compound_ops = 0;
			return fuse_compound_send_legacy(fm, arg, count);
		}
		return ret;  /* Propagate other errors */
	}

	return 0;
}
