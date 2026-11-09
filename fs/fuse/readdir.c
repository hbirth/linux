// SPDX-License-Identifier: GPL-2.0
/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2018  Miklos Szeredi <miklos@szeredi.hu>
*/


#include "fuse_i.h"
#include "dev.h"
#include <linux/pagemap.h>
#include <linux/vmalloc.h>

static int parse_dirfile(char *buf, size_t nbytes, struct dir_context *ctx)
{
	while (nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		if (!dir_emit(ctx, dirent->name, dirent->namelen, dirent->ino,
			      dirent->type | FILLDIR_FLAG_NOINTR))
			break;

		buf += reclen;
		nbytes -= reclen;
		ctx->pos = dirent->off;
	}

	return 0;
}

static struct page **fuse_readdir_alloc_buf(struct fuse_args_pages *ap, size_t *bufsize)
{
	unsigned int i, nr_alloc, nr_pages = DIV_ROUND_UP(*bufsize, PAGE_SIZE);
	struct page **pages = kzalloc_objs(*pages, nr_pages);

	if (!pages)
		return NULL;

	nr_alloc = alloc_pages_bulk(GFP_KERNEL, nr_pages, pages);
	if (!nr_alloc)
		goto free_array;

	if (nr_alloc < nr_pages) {
		nr_pages = nr_alloc;
		*bufsize = (size_t) nr_pages << PAGE_SHIFT;
	}

	ap->folios = fuse_folios_alloc(nr_pages, GFP_KERNEL, &ap->descs);
	if (!ap->folios)
		goto release_pages;

	for (i = 0; i < nr_pages; i++) {
		ap->folios[i] = page_folio(pages[i]);
		ap->descs[i].length = min_t(size_t, *bufsize - (size_t)i * PAGE_SIZE, PAGE_SIZE);
	}
	ap->num_folios = nr_pages;
	ap->args.out_pages = true;

	return pages;

release_pages:
	release_pages(pages, nr_pages);
free_array:
	kfree(pages);
	return NULL;
}

int fuse_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_read_in inarg = {};
	struct fuse_args_pages ap = {};
	void *buf;
	ssize_t res;
	/* fc->max_pages can exceed the payload buffer when I/O is zero-copied */
	size_t bufsize = clamp((size_t) ctx->count, PAGE_SIZE,
			       umin((size_t) fm->fc->max_pages << PAGE_SHIFT,
				    fuse_uring_max_payload(fm->fc->chan)));
	struct page **pages = fuse_readdir_alloc_buf(&ap, &bufsize);

	if (!pages)
		return -ENOMEM;

	inarg.fh = ff->fh;
	inarg.offset = ctx->pos;
	inarg.size = bufsize;
	inarg.flags = file->f_flags;
	ap.args.opcode = FUSE_READDIR;
	ap.args.nodeid = ff->nodeid;
	ap.args.in_numargs = 1;
	ap.args.in_args[0].size = sizeof(inarg);
	ap.args.in_args[0].value = &inarg;
	ap.args.out_argvar = true;
	ap.args.out_numargs = 1;
	ap.args.out_args[0].size = bufsize;

	res = fuse_simple_request(fm, &ap.args);
	if (res <= 0)
		goto out;

	buf = vm_map_ram(pages, ap.num_folios, -1);
	if (!buf) {
		res = -ENOMEM;
	} else {
		res = parse_dirfile(buf, res, ctx);
		vm_unmap_ram(buf, ap.num_folios);
	}
out:
	kfree(ap.folios);
	release_pages(pages, ap.num_folios);
	kfree(pages);

	fuse_invalidate_atime(inode);

	return res;
}
