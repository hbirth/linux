/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _FS_FUSE_DEV_H
#define _FS_FUSE_DEV_H

#include <linux/cleanup.h>

/** Maximum number of outstanding background requests */
#define FUSE_DEFAULT_MAX_BACKGROUND 12

struct fuse_conn;
struct fuse_chan;
struct fuse_dev;
struct fuse_args;
struct fuse_copy_state;
struct file;
enum fuse_notify_code;

struct fuse_chan *fuse_chan_new(void);
void fuse_chan_free(struct fuse_chan *fch);
unsigned int fuse_chan_max_background(struct fuse_chan *fch);
void fuse_chan_max_background_set(struct fuse_chan *fch, unsigned int val);
unsigned int fuse_chan_num_waiting(struct fuse_chan *fch);
void fuse_chan_set_fc(struct fuse_chan *fch, struct fuse_conn *fc);
ssize_t fuse_chan_send(struct fuse_chan *fch, struct fuse_args *args);
int fuse_chan_send_bg(struct fuse_chan *fch, struct fuse_args *args, gfp_t gfp_flags);

DEFINE_FREE(fuse_chan_free, struct fuse_chan *, if (_T) fuse_chan_free(_T))

/**
 * Initialize the client device
 */
int fuse_dev_init(void);

/**
 * Cleanup the client device
 */
void fuse_dev_cleanup(void);

void fuse_dev_install(struct fuse_dev *fud, struct fuse_chan *fch);
void fuse_dev_put(struct fuse_dev *fud);
bool fuse_dev_is_installed(struct fuse_dev *fud);
bool fuse_dev_is_sync_init(struct fuse_dev *fud);
struct fuse_dev *fuse_dev_grab(struct file *file);

/* Abort all requests */
void fuse_chan_abort(struct fuse_chan *fch);
void fuse_chan_wait_aborted(struct fuse_chan *fch);

/**
 * Acquire reference to fuse_conn
 */
struct fuse_conn *fuse_conn_get(struct fuse_conn *fc);

/**
 * Release reference to fuse_conn
 */
void fuse_conn_put(struct fuse_conn *fc);

dev_t fuse_conn_get_id(struct fuse_conn *fc);

int fuse_notify(struct fuse_conn *fc, enum fuse_notify_code code,
		unsigned int size, struct fuse_copy_state *cs);

int fuse_copy_one(struct fuse_copy_state *cs, void *val, unsigned size);
void fuse_copy_finish(struct fuse_copy_state *cs);

void fuse_uring_destruct(struct fuse_chan *fch);
int fuse_uring_ring_only_init(struct fuse_chan *fch);
size_t fuse_uring_max_payload(struct fuse_chan *fch);
size_t fuse_uring_max_io(struct fuse_chan *fch);

#endif /* _FS_FUSE_DEV_H */
