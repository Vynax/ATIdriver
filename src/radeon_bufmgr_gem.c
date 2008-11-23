/**************************************************************************
 *
 * Copyright © 2007-2008 Red Hat Inc.
 * Copyright © 2007 Intel Corporation
 * Copyright 2006 Tungsten Graphics, Inc., Bismarck, ND., USA
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 *
 **************************************************************************/
/*
 * Authors: Thomas Hellström <thomas-at-tungstengraphics-dot-com>
 *          Keith Whitwell <keithw-at-tungstengraphics-dot-com>
 *	    Eric Anholt <eric@anholt.net>
 *	    Dave Airlie <airlied@linux.ie>
 *	    Kristian Høgsberg <krh@redhat.com>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <xf86drm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "xf86.h"
#include "errno.h"
#include "string.h"

#include "radeon_reg.h"
#include "radeon_probe.h"
#include "radeon.h"
#include "radeon_bufmgr.h"
#include "radeon_drm.h"

#define DBG(...) do {					\
   if (bufmgr_gem->bufmgr.debug)			\
      fprintf(stderr, __VA_ARGS__);			\
} while (0)

typedef struct _dri_bo_gem {
	dri_bo bo;
	int refcount;
	int reloc_count;
	int map_count;
	/* reloc list - add to list for relocs */
	uint32_t gem_handle;
	const char *name;
	struct _dri_bo_gem *next;
	int in_vram; /* have we migrated this bo to VRAM ever */
	int force_gtt;
	int pinned;
	int touched;
	uint32_t space_accounted;
} dri_bo_gem;

typedef struct _dri_bufmgr_gem {
	dri_bufmgr bufmgr;
	struct radeon_bufmgr radeon_bufmgr;
	int fd;
	uint32_t vram_limit, gart_limit;
	uint32_t vram_write_used, gart_write_used;
	uint32_t read_used;

	struct _dri_bo_gem *bo_list;
} dri_bufmgr_gem;

static dri_bo *
dri_gem_bo_alloc(dri_bufmgr *bufmgr, const char *name,
		 unsigned long size, unsigned int alignment, uint64_t location_mask)

{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bufmgr;
	struct drm_radeon_gem_create args;
	int ret;
	unsigned int page_size = getpagesize();
	dri_bo_gem *gem_bo;

	gem_bo = calloc(1, sizeof(*gem_bo));
	if (!gem_bo)
		return NULL;

	gem_bo->bo.size = size;
	args.size = size;
	args.alignment = alignment;
	args.initial_domain = RADEON_GEM_DOMAIN_CPU;
	args.no_backing_store = 0;

	ret = drmCommandWriteRead(bufmgr_gem->fd, DRM_RADEON_GEM_CREATE, &args, sizeof(args));
	gem_bo->gem_handle = args.handle;
	if (ret != 0) {
		free(gem_bo);
		return NULL;
	}
	gem_bo->bo.bufmgr = bufmgr;

	gem_bo->refcount = 1;
	gem_bo->reloc_count = 0;
	gem_bo->map_count = 0;
	gem_bo->in_vram = 0;
	gem_bo->name = strdup(name);
	gem_bo->touched = 0;

	gem_bo->next = bufmgr_gem->bo_list;
	bufmgr_gem->bo_list = gem_bo;

	DBG("bo_create: buf %d (%s) %ldb\n",
	    gem_bo->gem_handle, gem_bo->name, size);

	return &gem_bo->bo;
}

static void
dri_gem_bo_reference(dri_bo *bo)
{
	dri_bo_gem *gem_bo = (dri_bo_gem *)bo;
	gem_bo->refcount++;
}

static void dri_gem_bo_free(dri_bo *bo)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bo->bufmgr;
	dri_bo_gem *gem_bo = (dri_bo_gem *)bo, *trav, *prev;
	struct drm_gem_close args;

	if (gem_bo->map_count)
		munmap(gem_bo->bo.virtual, gem_bo->bo.size);

	/* close object */
	args.handle = gem_bo->gem_handle;
	ioctl(bufmgr_gem->fd, DRM_IOCTL_GEM_CLOSE, &args);

	if (gem_bo == bufmgr_gem->bo_list)
		bufmgr_gem->bo_list = gem_bo->next;
	else {
		prev = trav = bufmgr_gem->bo_list;
		while (trav) {
			if (trav == gem_bo) {
				if (prev)
					prev->next = trav->next;
				break;
			}
			prev = trav;
			trav = trav->next;
		}
	}
	free(gem_bo->name);
	free(gem_bo);
}

static void
dri_gem_bo_unreference(dri_bo *bo)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bo->bufmgr;
	dri_bo_gem *gem_bo = (dri_bo_gem *)bo;

	if (!bo)
		return;
	
	if (--gem_bo->refcount == 0) {
		DBG("bo_unreference final: %d (%s) 0 - free %d\n",
		    gem_bo->gem_handle, gem_bo->name, gem_bo->in_vram);
		dri_gem_bo_free(bo);
		return;
	}
}

static int
dri_gem_bo_map(dri_bo *bo, int write_enable)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bo->bufmgr;
	dri_bo_gem *gem_bo = (dri_bo_gem *)bo;
	struct drm_radeon_gem_mmap args;
	int ret;

	if (gem_bo->map_count++ != 0)
		return 0;

	args.handle = gem_bo->gem_handle;
	args.offset = 0;
	args.size = gem_bo->bo.size;

	ret = drmCommandWriteRead(bufmgr_gem->fd, DRM_RADEON_GEM_MMAP, &args, sizeof(args));
	if (!ret)
		gem_bo->bo.virtual = (void *)(unsigned long)args.addr_ptr;

	return ret;
}

static int
dri_gem_bo_unmap(dri_bo *buf)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)buf->bufmgr;
	dri_bo_gem *gem_bo = (dri_bo_gem *)buf;

	if (--gem_bo->map_count > 0)
		return 0;

        munmap(gem_bo->bo.virtual, gem_bo->bo.size);
	gem_bo->bo.virtual = 0;
	return 0;
}

static void
dri_bufmgr_gem_destroy(dri_bufmgr *bufmgr)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bufmgr;
	int i;

	free(bufmgr);
}

void radeon_bufmgr_gem_wait_rendering(dri_bo *buf)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)buf->bufmgr;
	struct drm_radeon_gem_wait_rendering args;
	struct drm_radeon_gem_set_domain sd_args;
	dri_bo_gem *gem_bo = (dri_bo_gem *)buf;
	int ret;

	/* do a set domain */
	if (gem_bo->force_gtt) {
		sd_args.handle = gem_bo->gem_handle;
		sd_args.read_domains = RADEON_GEM_DOMAIN_GTT;
		sd_args.write_domain = 0;

		ret = drmCommandWriteRead(bufmgr_gem->fd, DRM_RADEON_GEM_SET_DOMAIN,
					  &sd_args, sizeof(sd_args));

	} else {
		args.handle = gem_bo->gem_handle;

		do {
		ret = drmCommandWriteRead(bufmgr_gem->fd, DRM_RADEON_GEM_WAIT_RENDERING,
					  &args, sizeof(args));
		} while (ret == -EAGAIN);
	}
	return;
}

dri_bo *
radeon_bo_gem_create_from_handle(dri_bufmgr *bufmgr,
				 uint32_t handle, unsigned long size)
{
    dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bufmgr;
    dri_bo_gem *bo_gem;
    char name[32];

    sprintf(name, "handle:%8x", handle);
    bo_gem = calloc(1, sizeof(*bo_gem));
    if (!bo_gem)
	return NULL;

    bo_gem->bo.size = size;
    bo_gem->bo.offset = 0;
    bo_gem->bo.virtual = NULL;
    bo_gem->bo.bufmgr = bufmgr;
    bo_gem->name = strdup(name);
    bo_gem->refcount = 1;
    bo_gem->pinned = 1;
    bo_gem->gem_handle = handle;
    bo_gem->in_vram = 1;

    bo_gem->next = bufmgr_gem->bo_list;
    bufmgr_gem->bo_list = bo_gem;
    return &bo_gem->bo;
}

/**
 * Returns a dri_bo wrapping the given buffer object handle.
 *
 * This can be used when one application needs to pass a buffer object
 * to another.
 */
dri_bo *
radeon_bo_gem_create_from_name(dri_bufmgr *bufmgr, const char *name,
			       unsigned int handle)
{
    dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bufmgr;
    int ret;
    struct drm_gem_open open_arg;

    memset(&open_arg, 0, sizeof(open_arg));
    open_arg.name = handle;
    ret = ioctl(bufmgr_gem->fd, DRM_IOCTL_GEM_OPEN, &open_arg);
    if (ret != 0) {
	fprintf(stderr, "Couldn't reference %s handle 0x%08x: %s\n",
	       name, handle, strerror(-ret));
	return NULL;
    }

    return radeon_bo_gem_create_from_handle(bufmgr,
					    open_arg.handle, open_arg.size);
}

#define BUF_OUT_RING(x)	 do {			\
		__head[__count++] = (x);				\
	} while (0)

void radeon_bufmgr_gem_emit_reloc(dri_bo *buf, struct radeon_relocs_info *reloc_info, uint32_t *head, uint32_t *count_p, uint32_t read_domains, uint32_t write_domain)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)buf->bufmgr;
	dri_bo_gem *gem_bo = (dri_bo_gem *)buf;
	uint32_t *__head = head;
	uint32_t __count = *count_p;
	dri_bo_gem *trav;
	int i;
	int index;
	int have_reloc = -1;

	for (i = 0; i < reloc_info->num_reloc; i++) {
		if (reloc_info->buf[i * 4] == gem_bo->gem_handle) {
			have_reloc = i;
			break;
		}
	}

	if (gem_bo->force_gtt && (read_domains & RADEON_GEM_DOMAIN_VRAM))
		read_domains = RADEON_GEM_DOMAIN_GTT;

	if (have_reloc != -1) {
		uint32_t old_write, old_read;

		index = have_reloc * 4;
		old_read = reloc_info->buf[index + 1];
		old_write = reloc_info->buf[index + 2];

		/* error up for now - work out new domains - if we have a write */
		if (write_domain && (old_read & write_domain)) {
			reloc_info->buf[index + 1] = 0;
			reloc_info->buf[index + 2] = write_domain;
		} else if (read_domains & old_write) {
			reloc_info->buf[index + 1] = 0;
		} else {
			/* rewrite the domains */
			if (write_domain != old_write)
				ErrorF("WRITE DOMAIN RELOC FAILURE 0x%x %d %d\n", gem_bo->gem_handle, write_domain, old_write);
			if (read_domains != old_read)
				ErrorF("READ DOMAIN RELOC FAILURE 0x%x %d %d\n", gem_bo->gem_handle, read_domains, old_read);
		}
		reloc_info->buf[index + 3]++;

	} else {

		if ((reloc_info->num_reloc + 1) * RADEON_RELOC_SIZE > reloc_info->size) {
			/* resize the buffer */
			reloc_info->size += getpagesize();
			reloc_info->buf = xrealloc(reloc_info->buf, reloc_info->size);
			if (!reloc_info->buf)
				FatalError("failed to increase reloc buffer size\n");
			reloc_info->max_bo = reloc_info->size / RADEON_RELOC_SIZE;
			reloc_info->bo_list = xrealloc(reloc_info->bo_list, reloc_info->max_bo * (sizeof(dri_bo *)));
		}

		dri_bo_reference(buf);
		gem_bo->touched = 1;

		index = reloc_info->num_reloc * 4;
		reloc_info->bo_list[index/4] = buf;
		reloc_info->buf[index] = gem_bo->gem_handle;
		reloc_info->buf[index + 1] = read_domains;
		reloc_info->buf[index + 2] = write_domain;
		reloc_info->buf[index + 3] = 1;
		reloc_info->num_reloc++;
	}

	if (write_domain == RADEON_GEM_DOMAIN_VRAM) {
		if (gem_bo->in_vram == 0)
			DBG("bo_into vram: buf %d (%s) %d %d\n",
			    gem_bo->gem_handle, gem_bo->name, read_domains, write_domain);
		
		gem_bo->in_vram = 1;
	}

	BUF_OUT_RING(CP_PACKET3(RADEON_CP_PACKET3_NOP, 0));
	BUF_OUT_RING(index);
	*count_p = __count;
}

static int radeon_gem_bufmgr_pin(dri_bo *bo, int domain)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bo->bufmgr;
	dri_bo_gem *gem_bo = (dri_bo_gem *)bo;
	struct drm_radeon_gem_pin pin;
	int ret;

	if (domain == RADEON_GEM_DOMAIN_VRAM)
	  gem_bo->in_vram = 1;

	pin.pin_domain = domain;
	pin.handle = gem_bo->gem_handle;
	pin.alignment = 0;

	ret = ioctl(bufmgr_gem->fd, DRM_IOCTL_RADEON_GEM_PIN, &pin);
	if (ret != 0)
		return -1;

	gem_bo->pinned = 1;
	return 0;
}

static void radeon_gem_bufmgr_unpin(dri_bo *bo)
{

	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bo->bufmgr;
	dri_bo_gem *gem_bo = (dri_bo_gem *)bo;
	struct drm_radeon_gem_unpin unpin;

	unpin.handle = gem_bo->gem_handle;
	ioctl(bufmgr_gem->fd, DRM_IOCTL_RADEON_GEM_UNPIN, &unpin);
	gem_bo->pinned = 0;
}


static uint32_t radeon_gem_bufmgr_get_handle(dri_bo *buf)
{
	dri_bo_gem *gem_bo = (dri_bo_gem *)buf;
	
	return gem_bo->gem_handle;
}

static int radeon_gem_bufmgr_check_aperture_space(struct radeon_space_check *bos, int num_bo)
{
	dri_bufmgr_gem *bufmgr_gem;
 	dri_bo_gem *gem_bo;
	dri_bo *buf;
	int this_op_read = 0, this_op_gart_write = 0, this_op_vram_write = 0;
	uint32_t read_domains, write_domain;
	int i;
	/* check the totals for this operation */

	if (num_bo == 0)
		return 0;

	bufmgr_gem = (dri_bufmgr_gem *)bos[0].buf->bufmgr;

	/* prepare */
	for (i = 0; i < num_bo; i++) {
		buf = bos[i].buf;
		gem_bo = (dri_bo_gem *)buf;

		bos[i].new_accounted = 0;
		read_domains = bos[i].read_domains;
		write_domain = bos[i].write_domain;
		
		/* pinned bos don't count */
		if (gem_bo->pinned)
			continue;
 
		/* already accounted this bo */
		if (write_domain && (write_domain == gem_bo->space_accounted))
			continue;

		if (read_domains && ((read_domains << 16) == gem_bo->space_accounted))
			continue;

		if (gem_bo->space_accounted == 0) {
			if (write_domain == RADEON_GEM_DOMAIN_VRAM)
				this_op_vram_write += buf->size;
			else if (write_domain == RADEON_GEM_DOMAIN_GTT)
				this_op_gart_write += buf->size;
			else
				this_op_read += buf->size;
			bos[i].new_accounted = (read_domains << 16) | write_domain;
		} else {
			uint16_t old_read, old_write;

			old_read = gem_bo->space_accounted >> 16;
			old_write = gem_bo->space_accounted & 0xffff;

			if (write_domain && (old_read & write_domain)) {
				bos[i].new_accounted = write_domain;
				/* moving from read to a write domain */
				if (write_domain == RADEON_GEM_DOMAIN_VRAM) {
					this_op_read -= buf->size;
					this_op_vram_write += buf->size;
				} else if (write_domain == RADEON_GEM_DOMAIN_VRAM) {
					this_op_read -= buf->size;
					this_op_gart_write += buf->size;
				}
			} else if (read_domains & old_write) {
				bos[i].new_accounted = gem_bo->space_accounted & 0xffff;
			} else {
				/* rewrite the domains */
				if (write_domain != old_write)
					ErrorF("WRITE DOMAIN RELOC FAILURE 0x%x %d %d\n", gem_bo->gem_handle, write_domain, old_write);
				if (read_domains != old_read)
					ErrorF("READ DOMAIN RELOC FAILURE 0x%x %d %d\n", gem_bo->gem_handle, read_domains, old_read);
				return BUFMGR_SPACE_FLUSH;
			}
		}
	}
	
	/* check sizes - operation first */
	if ((this_op_read + this_op_gart_write > bufmgr_gem->gart_limit) ||
	    (this_op_vram_write > bufmgr_gem->vram_limit)) {
		return BUFMGR_SPACE_OP_TO_BIG;
	}

	if (((bufmgr_gem->vram_write_used + this_op_vram_write) > bufmgr_gem->vram_limit) ||
	    ((bufmgr_gem->read_used + bufmgr_gem->gart_write_used + this_op_gart_write + this_op_read) > bufmgr_gem->gart_limit)) {
		return BUFMGR_SPACE_FLUSH;
	}

	bufmgr_gem->gart_write_used += this_op_gart_write;
	bufmgr_gem->vram_write_used += this_op_vram_write;
	bufmgr_gem->read_used += this_op_read;
	/* commit */
	for (i = 0; i < num_bo; i++) {
		buf = bos[i].buf;
		gem_bo = (dri_bo_gem *)buf;
		gem_bo->space_accounted = bos[i].new_accounted;
	}

	return BUFMGR_SPACE_OK;
}

/**
 * Initializes the GEM buffer manager, which is just a thin wrapper
 * around the GEM allocator.
 *
 * \param fd File descriptor of the opened DRM device.
 * \param fence_type Driver-specific fence type used for fences with no flush.
 * \param fence_type_flush Driver-specific fence type used for fences with a
 *	  flush.
 */
dri_bufmgr *
radeon_bufmgr_gem_init(int fd)
{
	dri_bufmgr_gem *bufmgr_gem;
	int i;

	bufmgr_gem = calloc(1, sizeof(*bufmgr_gem));
	bufmgr_gem->fd = fd;

	bufmgr_gem->bufmgr.bo_alloc = dri_gem_bo_alloc;
	bufmgr_gem->bufmgr.bo_reference = dri_gem_bo_reference;
	bufmgr_gem->bufmgr.bo_unreference = dri_gem_bo_unreference;
	bufmgr_gem->bufmgr.bo_map = dri_gem_bo_map;
	bufmgr_gem->bufmgr.bo_unmap = dri_gem_bo_unmap;
	bufmgr_gem->bufmgr.destroy = dri_bufmgr_gem_destroy;
	bufmgr_gem->bufmgr.pin = radeon_gem_bufmgr_pin;
	bufmgr_gem->bufmgr.unpin = radeon_gem_bufmgr_unpin;
	//bufmgr_gem->bufmgr.bo_wait_rendering = radeon_bufmgr_gem_wait_rendering;
	bufmgr_gem->radeon_bufmgr.emit_reloc = radeon_bufmgr_gem_emit_reloc;
	bufmgr_gem->bufmgr.get_handle = radeon_gem_bufmgr_get_handle;
	bufmgr_gem->bufmgr.check_aperture_space = radeon_gem_bufmgr_check_aperture_space;
	bufmgr_gem->bufmgr.debug = 0;
	return &bufmgr_gem->bufmgr;
}


void radeon_gem_bufmgr_post_submit(dri_bufmgr *bufmgr, struct radeon_relocs_info *reloc_info, int error)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bufmgr;
	struct _dri_bo_gem *trav, *prev;
	int i;
	
	if (error) {
		ErrorF("bufmgr: last submission : r:%d vs g:%d w:%d vs v:%d\n",
		       bufmgr_gem->read_used, bufmgr_gem->gart_limit, 
		       bufmgr_gem->vram_write_used, bufmgr_gem->vram_limit);
	}

	if (!bufmgr_gem->bo_list)
		return;

	for (i = 0; i < reloc_info->num_reloc; i++) {
		trav = (dri_bo_gem *)reloc_info->bo_list[i];

		trav->space_accounted = 0;
		dri_bo_unreference(&trav->bo);
	}

	bufmgr_gem->read_used = 0;
	bufmgr_gem->vram_write_used = 0;
	bufmgr_gem->gart_write_used = 0;
	
}



void radeon_bufmgr_emit_reloc(dri_bo *buf, struct radeon_relocs_info *relocs, uint32_t *head, uint32_t *count_p, uint32_t read_domains, uint32_t write_domain)
{
	struct radeon_bufmgr *radeon_bufmgr;

	radeon_bufmgr = (struct radeon_bufmgr *)(buf->bufmgr + 1);
	radeon_bufmgr->emit_reloc(buf, relocs, head, count_p, read_domains, write_domain);
}

/* if the buffer is references by the current IB we need to flush the IB */
int radeon_bufmgr_gem_has_references(dri_bo *buf)
{
	dri_bo_gem *gem_bo = (dri_bo_gem *)buf;

	return gem_bo->touched;
}

void radeon_bufmgr_gem_set_limit(dri_bufmgr *bufmgr, uint32_t domain, uint32_t limit)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bufmgr;

	if (domain == RADEON_GEM_DOMAIN_VRAM)
	    bufmgr_gem->vram_limit = limit;
	else
	    bufmgr_gem->gart_limit = limit;

}

void radeon_bufmgr_gem_force_gtt(dri_bo *buf)
{
	dri_bo_gem *gem_bo = (dri_bo_gem *)buf;

	if (!gem_bo->pinned)
	    gem_bo->force_gtt = 1;
}

int radeon_bufmgr_gem_in_vram(dri_bo *buf)
{
	dri_bo_gem *gem_bo = (dri_bo_gem *)buf;
	return gem_bo->in_vram;
}
