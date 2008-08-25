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
#include "dri_bufmgr.h"
#include "string.h"

#include "radeon_reg.h"
#include "radeon_probe.h"
#include "radeon.h"
#include "radeon_bufmgr.h"

typedef struct _dri_bo_gem {
	dri_bo bo;
	int refcount;
	int reloc_count;
	int map_count;
	/* reloc list - add to list for relocs */
	uint32_t gem_handle;
	const char *name;
	struct _dri_bo_gem *next;
} dri_bo_gem;

typedef struct _dri_bufmgr_gem {
	dri_bufmgr bufmgr;
	struct radeon_bufmgr radeon_bufmgr;
	int fd;
	struct _dri_bo_gem *reloc_head;
} dri_bufmgr_gem;

static dri_bo *
dri_gem_bo_alloc(dri_bufmgr *bufmgr, const char *name,
		 unsigned long size, unsigned int alignment)

{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bufmgr;
	struct drm_radeon_gem_create args;
	int ret;
	dri_bo_gem *gem_bo;

	args.size = size;
	args.alignment = alignment;
	args.initial_domain = RADEON_GEM_DOMAIN_CPU;
	args.no_backing_store = 0;

	gem_bo = malloc(sizeof(*gem_bo));
	if (!gem_bo)
		return NULL;

	ret = drmCommandWriteRead(bufmgr_gem->fd, DRM_RADEON_GEM_CREATE, &args, sizeof(args));
	gem_bo->gem_handle = args.handle;
	if (ret != 0) {
		free(gem_bo);
		return NULL;
	}
	gem_bo->refcount = 1;
	gem_bo->bo.size = size;
	gem_bo->bo.bufmgr = bufmgr;
	gem_bo->next = NULL;
	gem_bo->reloc_count = 0;
	gem_bo->map_count = 0;

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
	dri_bo_gem *gem_bo = (dri_bo_gem *)bo;
	struct drm_gem_close args;

	if (gem_bo->map_count)
		munmap(gem_bo->bo.virtual, gem_bo->bo.size);

	/* close object */
	args.handle = gem_bo->gem_handle;
	ioctl(bufmgr_gem->fd, DRM_IOCTL_GEM_CLOSE, &args);
	free(gem_bo);
}

static void
dri_gem_bo_unreference(dri_bo *bo)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bo->bufmgr;
	dri_bo_gem *gem_bo = (dri_bo_gem *)bo;

	if (!bo)
		return;

	if (--gem_bo->refcount == 0)
		dri_gem_bo_free(bo);

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
	free(bufmgr);
}

void radeon_bufmgr_gem_wait_rendering(dri_bo *buf)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)buf->bufmgr;
	struct drm_radeon_gem_set_domain dom_args;
	dri_bo_gem *gem_bo = (dri_bo_gem *)buf;
	int ret;

	dom_args.handle = gem_bo->gem_handle;
	dom_args.read_domains = RADEON_GEM_DOMAIN_CPU;
	dom_args.write_domain = 0;
	ret = drmCommandWriteRead(bufmgr_gem->fd, DRM_RADEON_GEM_SET_DOMAIN,
				  &dom_args, sizeof(dom_args));

	return;
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
    dri_bo_gem *bo_gem;
    int ret;
    struct drm_gem_open open_arg;

    bo_gem = calloc(1, sizeof(*bo_gem));
    if (!bo_gem)
	return NULL;

    memset(&open_arg, 0, sizeof(open_arg));
    open_arg.name = handle;
    ret = ioctl(bufmgr_gem->fd, DRM_IOCTL_GEM_OPEN, &open_arg);
    if (ret != 0) {
	fprintf(stderr, "Couldn't reference %s handle 0x%08x: %s\n",
	       name, handle, strerror(-ret));
	free(bo_gem);
	return NULL;
    }
    bo_gem->bo.size = open_arg.size;
    bo_gem->bo.offset = 0;
    bo_gem->bo.virtual = NULL;
    bo_gem->bo.bufmgr = bufmgr;
    bo_gem->name = name;
    bo_gem->refcount = 1;
    bo_gem->gem_handle = open_arg.handle;

    return &bo_gem->bo;
}

#define BUF_OUT_RING(x)	 do {			\
		__head[__count++] = (x);				\
	} while (0)

void radeon_bufmgr_gem_emit_reloc(dri_bo *buf, uint32_t *head, uint32_t *count_p, uint32_t read_domains, uint32_t write_domain)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)buf->bufmgr;
	dri_bo_gem *gem_bo = (dri_bo_gem *)buf;
	uint32_t *__head = head;
	uint32_t __count = *count_p;
	dri_bo_gem *trav;
	
	if (gem_bo->reloc_count == 0) {
		dri_bo_reference(buf);

		if (bufmgr_gem->reloc_head == NULL)
			bufmgr_gem->reloc_head = gem_bo;
		else {
			trav = bufmgr_gem->reloc_head;
			while (trav->next != NULL)
				trav = trav->next;
			trav->next = gem_bo;
		}
	}
	gem_bo->reloc_count++;
	BUF_OUT_RING(CP_PACKET3(RADEON_CP_PACKET3_NOP, 2));
	BUF_OUT_RING(gem_bo->gem_handle);
	BUF_OUT_RING(read_domains);
	BUF_OUT_RING(write_domain);
	*count_p = __count;
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

	bufmgr_gem = calloc(1, sizeof(*bufmgr_gem));
	bufmgr_gem->fd = fd;

	bufmgr_gem->bufmgr.bo_alloc = dri_gem_bo_alloc;
	bufmgr_gem->bufmgr.bo_reference = dri_gem_bo_reference;
	bufmgr_gem->bufmgr.bo_unreference = dri_gem_bo_unreference;
	bufmgr_gem->bufmgr.bo_map = dri_gem_bo_map;
	bufmgr_gem->bufmgr.bo_unmap = dri_gem_bo_unmap;
	bufmgr_gem->bufmgr.destroy = dri_bufmgr_gem_destroy;
	bufmgr_gem->bufmgr.bo_wait_rendering = radeon_bufmgr_gem_wait_rendering;
	bufmgr_gem->radeon_bufmgr.emit_reloc = radeon_bufmgr_gem_emit_reloc;
	return &bufmgr_gem->bufmgr;
}


void radeon_gem_bufmgr_post_submit(dri_bufmgr *bufmgr)
{
	dri_bufmgr_gem *bufmgr_gem = (dri_bufmgr_gem *)bufmgr;
	struct _dri_bo_gem *trav, *prev;

	if (!bufmgr_gem->reloc_head)
		return;

	trav = bufmgr_gem->reloc_head;
	while (trav) {
		prev = trav;
		trav = trav->next;
		
		prev->reloc_count = 0;
		prev->next = NULL;
		dri_bo_unreference(&prev->bo);
	}
	bufmgr_gem->reloc_head = NULL;

}

void radeon_gem_bufmgr_pin(dri_bo *buf)
{
}

void radeon_gem_bufmgr_unpin(dri_bo *buf)
{
}

uint32_t radeon_gem_bufmgr_get_handle(dri_bo *buf)
{
	dri_bo_gem *gem_bo = (dri_bo_gem *)buf;
	
	return gem_bo->gem_handle;
}

void radeon_bufmgr_emit_reloc(dri_bo *buf, uint32_t *head, uint32_t *count_p, uint32_t read_domains, uint32_t write_domain)
{
	struct radeon_bufmgr *radeon_bufmgr;

	radeon_bufmgr = (struct radeon_bufmgr *)(buf->bufmgr + 1);
	radeon_bufmgr->emit_reloc(buf, head, count_p, read_domains, write_domain);
}
