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

#include "xf86.h"
#include "errno.h"
#include "string.h"

#include "radeon_reg.h"
#include "radeon_probe.h"
#include "radeon.h"
#include "radeon_bufmgr.h"


typedef struct _dri_bo_exa {
	dri_bo bo;
	struct radeon_memory *mem;
	int refcount;
	int reloc_count;
	int map_count;
	/* reloc list - add to list for relocs */
	struct _dri_bo_exa *next;
} dri_bo_exa;

typedef struct _dri_bufmgr_exa {
	dri_bufmgr bufmgr;
	struct radeon_bufmgr radeon_bufmgr;
	ScrnInfoPtr pScrn;
	struct _dri_bo_exa *reloc_head;
} dri_bufmgr_exa;

static dri_bo *
dri_exa_alloc(dri_bufmgr *bufmgr, const char *name,
	      unsigned long size, unsigned int alignment)

{
	dri_bufmgr_exa *bufmgr_exa = (dri_bufmgr_exa *)bufmgr;
	RADEONInfoPtr info = RADEONPTR(bufmgr_exa->pScrn);
	dri_bo_exa *exa_buf;

	exa_buf = malloc(sizeof(*exa_buf));
	if (!exa_buf)
		return NULL;

	exa_buf->refcount = 1;
	exa_buf->mem = radeon_allocate_memory(bufmgr_exa->pScrn, RADEON_POOL_GART,
					      size, alignment, 0, name, 0);

	exa_buf->bo.size = exa_buf->mem->size;
	exa_buf->bo.offset = exa_buf->mem->offset;
	exa_buf->bo.bufmgr = bufmgr;
	exa_buf->next = NULL;
	exa_buf->reloc_count = 0;
	exa_buf->map_count = 0;

	return &exa_buf->bo;
}

static void
dri_exa_bo_reference(dri_bo *buf)
{
	dri_bo_exa *exa_buf = (dri_bo_exa *)buf;
	exa_buf->refcount++;
}

static void
dri_exa_bo_unreference(dri_bo *buf)
{
	dri_bufmgr_exa *bufmgr_exa = (dri_bufmgr_exa *)buf->bufmgr;
	dri_bo_exa *exa_buf = (dri_bo_exa *)buf;

	if (!buf)
		return;

	if (--exa_buf->refcount == 0)
		radeon_free_memory(bufmgr_exa->pScrn, exa_buf->mem);
}

static int
dri_exa_bo_map(dri_bo *buf, int write_enable)
{
	dri_bufmgr_exa *bufmgr_exa = (dri_bufmgr_exa *)buf->bufmgr;
	dri_bo_exa *exa_buf = (dri_bo_exa *)buf;

	if (exa_buf->map_count++ != 0)
		return 0;
	
	radeon_map_memory(bufmgr_exa->pScrn, exa_buf->mem);
	exa_buf->bo.virtual = exa_buf->mem->map;
	return 0;
}

static int
dri_exa_bo_unmap(dri_bo *buf)
{
	dri_bufmgr_exa *bufmgr_exa = (dri_bufmgr_exa *)buf->bufmgr;
	dri_bo_exa *exa_buf = (dri_bo_exa *)buf;

	if (--exa_buf->map_count > 0)
		return 0;

	radeon_unmap_memory(bufmgr_exa->pScrn, exa_buf->mem);
	exa_buf->bo.virtual = 0;
	return 0;
}

static void
dri_bufmgr_exa_destroy(dri_bufmgr *bufmgr)
{
	free(bufmgr);
}

void radeon_bufmgr_exa_wait_rendering(dri_bo *buf)
{
	dri_bufmgr_exa *bufmgr_exa = (dri_bufmgr_exa *)buf->bufmgr;
	RADEONInfoPtr info = RADEONPTR(bufmgr_exa->pScrn);
	struct drm_radeon_gem_set_domain dom_args;
	dri_bo_exa *exa_buf = (dri_bo_exa *)buf;
	int ret;

	dom_args.handle = exa_buf->mem->kernel_bo_handle;
	dom_args.read_domains = RADEON_GEM_DOMAIN_GTT;
	dom_args.write_domain = 0;
	ret = drmCommandWriteRead(info->drmFD, DRM_RADEON_GEM_SET_DOMAIN,
				  &dom_args, sizeof(dom_args));

	return;
}

int radeon_bufmgr_subdata(dri_bo *buf, unsigned long offset,
			  unsigned long size, const void *data)
{
	dri_bo_exa *exa_buf = (dri_bo_exa *)buf;
	dri_bufmgr_exa *bufmgr_exa = (dri_bufmgr_exa *)buf->bufmgr;
	RADEONInfoPtr info = RADEONPTR(bufmgr_exa->pScrn);
	int ret;
	/* go to pwrite */
	struct drm_radeon_gem_pwrite pwrite;

	pwrite.handle = exa_buf->mem->kernel_bo_handle;
	pwrite.offset = offset;
	pwrite.size = size;
	pwrite.data_ptr = (uint64_t)(uintptr_t)data;

	do {
		ret = drmCommandWriteRead(info->drmFD, DRM_IOCTL_RADEON_GEM_PWRITE,
					  &pwrite, sizeof(pwrite));
	} while (ret == -1 && errno == EINTR);

	if (ret != 0) {
		fprintf(stderr,"Pwrite %lx at %lx failed\n", size, offset);
		return -1;
	}
	return 0;
}


dri_bo *
radeon_bufmgr_exa_create_bo(dri_bufmgr *bufmgr, struct radeon_memory *mem)
{
	dri_bufmgr_exa *bufmgr_exa = (dri_bufmgr_exa *)bufmgr;
	dri_bo_exa *exa_buf;

	exa_buf = malloc(sizeof(*exa_buf));
	if (!exa_buf)
		return NULL;
	exa_buf->refcount = 1;
	exa_buf->mem =  mem;
	exa_buf->bo.size = exa_buf->mem->size;
	exa_buf->bo.offset = exa_buf->mem->offset;
	exa_buf->bo.bufmgr = bufmgr;
	exa_buf->bo.virtual = exa_buf->mem->map;
	exa_buf->next = NULL;
	exa_buf->reloc_count = 0;
	/* get map count right */
	exa_buf->map_count = 1;

	return &exa_buf->bo;
}

static void radeon_bufmgr_exa_emit_reloc(dri_bo *buf, uint32_t *head, uint32_t *count_p, uint32_t read_domains, uint32_t write_domain)
{
	dri_bufmgr_exa *bufmgr_exa = (dri_bufmgr_exa *)buf->bufmgr;
	ScrnInfoPtr pScrn = bufmgr_exa->pScrn;
	dri_bo_exa *exa_buf = (dri_bo_exa *)buf;
	uint32_t *__head = head;
	uint32_t __count = *count_p;
	dri_bo_exa *trav;

	if (exa_buf->reloc_count == 0) {
		dri_bo_reference(buf);

		if (bufmgr_exa->reloc_head == NULL)
			bufmgr_exa->reloc_head = exa_buf;
		else {
			trav = bufmgr_exa->reloc_head;
			while (trav->next != NULL)
				trav = trav->next;
			trav->next = exa_buf;
		}
	}
	exa_buf->reloc_count++;
	OUT_RING(CP_PACKET3(RADEON_CP_PACKET3_NOP, 2));
	OUT_RING(exa_buf->mem->kernel_bo_handle);
	OUT_RING(read_domains);
	OUT_RING(write_domain);
	*count_p = __count;
}

/**
 * Initializes the EXA buffer manager, which is just a thin wrapper
 * around the EXA allocator.
 *
 * \param fd File descriptor of the opened DRM device.
 * \param fence_type Driver-specific fence type used for fences with no flush.
 * \param fence_type_flush Driver-specific fence type used for fences with a
 *	  flush.
 */
dri_bufmgr *
radeon_bufmgr_exa_init(ScrnInfoPtr pScrn)
{
	dri_bufmgr_exa *bufmgr_exa;

	bufmgr_exa = calloc(1, sizeof(*bufmgr_exa));
	bufmgr_exa->pScrn = pScrn;

	bufmgr_exa->bufmgr.bo_alloc = dri_exa_alloc;
	bufmgr_exa->bufmgr.bo_reference = dri_exa_bo_reference;
	bufmgr_exa->bufmgr.bo_unreference = dri_exa_bo_unreference;
	bufmgr_exa->bufmgr.bo_map = dri_exa_bo_map;
	bufmgr_exa->bufmgr.bo_unmap = dri_exa_bo_unmap;
	bufmgr_exa->bufmgr.destroy = dri_bufmgr_exa_destroy;
	//bufmgr_exa->bufmgr.bo_wait_rendering = radeon_bufmgr_exa_wait_rendering;
	bufmgr_exa->radeon_bufmgr.emit_reloc = radeon_bufmgr_exa_emit_reloc;
	return &bufmgr_exa->bufmgr;
}

void radeon_bufmgr_post_submit(dri_bufmgr *bufmgr)
{
	dri_bufmgr_exa *bufmgr_exa = (dri_bufmgr_exa *)bufmgr;
	struct _dri_bo_exa *trav, *prev;

	if (!bufmgr_exa->reloc_head)
		return;

	trav = bufmgr_exa->reloc_head;
	while (trav) {
		prev = trav;
		trav = trav->next;
		
		prev->reloc_count = 0;
		prev->next = NULL;
		dri_bo_unreference(&prev->bo);
	}
	bufmgr_exa->reloc_head = NULL;

}

void radeon_bufmgr_pin(dri_bo *buf)
{
	dri_bufmgr_exa *bufmgr_exa = (dri_bufmgr_exa *)buf->bufmgr;
	dri_bo_exa *exa_buf = (dri_bo_exa *)buf;

	radeon_bind_memory(bufmgr_exa->pScrn, exa_buf->mem);
}

void radeon_bufmgr_unpin(dri_bo *buf)
{
	dri_bufmgr_exa *bufmgr_exa = (dri_bufmgr_exa *)buf->bufmgr;
	dri_bo_exa *exa_buf = (dri_bo_exa *)buf;

	radeon_unbind_memory(bufmgr_exa->pScrn, exa_buf->mem);
}

uint32_t radeon_bufmgr_get_handle(dri_bo *buf)
{
	dri_bo_exa *exa_buf = (dri_bo_exa *)buf;
	
	return exa_buf->mem->kernel_bo_handle;
}
