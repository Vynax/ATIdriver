
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "radeon.h"
#include "radeon_drm.h"
#include "radeon_bufmgr_gem.h"

void radeon_free_memory(ScrnInfoPtr pScrn, struct radeon_memory *mem)
{
	RADEONInfoPtr info = RADEONPTR(pScrn);

	if (mem == NULL)
		return;

	if (mem->map)
	    radeon_unmap_memory(pScrn, mem);
	    
	if (mem->kernel_bo_handle) {
		struct drm_gem_close close;

		close.handle = mem->kernel_bo_handle;
		ioctl(info->dri->drmFD, DRM_IOCTL_GEM_CLOSE, &close);
	}

	if (info->mm.bo_list[mem->pool] == mem) {
	  info->mm.bo_list[mem->pool] = mem->next;
	  if (mem->next)
	    mem->next->prev = NULL;
	} else {
	  if (mem->prev)
	    mem->prev->next = mem->next;
	  if (mem->next)
	    mem->next->prev = mem->prev;
	}
	xfree(mem->name);
	xfree(mem);
	return;
}

struct radeon_memory *radeon_allocate_memory(ScrnInfoPtr pScrn, int pool, int size, int alignment, Bool no_backing_store, char *name,
					     int static_alloc)
{
    RADEONInfoPtr  info   = RADEONPTR(pScrn);	
    struct drm_radeon_gem_create args;
    struct radeon_memory *mem;
    int ret;

    mem = xcalloc(1, sizeof(*mem));
    if (!mem)
	return NULL;
    
    mem->name = xstrdup(name); 
    if (!mem->name) {
	xfree(mem);
	return NULL;
    }

    mem->size = size;
    mem->pool = pool;
    mem->next = mem->prev = NULL;
    args.size = size;
    args.alignment = alignment;
    if (pool == RADEON_POOL_VRAM)
      args.initial_domain = RADEON_GEM_DOMAIN_VRAM;
    else
      args.initial_domain = RADEON_GEM_DOMAIN_GTT;
    args.flags = no_backing_store ? RADEON_GEM_NO_BACKING_STORE : 0;

    ret = drmCommandWriteRead(info->dri->drmFD, DRM_RADEON_GEM_CREATE, &args, sizeof(args));
    if (ret) {
	ErrorF("Failed to allocate %s\n", mem->name);
	xfree(mem);
	return NULL;
    }

    mem->kernel_bo_handle = args.handle;
    //    xf86DrvMsg(pScrn->scrnIndex, X_INFO,	
    //	       "%s allocated %d with handle %x\n", mem->name, mem->size, mem->kernel_bo_handle);

    /* add to VRAM linked list for now */

    mem->prev = NULL;
    mem->next = info->mm.bo_list[pool];
    if (info->mm.bo_list[pool] != NULL)
	info->mm.bo_list[pool]->prev = mem;
    info->mm.bo_list[pool] = mem;
    return mem;
}

Bool radeon_free_all_memory(ScrnInfoPtr pScrn)
{
    RADEONInfoPtr  info   = RADEONPTR(pScrn);	
    struct radeon_memory *mem, *tmp;
    int i;

    for (i = 0; i < 2; i++) {
	
	for (mem = info->mm.bo_list[i]; mem != NULL; ) {
	    tmp = mem->next;
	    radeon_free_memory(pScrn, mem);
	    mem = tmp;
	}
    }
    return TRUE;
}

int radeon_map_memory(ScrnInfoPtr pScrn, struct radeon_memory *mem)
{
    struct drm_radeon_gem_mmap args;
    RADEONInfoPtr info = RADEONPTR(pScrn);
    int ret;
    void *ptr;

    assert(!mem->map);

    args.handle = mem->kernel_bo_handle;
    args.size = mem->size;
    ret = drmCommandWriteRead(info->dri->drmFD, DRM_RADEON_GEM_MMAP, &args, sizeof(args));

    if (ret)
	return ret;

    ptr = mmap(0, args.size, PROT_READ|PROT_WRITE, MAP_SHARED, info->dri->drmFD, args.addr_ptr);
    if (ptr == MAP_FAILED)
        return -errno;

    mem->map = ptr;
    //    ErrorF("Mapped %s size %ld at %x %p\n", mem->name, mem->size, mem->offset, mem->map);
    return ret;
}

void radeon_unmap_memory(ScrnInfoPtr pScrn, struct radeon_memory *mem)
{
    assert(mem->map);
    if (mem->map) {
        munmap(mem->map, mem->size);
        mem->map = NULL;
    }
}

/* Okay radeon
   2D allocations 
   - Front buffer
   - cursors
   - EXA space

   3D related:
   - Backbuffer
   - Depth buffer
   - textures
*/


Bool radeon_setup_kernel_mem(ScreenPtr pScreen)
{
    ScrnInfoPtr pScrn = xf86Screens[pScreen->myNum];
    RADEONInfoPtr info = RADEONPTR(pScrn);
    xf86CrtcConfigPtr   xf86_config = XF86_CRTC_CONFIG_PTR(pScrn);
    int cpp = info->CurrentLayout.pixel_bytes;
    int screen_size;
    int stride = pScrn->displayWidth * cpp;
    int total_size_bytes = 0, remain_size_bytes;
    int fb_size_bytes;
    int pagesize = 4096;
    
    screen_size = RADEON_ALIGN(pScrn->virtualY, 16) * stride;

    ErrorF("%d x %d x %d = %dK\n", pScrn->displayWidth, pScrn->virtualY, cpp, screen_size / 1024);

    {
	int cursor_size = 64 * 4 * 64;
	int c;

    	cursor_size = RADEON_ALIGN(cursor_size, pagesize);
	for (c = 0; c < xf86_config->num_crtc; c++) {
	    /* cursor objects */
	    info->mm.cursor[c] = radeon_allocate_memory(pScrn, RADEON_POOL_VRAM, cursor_size, 0, 1, "Cursor", 0);
	    if (!info->mm.cursor[c]) {
		return FALSE;
	    }

	    if (radeon_map_memory(pScrn, info->mm.cursor[c])) {
		ErrorF("Failed to map front buffer memory\n");
	    }
	    
	    if (!info->drm_mode_setting) {
		xf86CrtcPtr crtc = xf86_config->crtc[c];
		RADEONCrtcPrivatePtr radeon_crtc = crtc->driver_private;
		radeon_crtc->cursor = info->mm.cursor[c];
	    } else {
		drmmode_set_cursor(pScrn, &info->drmmode, c, (void *)info->mm.cursor[c]->map, info->mm.cursor[c]->kernel_bo_handle);
	    }
	    total_size_bytes += cursor_size;
	}
    }

    screen_size = RADEON_ALIGN(screen_size, pagesize);
    /* keep area front front buffer - but don't allocate it yet */
    total_size_bytes += screen_size;

    /* work out from the mm size what the exa / tex sizes need to be */
    remain_size_bytes = info->mm.vram_size - total_size_bytes;

    info->dri->textureSize = 0;
#if 0
    if (info->dri->textureSize > 0)
    	info->dri->textureSize = (remain_size_bytes / 100) * info->dri->textureSize;
    else
    	info->dri->textureSize = remain_size_bytes / 2;

    info->dri->textureSize = RADEON_ALIGN(info->dri->textureSize, pagesize);

    remain_size_bytes -= info->dri->textureSize;
#endif

    ErrorF("texture size is %dK, exa is %dK\n", info->dri->textureSize / 1024, remain_size_bytes/1024);


    fb_size_bytes = screen_size;

    ErrorF("fb size is %dK %dK\n", fb_size_bytes / 1024, total_size_bytes / 1024);

    info->mm.front_buffer = radeon_allocate_memory(pScrn, RADEON_POOL_VRAM, fb_size_bytes, 0, 1, "Front Buffer", 1);
    if (!info->mm.front_buffer) {
	return FALSE;
    }

    drmmode_set_fb(pScrn, &info->drmmode, pScrn->virtualX, RADEON_ALIGN(pScrn->virtualY, 16), stride, info->mm.front_buffer->kernel_bo_handle);

    xf86DrvMsg(pScrn->scrnIndex, X_INFO, "Front buffer size: %dK at 0x%08x\n", info->mm.front_buffer->size/1024, info->mm.front_buffer->offset);
    xf86DrvMsg(pScrn->scrnIndex, X_INFO, "Remaining VRAM size (used for pixmaps): %dK\n", remain_size_bytes/1024);

    /* set the emit limit at 90% of VRAM */
    remain_size_bytes = (remain_size_bytes / 10) * 9;

    radeon_bufmgr_gem_set_limit(info->bufmgr, RADEON_GEM_DOMAIN_VRAM, remain_size_bytes);
    return TRUE;
}


