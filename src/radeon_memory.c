
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "radeon.h"
#include "radeon_drm.h"

Bool
radeon_bind_memory(ScrnInfoPtr pScrn, struct radeon_memory *mem)
{
	RADEONInfoPtr info = RADEONPTR(pScrn);	
  
	if (mem == NULL || mem->bound)
		return TRUE;

	if (!info->drm_mm)
		return FALSE;

	if (mem->kernel_bo_handle) {
		struct drm_radeon_gem_pin pin;

		int ret;

		pin.handle = mem->kernel_bo_handle;
		pin.alignment = mem->alignment;

		ret = ioctl(info->drmFD, DRM_IOCTL_RADEON_GEM_PIN, &pin);
		if (ret != 0) {
			xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
				   "Failed to pin %s: %s\n", mem->name, strerror(errno));
			return FALSE;
		}

		mem->bound = TRUE;
		mem->offset = pin.offset;
		ErrorF("pin returned 0x%llx\n", pin.offset);
		mem->end = mem->offset + mem->size;
		return TRUE;
	}
	return FALSE;
}

static Bool
radeon_unbind_memory(ScrnInfoPtr pScrn, struct radeon_memory *mem)
{
	RADEONInfoPtr info = RADEONPTR(pScrn);
	int ret;

	if (mem == NULL || !mem->bound)
		return TRUE;

	if (!info->drm_mm)
		return FALSE;


	if (mem->kernel_bo_handle) {
		struct drm_radeon_gem_unpin unpin;

		unpin.handle = mem->kernel_bo_handle;
		ret = ioctl(info->drmFD, DRM_IOCTL_RADEON_GEM_UNPIN, &unpin);

		if (ret == 0) {
			mem->bound = FALSE;
			mem->offset = -1;
			mem->end = -1;
			return TRUE;
		} else {
			return FALSE;
		}
	}
	return FALSE;
}

void radeon_free_memory(ScrnInfoPtr pScrn, struct radeon_memory *mem)
{
	RADEONInfoPtr info = RADEONPTR(pScrn);

	if (mem == NULL)
		return;

	if (mem->map)
	    radeon_unmap_memory(pScrn, mem);
	    
	radeon_unbind_memory(pScrn, mem);

	if (mem->kernel_bo_handle) {
		struct drm_gem_close close;

		close.handle = mem->kernel_bo_handle;
		ioctl(info->drmFD, DRM_IOCTL_GEM_CLOSE, &close);
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

struct radeon_memory *radeon_allocate_memory(ScrnInfoPtr pScrn, int pool, int size, int alignment, Bool no_backing_store, char *name)
{
    RADEONInfoPtr  info   = RADEONPTR(pScrn);	
    struct drm_radeon_gem_create args;
    struct radeon_memory *mem, *scan;
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
      args.initial_domain = RADEON_GEM_DOMAIN_CPU;
    args.no_backing_store = no_backing_store;

    ret = drmCommandWriteRead(info->drmFD, DRM_RADEON_GEM_CREATE, &args, sizeof(args));
    if (ret) {
	ErrorF("Failed to allocate %s\n", mem->name);
	xfree(mem);
	return NULL;
    }

    mem->kernel_bo_handle = args.handle;
    xf86DrvMsg(pScrn->scrnIndex, X_INFO,	
	       "%s allocated with handle %x\n", mem->name, mem->kernel_bo_handle);

    /* add to VRAM linked list for now */

    mem->prev = NULL;
    mem->next = info->mm.bo_list[pool];
    if (info->mm.bo_list[pool] != NULL)
	info->mm.bo_list[pool]->prev = mem;
    info->mm.bo_list[pool] = mem;
    return mem;
}

Bool radeon_bind_all_memory(ScrnInfoPtr pScrn)
{
    RADEONInfoPtr  info   = RADEONPTR(pScrn);	
    struct radeon_memory *mem;
    int i;

    for (i = 0; i < 2; i++) {
	for (mem = info->mm.bo_list[i]; mem->next != NULL;
	     mem = mem->next) {
	    if (!radeon_bind_memory(pScrn, mem)) {
		FatalError("Couldn't bind %s\n", mem->name);
		
	    }
	}
    }
    return TRUE;
}
	    
Bool radeon_unbind_all_memory(ScrnInfoPtr pScrn)
{
    RADEONInfoPtr  info   = RADEONPTR(pScrn);	
    struct radeon_memory *mem;
    int i;

    for (i = 0; i < 2; i++) {
	for (mem = info->mm.bo_list[i]; mem->next != NULL;
	     mem = mem->next) {
	    radeon_unbind_memory(pScrn, mem);
	}
    }
    return TRUE;
}

int radeon_map_memory(ScrnInfoPtr pScrn, struct radeon_memory *mem)
{
    struct drm_radeon_gem_mmap args;
    RADEONInfoPtr info = RADEONPTR(pScrn);
    int ret;

    args.handle = mem->kernel_bo_handle;
    args.size = mem->size;
    ret = drmCommandWriteRead(info->drmFD, DRM_RADEON_GEM_MMAP, &args, sizeof(args));

    if (!ret)
	mem->map = (void *)(unsigned long)args.addr_ptr;
    ErrorF("Mapped %s size %d at %d %p\n", mem->name, mem->size, mem->offset, mem->map);
    return ret;
}

void radeon_unmap_memory(ScrnInfoPtr pScrn, struct radeon_memory *mem)
{
    munmap(mem->map, mem->size);
    mem->map = NULL;
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
    int total_size_bytes = (20*1024*1024)+32*1024, remain_size_bytes;
    int fb_size_bytes;

    screen_size = RADEON_ALIGN(pScrn->virtualY, 16) * stride;

    ErrorF("%d x %d x %d = %dK\n", pScrn->displayWidth, pScrn->virtualY, cpp, screen_size / 1024);

    {
	int cursor_size = 64 * 4 * 64;
	int c;

	for (c = 0; c < xf86_config->num_crtc; c++) {
	    /* cursor objects */
	    info->mm.cursor[c] = radeon_allocate_memory(pScrn, RADEON_POOL_VRAM, cursor_size, 0, 1, "Cursor");
	    if (!info->mm.cursor[c]) {
		return FALSE;
	    }

	    radeon_bind_memory(pScrn, info->mm.cursor[c]);

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

#if 0
    info->mm.front_buffer = radeon_allocate_memory(pScrn, RADEON_POOL_VRAM, screen_size, 0, 1, "Front Buffer");
    if (!info->mm.front_buffer) {
	return FALSE;
    }

    radeon_bind_memory(pScrn, info->mm.front_buffer);

    if (radeon_map_memory(pScrn, info->mm.front_buffer)) {
	ErrorF("Failed to map front buffer memory\n");
    }
#endif
    /* keep area front front buffer - but don't allocate it yet */
    total_size_bytes += screen_size;

    if (info->directRenderingEnabled) {
	info->backPitch = pScrn->displayWidth;
	info->mm.back_buffer = radeon_allocate_memory(pScrn, RADEON_POOL_VRAM, screen_size, 0, 1, "Back Buffer");
	if (!info->mm.back_buffer) {
	    return FALSE;
	}
	radeon_bind_memory(pScrn, info->mm.back_buffer);
	total_size_bytes += screen_size;
	
	info->depthPitch = RADEON_ALIGN(pScrn->displayWidth, 32);
	{
	    int depthCpp = (info->depthBits - 8) / 4;
	    int depth_size = RADEON_ALIGN(pScrn->virtualY, 16) * info->depthPitch * depthCpp;
	    info->mm.depth_buffer = radeon_allocate_memory(pScrn, RADEON_POOL_VRAM, depth_size, 0, 1, "Depth Buffer");
	    if (!info->mm.depth_buffer) {
		return FALSE;
	    }
	    radeon_bind_memory(pScrn, info->mm.depth_buffer);
	    total_size_bytes += depth_size;
	}
    }
    /* work out from the mm size what the exa / tex sizes need to be */
    remain_size_bytes = info->mm.vram_size - total_size_bytes;

    info->textureSize = remain_size_bytes / 2;

    ErrorF("texture size is %dK, exa is %dK\n", info->textureSize / 1024, (remain_size_bytes - info->textureSize)/1024);


        /* allocate an object for all the EXA bits */
    /* shove EXA + frontbuffer together until we have EXA pixmap hooks */
    fb_size_bytes = screen_size + (remain_size_bytes - info->textureSize);
    ErrorF("fb size is %dK %dK\n", fb_size_bytes / 1024, total_size_bytes / 1024);

    fb_size_bytes = 64 * 1024 * 1024;
    info->mm.front_buffer = radeon_allocate_memory(pScrn, RADEON_POOL_VRAM, fb_size_bytes, 0, 1, "Front Buffer + EXA");
    if (!info->mm.front_buffer) {
	return FALSE;
    }

    radeon_bind_memory(pScrn, info->mm.front_buffer);
    if (radeon_map_memory(pScrn, info->mm.front_buffer)) {
	ErrorF("Failed to map front buffer memory\n");
    }
    info->frontPitch = pScrn->displayWidth;
#if 0
    info->mm.exa_buffer = radeon_allocate_memory(pScrn, RADEON_POOL_VRAM, remain_size_bytes - info->textureSize, 0, 1, "EXA Memory Buffer");
    if (!info->mm.exa_buffer) {
	return FALSE;
    }
    radeon_bind_memory(pScrn, info->mm.exa_buffer);
    if (radeon_map_memory(pScrn, info->mm.exa_buffer)) {
	ErrorF("Failed to map front buffer memory\n");
    }
#endif
    info->exa->memoryBase = info->mm.front_buffer->map;
    info->exa->offScreenBase = screen_size;
    info->exa->memorySize = fb_size_bytes;

    xf86DrvMsg(pScrn->scrnIndex, X_INFO,
	       "Will use %ld kb for X Server offscreen at offset 0x%08lx\n",
	       (info->exa->memorySize - info->exa->offScreenBase) /
	       1024, info->exa->offScreenBase);

    if (info->directRenderingEnabled) {
	/* allocate an object for all the textures */
	info->textureSize /= 2;
	info->mm.texture_buffer = radeon_allocate_memory(pScrn, RADEON_POOL_VRAM, info->textureSize, 0, 1, "Texture Buffer");
	if (!info->mm.texture_buffer) {
	    return FALSE;
	}
	radeon_bind_memory(pScrn, info->mm.texture_buffer);
	
    }
	
    if (info->drm_mode_setting) {
	drmmode_set_fb(pScrn, &info->drmmode, pScrn->virtualX, RADEON_ALIGN(pScrn->virtualY, 16), stride, info->mm.front_buffer->kernel_bo_handle);
    }
    return TRUE;
}

Bool radeon_setup_gart_mem(ScreenPtr pScreen)
{
    ScrnInfoPtr pScrn = xf86Screens[pScreen->myNum];
    RADEONInfoPtr info = RADEONPTR(pScrn);


    info->mm.gart_texture_buffer =
	radeon_allocate_memory(pScrn, RADEON_POOL_GART,
			       info->gartTexMapSize,
			       0, 1, "GART texture buffers");
    
    if (!info->mm.gart_texture_buffer) {
	return FALSE;
    }

    radeon_bind_memory(pScrn, info->mm.gart_texture_buffer);
    return TRUE;
}

uint32_t radeon_create_new_fb(ScrnInfoPtr pScrn, int width, int height, int *pitch)
{
    return 0;
}



