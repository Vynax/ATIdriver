
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "radeon.h"
#include "radeon_drm.h"
#include "radeon_bufmgr_gem.h"

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
	    info->mm.cursor[c] = dri_bo_alloc(info->bufmgr, "front", cursor_size,
					      0, RADEON_GEM_DOMAIN_VRAM);
	    if (!info->mm.cursor[c]) {
		return FALSE;
	    }

	    if (dri_bo_map(info->mm.cursor[c], 1)) {
	      ErrorF("Failed to map cursor buffer memory\n");
	    }
	    
	    drmmode_set_cursor(pScrn, &info->drmmode, c, info->mm.cursor[c]);
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

    info->mm.front_buffer = dri_bo_alloc(info->bufmgr, "front", screen_size,
					 0, RADEON_GEM_DOMAIN_VRAM);

    drmmode_set_fb(pScrn, &info->drmmode, pScrn->virtualX, RADEON_ALIGN(pScrn->virtualY, 16), stride, info->mm.front_buffer);

    xf86DrvMsg(pScrn->scrnIndex, X_INFO, "Front buffer size: %dK\n", info->mm.front_buffer->size/1024);
    xf86DrvMsg(pScrn->scrnIndex, X_INFO, "Remaining VRAM size (used for pixmaps): %dK\n", remain_size_bytes/1024);

    /* set the emit limit at 90% of VRAM */
    remain_size_bytes = (remain_size_bytes / 10) * 9;

    radeon_bufmgr_gem_set_limit(info->bufmgr, RADEON_GEM_DOMAIN_VRAM, remain_size_bytes);
    return TRUE;
}


