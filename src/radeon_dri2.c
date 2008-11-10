/*
 * Copyright 2008 Kristian Høgsberg 
 * Copyright 2008 Jérôme Glisse
 *
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation on the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NON-INFRINGEMENT.  IN NO EVENT SHALL ATI, VA LINUX SYSTEMS AND/OR
 * THEIR SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "radeon.h"
#include "radeon_dri2.h"
#include "radeon_version.h"

#ifdef DRI2

struct dri2_buffer_priv {
    PixmapPtr   pixmap;
};


static DRI2BufferPtr
radeon_dri2_create_buffers(DrawablePtr drawable,
                           unsigned int *attachments,
                           int count)
{
    ScreenPtr pScreen = drawable->pScreen;
    DRI2BufferPtr buffers;
    struct dri2_buffer_priv *privates;
    PixmapPtr pixmap, depth_pixmap;
    struct radeon_exa_pixmap_priv *driver_priv;
    int i, r;

    buffers = xcalloc(count, sizeof *buffers);
    if (buffers == NULL) {
        return NULL;
    }
    privates = xcalloc(count, sizeof(struct dri2_buffer_priv));
    if (privates == NULL) {
        xfree(buffers);
        return NULL;
    }

    depth_pixmap = NULL;
    for (i = 0; i < count; i++) {
        if (attachments[i] == DRI2BufferFrontLeft) {
            if (drawable->type == DRAWABLE_PIXMAP) {
                pixmap = (Pixmap*)drawable;
            } else {
                pixmap = (*pScreen->GetWindowPixmap)((WindowPtr)drawable);
            }
            pixmap->refcnt++;
        } else if (attachments[i] == DRI2BufferStencil && depth_pixmap) {
            pixmap = depth_pixmap;
            pixmap->refcnt++;
        } else {
            pixmap = (*pScreen->CreatePixmap)(pScreen,
                                              drawable->width,
                                              drawable->height,
                                              drawable->depth,
                                              0);
        }

        if (attachments[i] == DRI2BufferDepth) {
            depth_pixmap = pixmap;
        }
        driver_priv = exaGetPixmapDriverPrivate(pixmap);
        r = radeon_bo_gem_name_buffer(driver_priv->bo, &buffers[i].name);
        if (r) {
            /* FIXME: cleanup */
            fprintf(stderr, "flink error: %d %s\n", r, strerror(r));
            xfree(buffers);
            xfree(privates);
            return NULL;
        }
        fprintf(stderr, "flinkname: %d\n", buffers[i].name);
        buffers[i].attachment = attachments[i];
        buffers[i].pitch = pixmap->devKind;
        buffers[i].cpp = pixmap->drawable.bitsPerPixel / 8;
        buffers[i].driverPrivate = &privates[i];
        buffers[i].flags = 0; /* not tiled */
        privates[i].pixmap = pixmap;
    }
    return buffers;
}

static void
radeon_dri2_destroy_buffers(DrawablePtr drawable,
                            DRI2BufferPtr buffers,
                            int count)
{
    ScreenPtr pScreen = drawable->pScreen;
    struct dri2_buffer_priv *private;
    int i;

    for (i = 0; i < count; i++) {
        private = buffers[i].driverPrivate;
        (*pScreen->DestroyPixmap)(private->pixmap);
    }
    if (buffers) {
        xfree(buffers[0].driverPrivate);
        xfree(buffers);
    }
}

static void
radeon_dri2_copy_region(DrawablePtr drawable,
                        RegionPtr region,
                        DRI2BufferPtr dest_buffer,
                        DRI2BufferPtr src_buffer)
{
    struct dri2_buffer_priv *private = src_buffer->driverPrivate;
    ScreenPtr pScreen = drawable->pScreen;
    ScrnInfoPtr pScrn = xf86Screens[pScreen->myNum];
    PixmapPtr pixmap = private->pixmap;
    RegionPtr copy_clip;
    GCPtr gc;

    gc = GetScratchGC(drawable->depth, pScreen);
    copy_clip = REGION_CREATE(pScreen, NULL, 0);
    REGION_COPY(pScreen, copy_clip, region);
    (*gc->funcs->ChangeClip) (gc, CT_REGION, copy_clip, 0);
    ValidateGC(drawable, gc);
    (*gc->ops->CopyArea)(&pixmap->drawable, drawable, gc,
                         0, 0, drawable->width, drawable->height, 0, 0);
    FreeScratchGC(gc);
    RADEONCPReleaseIndirect(pScrn);
}

Bool
radeon_dri2_screen_init(ScreenPtr pScreen)
{
    ScrnInfoPtr pScrn = xf86Screens[pScreen->myNum];
    RADEONInfoPtr info = RADEONPTR(pScrn);
    DRI2InfoRec dri2_info;
    int fd;
    char *bus_id;
    char *tmp_bus_id;
    int cmp;
    int i;

    if (!info->useEXA) {
        xf86DrvMsg(pScrn->scrnIndex, X_WARNING, "DRI2 requires EXA\n");
        return FALSE;
    }

    /* The whole drmOpen thing is a fiasco and we need to find a way
     * back to just using open(2).  For now, however, lets just make
     * things worse with even more ad hoc directory walking code to
     * discover the device file name. */
    bus_id = DRICreatePCIBusID(info->PciInfo);
    for (i = 0; i < DRM_MAX_MINOR; i++) {
        sprintf(info->dri2.device_name, DRM_DEV_NAME, DRM_DIR_NAME, i);
        fd = open(info->dri2.device_name, O_RDWR);
        if (fd < 0)
            continue;

        tmp_bus_id = drmGetBusid(fd);
        close(fd);
        if (tmp_bus_id == NULL)
            continue;

        cmp = strcmp(tmp_bus_id, bus_id);
        drmFree(tmp_bus_id);
        if (cmp == 0)
            break;
    }
    xfree(bus_id);

    if (i == DRM_MAX_MINOR) {
        xf86DrvMsg(pScrn->scrnIndex, X_WARNING,
                   "DRI2: failed to open drm device\n");
        return FALSE;
    }

    if ( (info->ChipFamily >= CHIP_FAMILY_R300) ) {
        dri2_info.driverName = R300_DRIVER_NAME;
    } else if ( info->ChipFamily >= CHIP_FAMILY_R200 ) {
        dri2_info.driverName = R200_DRIVER_NAME;
    } else {
        dri2_info.driverName = RADEON_DRIVER_NAME;
    }
    dri2_info.fd = info->dri2.drm_fd;
    dri2_info.deviceName = info->dri2.device_name;
    dri2_info.version = 1;
    dri2_info.CreateBuffers = radeon_dri2_create_buffers;
    dri2_info.DestroyBuffers = radeon_dri2_destroy_buffers;
    dri2_info.CopyRegion = radeon_dri2_copy_region;
    info->dri2.enabled = DRI2ScreenInit(pScreen, &dri2_info);
    return info->dri2.enabled;
}

void
radeon_dri2_close_screen(ScreenPtr pScreen)
{
    DRI2CloseScreen(pScreen);
}

#endif
