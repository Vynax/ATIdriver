#ifndef RADEON_BUFMGR_EXA_H
#define RADEON_BUFMGR_EXA_H

#include "dri_bufmgr.h"

dri_bufmgr *radeon_bufmgr_exa_init(ScrnInfoPtr pScrn);
extern void radeon_bufmgr_exa_wait_rendering(dri_bo *bo);
extern dri_bo *radeon_bufmgr_exa_create_bo(dri_bufmgr *bufmgr, struct radeon_memory *mem);
void radeon_bufmgr_exa_emit_reloc(dri_bo *bo, uint32_t *head, uint32_t *count_p);
void radeon_bufmgr_post_submit(dri_bufmgr *bufmgr);
#endif
