#ifndef RADEON_BUFMGR_EXA_H
#define RADEON_BUFMGR_EXA_H

#include "radeon_dri_bufmgr.h"

dri_bufmgr *radeon_bufmgr_exa_init(ScrnInfoPtr pScrn);
extern void radeon_bufmgr_exa_wait_rendering(dri_bo *bo);
extern dri_bo *radeon_bufmgr_exa_create_bo(dri_bufmgr *bufmgr, struct radeon_memory *mem);
void radeon_bufmgr_exa_emit_reloc(dri_bo *bo, uint32_t *head, uint32_t *count_p, uint32_t read_domains, uint32_t write_domain);
void radeon_bufmgr_post_submit(dri_bufmgr *bufmgr);
void radeon_bufmgr_pin(dri_bo *buf);
void radeon_bufmgr_unpin(dri_bo *buf);
uint32_t radeon_bufmgr_get_handle(dri_bo *buf);
#endif
