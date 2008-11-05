#ifndef RADEON_BUFMGR_GEM_H
#define RADEON_BUFMGR_GEM_H

#include "radeon_dri_bufmgr.h"


extern void radeon_bufmgr_gem_wait_rendering(dri_bo *bo);
extern dri_bo *radeon_bufmgr_gem_create_bo(dri_bufmgr *bufmgr, struct radeon_memory *mem);
void radeon_bufmgr_gem_emit_reloc(dri_bo *bo, struct radeon_relocs_info *reloc_info, uint32_t *head, uint32_t *count_p, uint32_t read_domains, uint32_t write_domain);
void radeon_gem_bufmgr_post_submit(dri_bufmgr *bufmgr, struct radeon_relocs_info *reloc_info, int error);
void radeon_bufmgr_pin(dri_bo *buf);
void radeon_bufmgr_unpin(dri_bo *buf);
uint32_t radeon_bufmgr_get_handle(dri_bo *buf);
int radeon_bufmgr_gem_has_references(dri_bo *buf);
int radeon_bufmgr_gem_force_gtt(dri_bo *buf);
void radeon_bufmgr_gem_set_limit(dri_bufmgr *bufmgr, uint32_t domain, uint32_t limit);
int radeon_bufmgr_gem_in_vram(dri_bo *buf);
int radeon_bo_gem_name_buffer(dri_bo *bo, uint32_t *name);
#endif
