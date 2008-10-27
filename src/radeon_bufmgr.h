/**
 * @file intel_bufmgr.h
 *
 * Public definitions of Intel-specific bufmgr functions.
 */

#ifndef RADEON_BUFMGR_H
#define RADEON_BUFMGR_H

#include "radeon_dri_bufmgr.h"

struct radeon_bufmgr {
  void (*emit_reloc)(dri_bo *buf, struct radeon_relocs_info *relocs, uint32_t *head, uint32_t *count_p, uint32_t read_domains, uint32_t write_domain);
};

dri_bufmgr *radeon_bufmgr_gem_init(int fd);
dri_bo *radeon_bo_gem_create_from_name(dri_bufmgr *bufmgr, const char *name,
				       unsigned int handle);
dri_bo *radeon_bo_gem_create_from_handle(dri_bufmgr *bufmgr,
					 uint32_t handle, unsigned long size);

void radeon_bufmgr_emit_reloc(dri_bo *buf, struct radeon_relocs_info *relocs, uint32_t *head, uint32_t *count_p, uint32_t read_domains, uint32_t write_domain);

dri_bufmgr *radeon_bufmgr_exa_init(ScrnInfoPtr pScrn);
extern void radeon_bufmgr_exa_wait_rendering(dri_bo *bo);
extern dri_bo *radeon_bufmgr_exa_create_bo(dri_bufmgr *bufmgr, struct radeon_memory *mem);
void radeon_bufmgr_post_submit(dri_bufmgr *bufmgr);
#endif
