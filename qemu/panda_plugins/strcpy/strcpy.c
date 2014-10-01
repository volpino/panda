/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "config.h"
#include "qemu-common.h"
#include "rr_log.h"

#include "panda_plugin.h"
#include "panda_plugins/taint/taint_ext.h"

#include <stdio.h>

bool init_plugin(void *);
void uninit_plugin(void *);

int before_block_exec(CPUState *env, TranslationBlock *tb);

uint32_t get_stack(CPUState *env, int offset) {
    uint32_t result = 0;
    panda_virtual_memory_rw(env, env->regs[R_ESP] + 4 * offset, (uint8_t *)&result, 4, 0);
    return result;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (env->cr[3] == 0x074c4000 || env->cr[3] == 0x07a41000) {
        //printf("it's a bash: %lx\n", tb->pc);
        // right process.
        if (tb->pc == 0x080646c0) {
            target_ulong src = get_stack(env, 2);
            printf("strcpy: ret=%lx, str=%lx\n", get_stack(env, 0), src);
            char buf[4096];
            panda_virtual_memory_rw(env, get_stack(env, 2), (uint8_t *)buf, 4096, 0);
            //printf("    %s\n", buf);
            printf("     %lu\n", taint_query_ram(panda_virt_to_phys(env, src)));
        }
    }

    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    init_taint_api();

    return true;
}

void uninit_plugin(void *self) {

}
