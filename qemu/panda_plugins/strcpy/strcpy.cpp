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

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "rr_log.h"

#include "panda_plugin.h"
#include "panda_plugins/taint/taint_ext.h"

#include <stdio.h>

bool init_plugin(void *);
void uninit_plugin(void *);

int before_block_exec(CPUState *env, TranslationBlock *tb);

} // extern "C"

#include <set>
#include <vector>
#include <string>

static std::set<target_ulong> tainted_strcpys;

static FILE *strcpy_log;

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
            uint32_t num_labels = taint_query_ram(panda_virt_to_phys(env, src));
            if (num_labels > 0) {
                target_ulong ret = get_stack(env, 0);
                fprintf(strcpy_log, "TAINTED strcpy: ret=%lx, str=%lx, num=%u\n", ret, src, num_labels);
                char buf[200];
                panda_virtual_memory_rw(env, get_stack(env, 2), (uint8_t *)buf, 200, 0);
                fprintf(strcpy_log, "    %s\n", buf);
                tainted_strcpys.insert(ret);
            }
        }
    }

    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    strcpy_log = fopen("strcpy.txt", "w");

    init_taint_api();

    return true;
}

void uninit_plugin(void *self) {
    for (auto it = tainted_strcpys.begin(); it != tainted_strcpys.end(); it++) {
        printf("0x%lx\n", *it);
    }
    printf("\n");
}
