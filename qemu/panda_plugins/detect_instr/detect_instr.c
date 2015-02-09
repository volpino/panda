/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Federico Scrinzi      fox91 anche dot no
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
#include "cpu.h"

#include "panda_plugin.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <capstone/capstone.h>

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);

bool init_plugin(void *);
void uninit_plugin(void *);

// This is where we'll write out the detected instructions data
FILE *plugin_log;
panda_arg_list* args;
const char* instr_to_detect;

csh handle;
csh handle2;

// Check if the instruction is the desired one
bool translate_callback(CPUState *env, target_ulong pc) {
    // The maximum length of an instruction on x86 is 15 bytes
    // FIXME: This might be broken for other archs
    unsigned char buf[15];
    panda_virtual_memory_rw(env, pc, buf, 15, 0);

    bool found = false;
    cs_insn *insn;
    size_t count;

    csh* curr_handle = &handle;

#ifdef TARGET_ARM
    if (env->thumb == 0) {
        curr_handle = &handle2;
    }
#endif

#if defined(TARGET_I386) || defined(TARGET_X86_64)
    if (!(env->hflags & HF_LMA_MASK)) {  // true if it's 32 bit mode
        curr_handle = &handle2;
    }
#endif

    count = cs_disasm(*curr_handle, buf, sizeof(buf), 0, 1, &insn);
    if (count > 0) {
        if (strcasecmp(insn[0].mnemonic, instr_to_detect) == 0) {
            found = true;
        }
        cs_free(insn, count);
    }

    return found;
}

// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    fprintf(plugin_log, "PC=" TARGET_FMT_lx ", EAX=" TARGET_FMT_lx "\n", pc, env->regs[R_EAX]);
#endif
#ifdef TARGET_ARM
    fprintf(plugin_log, "PC=" TARGET_FMT_lx ", R0=" TARGET_FMT_lx "\n", pc, env->regs[0]);
#endif
    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb;

#if defined(TARGET_I386) || defined(TARGET_X86_64) || defined(TARGET_ARM)
    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    args = panda_get_args("detect_instr");
    instr_to_detect = panda_parse_string(args, "instr", "");
#endif

#if defined(TARGET_I386) || defined(TARGET_X86_64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return false;

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle2) != CS_ERR_OK)
        return false;
#endif

#ifdef TARGET_ARM
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK)
        return false;

    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle2) != CS_ERR_OK)
        return false;
#endif

    plugin_log = fopen("detect_instr.txt", "w");
    if (!plugin_log) return false;
    else return true;

    return true;
}

void uninit_plugin(void *self) {
    fclose(plugin_log);
    panda_free_args(args);
#if defined(TARGET_I386) || defined(TARGET_X86_64) || defined(TARGET_ARM)
    cs_close(&handle);
    cs_close(&handle2);
#endif
}
