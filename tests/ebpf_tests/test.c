/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
 * Copyright 2017 Yutaro Hayakawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <math.h>
#include <sys/ebpf.h>

#if defined(__APPLE__)
#include "../../Darwin/ebpf/user/elf.h" 
#else
#include <elf.h>
#endif

/* MaxOSX and FreeBSD doesn't have memfrob */
#if defined(__APPLE__) || defined(__FreeBSD__)
void *
memfrob(void *s, size_t n)
{
    uint8_t *t = s;
    for (int i = 0; i < n; i++) {
        *(t + i) = *(t + i) ^ 42;
    }

    return s;
}
#endif

static void *readfile(const char *path, size_t maxlen, size_t *len);
static void register_functions(struct ebpf_vm *vm);

static void
usage(const char *name)
{
    fprintf(stderr, "usage: %s [-h] [-j|--jit] [-m|--mem PATH] BINARY\n", name);
    fprintf(stderr, "\nExecutes the eBPF code in BINARY and prints the result "
                    "to stdout.\n");
    fprintf(stderr, "If --mem is given then the specified file will be read "
                    "and a pointer\nto its data passed in r1.\n");
    fprintf(stderr, "If --jit is given then the JIT compiler will be used.\n");
    fprintf(stderr, "\nOther options:\n");
}

int
main(int argc, char **argv)
{
    struct option longopts[] = {{
                                    .name = "help",
                                    .val = 'h',
                                },
                                {.name = "mem", .val = 'm', .has_arg = 1},
                                {.name = "jit", .val = 'j'},
                                {}};

    const char *mem_filename = NULL;
    bool jit = false;

    int opt;
    while ((opt = getopt_long(argc, argv, "hm:j", longopts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            mem_filename = optarg;
            break;
        case 'j':
            jit = true;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (argc != optind + 1) {
        usage(argv[0]);
        return 1;
    }

    const char *code_filename = argv[optind];
    size_t code_len;
    void *code = readfile(code_filename, 1024 * 1024, &code_len);
    if (code == NULL) {
        return 1;
    }

    size_t mem_len = 0;
    void *mem = NULL;
    if (mem_filename != NULL) {
        mem = readfile(mem_filename, 1024 * 1024, &mem_len);
        if (mem == NULL) {
            return 1;
        }
    }

    struct ebpf_vm *vm = ebpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    register_functions(vm);

    /*
     * The ELF magic corresponds to an RSH instruction with an offset,
     * which is invalid.
     */
    bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);

    int rv;
    if (elf) {
        rv = ebpf_load_elf(vm, code, code_len);
    } else {
        rv = ebpf_load(vm, code, code_len);
    }

    free(code);

    if (rv < 0) {
        ebpf_destroy(vm);
        return 1;
    }

    uint64_t ret;

    if (jit) {
        ebpf_jit_fn fn = ebpf_compile(vm);
        if (fn == NULL) {
            return 1;
        }

        ret = ebpf_exec_jit(vm, mem, mem_len);
    } else {
        ret = ebpf_exec(vm, mem, mem_len);
    }

    printf("0x%" PRIx64 "\n", ret);

    ebpf_destroy(vm);

    return 0;
}

static void *
readfile(const char *path, size_t maxlen, size_t *len)
{
    FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    void *data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data + offset, 1, maxlen - offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr,
                "Failed to read %s because it is too large (max %u bytes)\n",
                path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;
}

static uint64_t
gather_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e)
{
    return ((uint64_t)a << 32) | ((uint32_t)b << 24) | ((uint32_t)c << 16) |
           ((uint16_t)d << 8) | e;
}

static void
trash_registers(void)
{
    /* Overwrite all caller-save registers */
    asm("mov $0xf0, %rax;"
        "mov $0xf1, %rcx;"
        "mov $0xf2, %rdx;"
        "mov $0xf3, %rsi;"
        "mov $0xf4, %rdi;"
        "mov $0xf5, %r8;"
        "mov $0xf6, %r9;"
        "mov $0xf7, %r10;"
        "mov $0xf8, %r11;");
}

static uint32_t
sqrti(uint32_t x)
{
    return sqrt(x);
}

static void
register_functions(struct ebpf_vm *vm)
{
    ebpf_register(vm, 0, "gather_bytes", gather_bytes);
    ebpf_register(vm, 1, "memfrob", memfrob);
    ebpf_register(vm, 2, "trash_registers", trash_registers);
    ebpf_register(vm, 3, "sqrti", sqrti);
    ebpf_register(vm, 4, "strcmp_ext", strcmp);
}
