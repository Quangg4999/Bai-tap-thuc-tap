#define _CRT_SECURE_NO_WARNINGS  /* Windows/MSVC: cho phep dung strcpy khong bao loi C4996 */
/*
 * Bai 1.1 - Memory Layout Explorer (C thuan, malloc)
 * -----------------------------------------------------
 * In dia chi cua: bien local (stack), bien static (function-static
 * va file-static), bien global, va vung cap phat bang malloc.
 * So sanh khoang cach (byte) giua cac vung va giua cac lan cap phat
 * lien tiep trong cung mot vung.
 *
 * Build tren Windows (x64):
 *   - MinGW-w64 :  gcc -O0 -std=c11 memory_layout.c -o memory_layout.exe
 *   - MSVC      :  cl /Od /std:c11 memory_layout.c
 *
 * Chay:
 *   memory_layout.exe
 *
 * Ghi chu: dung -O0 (khong toi uu) de trinh bien dich khong loai bo
 * hay dat bien vao thanh ghi, tranh lam sai lech dia chi quan sat duoc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

/* ---------------- Vung GLOBAL (.data / .bss) ---------------- */
int    g_global_init1 = 111;          /* .data - co gia tri khoi tao */
int    g_global_init2 = 222;
double g_global_init3 = 3.14159;
int    g_global_bss1;                 /* .bss - khong khoi tao (mac dinh 0) */
int    g_global_bss2;

static int g_file_static1 = 999;      /* static o pham vi file: van la
                                          global storage duration, chi
                                          khac o internal linkage */
static int g_file_static2 = 888;

/* ---------------- Ham tien ich in dia chi / khoang cach --------- */
static void print_addr(const char *label, const void *addr)
{
    printf("  %-22s = %p\n", label, addr);
}

/* In khoang cach co dau (b - a) theo byte, kem gia tri hex tri tuyet doi */
static void print_gap(const char *from, const char *to, uintptr_t a, uintptr_t b)
{
    intptr_t diff = (intptr_t)(b - a);
    uintptr_t mag = (uintptr_t)(diff < 0 ? -diff : diff);
    printf("  %-16s -> %-16s : %+" PRIdPTR " byte   (0x%" PRIxPTR ")\n",
           from, to, diff, mag);
}

/* Bien static khai bao TRONG ham: cung la vung static storage duration,
 * nhung thuong nam ke vung global tuy theo trinh bien dich */
static void get_static_local_addrs(uintptr_t out[4])
{
    static int    s1 = 1;
    static int    s2 = 2;
    static double s3 = 3.0;
    static char   s4[8] = "abc";


    printf("\n--- STATIC LOCAL (bien 'static' khai bao trong ham) ---\n");
    print_addr("s1 (static int)",    &s1);
    print_addr("s2 (static int)",    &s2);
    print_addr("s3 (static double)", &s3);
    print_addr("s4 (static char[8])",&s4);

    out[0] = (uintptr_t)&s1;
    out[1] = (uintptr_t)&s2;
    out[2] = (uintptr_t)&s3;
    out[3] = (uintptr_t)&s4;
}

int main(void)
{
    printf("========== MEMORY LAYOUT EXPLORER (C / malloc, x64) ==========\n");
    printf("sizeof(void*) = %zu byte\n", sizeof(void *));

    /* ---------------- GLOBAL ---------------- */
    printf("\n--- GLOBAL / FILE-STATIC (.data, .bss) ---\n");
    print_addr("g_global_init1", &g_global_init1);
    print_addr("g_global_init2", &g_global_init2);
    print_addr("g_global_init3", &g_global_init3);
    print_addr("g_global_bss1",  &g_global_bss1);
    print_addr("g_global_bss2",  &g_global_bss2);
    print_addr("g_file_static1", &g_file_static1);
    print_addr("g_file_static2", &g_file_static2);

    /* ---------------- STATIC LOCAL ---------------- */
    uintptr_t static_addrs[4];
    get_static_local_addrs(static_addrs);

    /* ---------------- LOCAL / STACK ---------------- */
    printf("\n--- LOCAL / STACK (khai bao trong main) ---\n");
    int    l1 = 1;
    int    l2 = 2;
    double l3 = 3.0;
    char   l4[16] = "local-buf";
    int    l5[4]  = {1, 2, 3, 4};
    print_addr("l1 (int)",      &l1);
    print_addr("l2 (int)",      &l2);
    print_addr("l3 (double)",   &l3);
    print_addr("l4 (char[16])", &l4);
    print_addr("l5 (int[4])",   &l5);

    /* ---------------- HEAP (malloc) ---------------- */
    printf("\n--- HEAP (malloc) ---\n");
    int    *h1 = (int *)   malloc(sizeof(int));
    int    *h2 = (int *)   malloc(sizeof(int));
    double *h3 = (double *)malloc(sizeof(double));
    char   *h4 = (char *)  malloc(32);
    int    *h5 = (int *)   malloc(sizeof(int) * 4);
    if (!h1 || !h2 || !h3 || !h4 || !h5) {
        fprintf(stderr, "malloc that bai\n");
        return 1;
    }
    *h1 = 10; *h2 = 20; *h3 = 30.0;
    strcpy(h4, "heap-buf");
    h5[0] = 1;
    print_addr("h1 (malloc int)",     h1);
    print_addr("h2 (malloc int)",     h2);
    print_addr("h3 (malloc double)",  h3);
    print_addr("h4 (malloc char[32])",h4);
    print_addr("h5 (malloc int[4])",  h5);

    /* ---------------- SO SANH KHOANG CACH GIUA CAC VUNG ---------------- */
    printf("\n--- KHOANG CACH GIUA CAC VUNG BO NHO ---\n");
    uintptr_t addr_global = (uintptr_t)&g_global_init1;
    uintptr_t addr_static = static_addrs[0];
    uintptr_t addr_local  = (uintptr_t)&l1;
    uintptr_t addr_heap   = (uintptr_t)h1;

    print_gap("global",       "file-static",  addr_global, (uintptr_t)&g_file_static1);
    print_gap("global",       "func-static",  addr_global, addr_static);
    print_gap("func-static",  "local(stack)", addr_static, addr_local);
    print_gap("local(stack)", "heap",         addr_local,  addr_heap);
    print_gap("global",       "heap",         addr_global, addr_heap);

    /* ---------------- THU TU CAP PHAT TRONG CUNG VUNG ---------------- */
    printf("\n--- THU TU CAP PHAT LIEN TIEP TRONG CUNG VUNG ---\n");
    print_gap("h1", "h2", (uintptr_t)h1, (uintptr_t)h2);
    print_gap("h2", "h3", (uintptr_t)h2, (uintptr_t)h3);
    print_gap("h3", "h4", (uintptr_t)h3, (uintptr_t)h4);
    print_gap("h4", "h5", (uintptr_t)h4, (uintptr_t)h5);
    print_gap("l1(stack)", "l2(stack)", (uintptr_t)&l1, (uintptr_t)&l2);
    print_gap("l2(stack)", "l3(stack)", (uintptr_t)&l2, (uintptr_t)&l3);
    print_gap("g_init1", "g_init2", (uintptr_t)&g_global_init1, (uintptr_t)&g_global_init2);

    printf("\nGhi chu:\n");
    printf("  - Stack thuong cap phat theo chieu dia chi GIAM dan giua cac lan goi ham,\n");
    printf("    nhung cac bien local trong CUNG mot ham thi thu tu phu thuoc trinh bien dich.\n");
    printf("  - Heap (malloc) thuong cap phat TANG dan trong cung 1 tien trinh (tuy allocator).\n");
    printf("  - .data/.bss (global) va static-local co the nam gan nhau hoac cach xa nhau\n");
    printf("    tuy trinh bien dich va che do toi uu.\n");
    printf("  - ASLR (Windows/Linux) lam dia chi thay doi giua cac lan chay,\n");
    printf("    nhung KHOANG CACH TUONG DOI giua cac vung thuong on dinh.\n");

    free(h1); free(h2); free(h3); free(h4); free(h5);
    return 0;
}
