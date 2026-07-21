#define _CRT_SECURE_NO_WARNINGS  /* Windows/MSVC: cho phep dung strcpy khong bao loi C4996 */
/*
 * Bai 1.1 - Memory Layout Explorer (C++, new/delete, KHONG dung STL)
 * -------------------------------------------------------------------
 * Tuong tu ban C, nhung dung toan tu new/delete cua C++ thay vi malloc/free.
 * Khong dung bat ky container/STL nao (vector, string, iostream...),
 * chi dung <cstdio>, <cstdlib>, <cstdint>, <cinttypes>, <cstring>.
 *
 * Build tren Windows (x64):
 *   - MinGW-w64 :  g++ -O0 -std=c++17 memory_layout.cpp -o memory_layout.exe
 *   - MSVC      :  cl /Od /std:c++17 memory_layout.cpp
 *
 * Chay:
 *   memory_layout.exe
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cinttypes>
#include <cstring>

/* ---------------- Vung GLOBAL (.data / .bss) ---------------- */
int    g_global_init1 = 111;
int    g_global_init2 = 222;
double g_global_init3 = 3.14159;
int    g_global_bss1;
int    g_global_bss2;

static int g_file_static1 = 999;   /* static o pham vi file (internal linkage) */
static int g_file_static2 = 888;

/* ---------------- Ham tien ich ---------------- */
static void print_addr(const char *label, const void *addr)
{
    std::printf("  %-22s = %p\n", label, addr);
}

static void print_gap(const char *from, const char *to, uintptr_t a, uintptr_t b)
{
    intptr_t diff = static_cast<intptr_t>(b - a);
    uintptr_t mag = static_cast<uintptr_t>(diff < 0 ? -diff : diff);
    std::printf("  %-16s -> %-16s : %+" PRIdPTR " byte   (0x%" PRIxPTR ")\n",
                from, to, diff, mag);
}

static void get_static_local_addrs(uintptr_t out[4])
{
    static int    s1 = 1;
    static int    s2 = 2;
    static double s3 = 3.0;
    static char   s4[8] = "abc";

    std::printf("\n--- STATIC LOCAL (bien 'static' khai bao trong ham) ---\n");
    print_addr("s1 (static int)",     &s1);
    print_addr("s2 (static int)",     &s2);
    print_addr("s3 (static double)",  &s3);
    print_addr("s4 (static char[8])", &s4);

    out[0] = reinterpret_cast<uintptr_t>(&s1);
    out[1] = reinterpret_cast<uintptr_t>(&s2);
    out[2] = reinterpret_cast<uintptr_t>(&s3);
    out[3] = reinterpret_cast<uintptr_t>(&s4);
}

int main()
{
    std::printf("========== MEMORY LAYOUT EXPLORER (C++ / new, x64) ==========\n");
    std::printf("sizeof(void*) = %zu byte\n", sizeof(void *));

    /* ---------------- GLOBAL ---------------- */
    std::printf("\n--- GLOBAL / FILE-STATIC (.data, .bss) ---\n");
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
    std::printf("\n--- LOCAL / STACK (khai bao trong main) ---\n");
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

    /* ---------------- HEAP (new) ---------------- */
    std::printf("\n--- HEAP (new) ---\n");
    int    *h1 = new int(10);
    int    *h2 = new int(20);
    double *h3 = new double(30.0);
    char   *h4 = new char[32];
    int    *h5 = new int[4]{1, 2, 3, 4};
    std::strcpy(h4, "heap-buf");
    print_addr("h1 (new int)",      h1);
    print_addr("h2 (new int)",      h2);
    print_addr("h3 (new double)",   h3);
    print_addr("h4 (new char[32])", h4);
    print_addr("h5 (new int[4])",   h5);

    /* ---------------- SO SANH KHOANG CACH GIUA CAC VUNG ---------------- */
    std::printf("\n--- KHOANG CACH GIUA CAC VUNG BO NHO ---\n");
    uintptr_t addr_global = reinterpret_cast<uintptr_t>(&g_global_init1);
    uintptr_t addr_static = static_addrs[0];
    uintptr_t addr_local  = reinterpret_cast<uintptr_t>(&l1);
    uintptr_t addr_heap   = reinterpret_cast<uintptr_t>(h1);

    print_gap("global",       "file-static",  addr_global, reinterpret_cast<uintptr_t>(&g_file_static1));
    print_gap("global",       "func-static",  addr_global, addr_static);
    print_gap("func-static",  "local(stack)", addr_static, addr_local);
    print_gap("local(stack)", "heap",         addr_local,  addr_heap);
    print_gap("global",       "heap",         addr_global, addr_heap);

    /* ---------------- THU TU CAP PHAT TRONG CUNG VUNG ---------------- */
    std::printf("\n--- THU TU CAP PHAT LIEN TIEP TRONG CUNG VUNG ---\n");
    print_gap("h1", "h2", reinterpret_cast<uintptr_t>(h1), reinterpret_cast<uintptr_t>(h2));
    print_gap("h2", "h3", reinterpret_cast<uintptr_t>(h2), reinterpret_cast<uintptr_t>(h3));
    print_gap("h3", "h4", reinterpret_cast<uintptr_t>(h3), reinterpret_cast<uintptr_t>(h4));
    print_gap("h4", "h5", reinterpret_cast<uintptr_t>(h4), reinterpret_cast<uintptr_t>(h5));
    print_gap("l1(stack)", "l2(stack)", reinterpret_cast<uintptr_t>(&l1), reinterpret_cast<uintptr_t>(&l2));
    print_gap("l2(stack)", "l3(stack)", reinterpret_cast<uintptr_t>(&l2), reinterpret_cast<uintptr_t>(&l3));
    print_gap("g_init1", "g_init2", reinterpret_cast<uintptr_t>(&g_global_init1), reinterpret_cast<uintptr_t>(&g_global_init2));

    std::printf("\nGhi chu:\n");
    std::printf("  - Stack thuong cap phat theo chieu dia chi GIAM dan giua cac lan goi ham.\n");
    std::printf("  - Heap (new) thuong cap phat TANG dan trong cung 1 tien trinh (tuy allocator).\n");
    std::printf("  - .data/.bss (global) va static-local co the gan hoac xa nhau tuy compiler.\n");
    std::printf("  - ASLR lam dia chi tuyet doi thay doi giua cac lan chay, nhung khoang cach\n");
    std::printf("    TUONG DOI giua cac vung thuong on dinh.\n");

    delete h1;
    delete h2;
    delete h3;
    delete[] h4;
    delete[] h5;
    return 0;
}
