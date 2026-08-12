#define _CRT_SECURE_NO_WARNINGS  /* Windows/MSVC: cho phep dung strcpy/strncpy khong bao loi C4996 */
/*
 * Bai 1.2 - Unsafe vs Safe Copy (Buffer Overflow Demo)
 * -------------------------------------------------------------------
 * Minh hoa truc quan buffer overflow: 2 bien nam CANH NHAU tren stack
 * (buffer va canary). UnsafeCopy() khong kiem tra kich thuoc dich,
 * neu chuoi nguon dai hon buffer se GHI DE len canary ben canh.
 * SafeCopy() luon gioi han so byte copy theo dung dung luong buffer.
 *
 * Build tren Windows (x64):
 *   - MinGW-w64 :  gcc -O0 -std=c11 unsafe_safe_copy.c -o unsafe_safe_copy.exe
 *   - MSVC      :  cl /Od /std:c11 unsafe_safe_copy.c
 *
 * Huong dan debug xem memory bi overwrite: xem huong dan kem theo.
 */

#include <stdio.h>
#include <string.h>

/* ---------------- UNSAFE: khong kiem tra kich thuoc dich ---------------- */
void UnsafeCopy(char *dst, const char *src)
{
    strcpy(dst, src);   /* NGUY HIEM: copy toan bo src, khong quan tam dst chua duoc bao nhieu */
}

/* ---------------- SAFE: luon gioi han theo dung dung luong dich --------- */
void SafeCopy(char *dst, size_t dstSize, const char *src)
{
    if (dst == NULL || dstSize == 0) return;

    size_t i = 0;
    /* Chi copy toi da (dstSize - 1) ky tu, chua lai 1 cho cho '\0' */
    for (i = 0; i < dstSize - 1 && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';   /* Luon dam bao chuoi ket thuc dung cach */
}

/* Ham tien ich: in noi dung 1 vung nho duoi dang hex, de nhin thay
 * ro byte nao bi ghi de (kha nang cao la ky tu 'A' = 0x41) */
void dump_hex(const char *label, const void *addr, size_t len)
{
    const unsigned char *p = (const unsigned char *)addr;
    printf("%s (%zu byte tai %p):\n  ", label, len, addr);
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", p[i]);
        if ((i + 1) % 16 == 0) printf("\n  ");
    }
    printf("\n");
}

int main(void)
{
    printf("========== DEMO: UNSAFE COPY vs SAFE COPY ==========\n\n");

    /* ---------------- Kich ban 1: UnsafeCopy gay tran bo nho ---------------- */
    {
        printf("--- Kich ban 1: UnsafeCopy (buffer overflow) ---\n");

        char   buffer[8];              /* "ly nho", chi chua duoc 8 byte */
        int    canary = 0x1234ABCD;    /* "linh canh" nam NGAY SAU buffer tren stack */

        printf("TRUOC khi copy:\n");
        printf("  buffer = \"%s\"\n", buffer);   /* chua khoi tao, co the la rac */
        printf("  canary = 0x%08X   (dia chi buffer=%p, canary=%p, chenh lech=%td byte)\n\n",
               canary, (void *)buffer, (void *)&canary,
               (char *)&canary - buffer);

        /* Chuoi nguon dai HON NHIEU so voi buffer[8] -> se tran ra ngoai */
        const char *chuoi_dai = "AAAAAAAAAAAAAAAAAAAA";  /* 20 ky tu + '\0' = 21 byte */

        UnsafeCopy(buffer, chuoi_dai);

        printf("SAU khi UnsafeCopy(buffer, \"%s\"):\n", chuoi_dai);
        printf("  buffer = \"%s\"\n", buffer);
        printf("  canary = 0x%08X   <-- neu KHAC 0x1234ABCD nghia la da bi GHI DE!\n\n",
               canary);

        dump_hex("Vung nho buffer + canary SAU khi UnsafeCopy",
                  buffer, sizeof(buffer) + sizeof(canary));

        if (canary != 0x1234ABCD) {
            printf("  ==> XAC NHAN: buffer overflow da GHI DE len bien canary ben canh!\n");
        } else {
            printf("  ==> Canary may man khong bi doi (tuy trinh bien dich sap xep bo nho),\n");
            printf("      nhung du lieu van tran ra ngoai buffer[8] mot cach nguy hiem.\n");
        }
    }

    printf("\n----------------------------------------------------\n\n");

    /* ---------------- Kich ban 2: SafeCopy khong gay tran bo nho ---------------- */
    {
        printf("--- Kich ban 2: SafeCopy (an toan) ---\n");

        char buffer2[8];
        int  canary2 = 0x1234ABCD;

        printf("TRUOC khi copy:\n");
        printf("  canary2 = 0x%08X\n\n", canary2);

        const char *chuoi_dai = "AAAAAAAAAAAAAAAAAAAA";

        SafeCopy(buffer2, sizeof(buffer2), chuoi_dai);

        printf("SAU khi SafeCopy(buffer2, sizeof(buffer2)=%zu, \"%s\"):\n",
               sizeof(buffer2), chuoi_dai);
        printf("  buffer2 = \"%s\"   (bi CAT BOT con 7 ky tu + '\\0', khong tran)\n", buffer2);
        printf("  canary2 = 0x%08X   <-- van giu nguyen, KHONG bi ghi de\n\n", canary2);
          
        dump_hex("Vung nho buffer2 + canary2 SAU khi SafeCopy",
                  buffer2, sizeof(buffer2) + sizeof(canary2));

        if (canary2 == 0x1234ABCD) {
            printf("  ==> XAC NHAN: SafeCopy khong lam anh huong den bien ben canh.\n");
        }
    }

    printf("\n==========  Nhan phim bat ky de dong  ==========\n");
    return 0;
}
