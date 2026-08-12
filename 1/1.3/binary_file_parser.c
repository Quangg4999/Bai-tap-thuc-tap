#define _CRT_SECURE_NO_WARNINGS  /* Windows/MSVC: cho phep dung fopen khong bao loi C4996 */
/*
 * Bai 1.3 - Binary File Parser
 * -------------------------------------------------------------------
 * Thiet ke struct FILE_HDR lam "header" dung truoc mot khoi du lieu.
 * Ghi header + du lieu that xuong file nhi phan (fwrite).
 * Doc lai, validate magic va dataSize truoc khi tin tuong xu ly tiep.
 * Kem demo truong hop file bi hong / gia mao (sai magic).
 *
 * Build tren Windows (x64):
 *   - MinGW-w64 :  gcc -O0 -std=c11 binary_file_parser.c -o binary_file_parser.exe
 *   - MSVC      :  cl /Od /std:c11 binary_file_parser.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC_VALUE   "FHDR"   /* "chu ky" nhan dien file, dung 4 ky tu */
#define FORMAT_VERSION  1

#pragma pack(push, 1)   /* tat padding, dam bao struct dung 12 byte tren moi compiler */
struct FILE_HDR {
    char magic[4];      /* "chu ky" nhan dien - phai la MAGIC_VALUE */
    int  version;        /* phien ban dinh dang file */
    int  dataSize;        /* kich thuoc (byte) cua phan du lieu di kem SAU header */
};
#pragma pack(pop)

/* ---------------- GHI file: header + du lieu that ---------------- */
int WriteBinaryFile(const char *filename, const int *payload, int payloadCount)
{
    FILE *f = fopen(filename, "wb");   /* "wb" = write binary */
    if (!f) {
        fprintf(stderr, "Loi: khong mo duoc file '%s' de ghi\n", filename);
        return 0;
    }

    struct FILE_HDR hdr;
    memcpy(hdr.magic, MAGIC_VALUE, 4);
    hdr.version  = FORMAT_VERSION;
    hdr.dataSize = (int)(payloadCount * sizeof(int));

    /* Ghi header truoc (12 byte), sau do ghi du lieu that */
    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(payload, sizeof(int), payloadCount, f);

    fclose(f);
    printf("[GHI] Da ghi file '%s': header=%zu byte, data=%d byte (%d so int)\n",
           filename, sizeof(hdr), hdr.dataSize, payloadCount);
    return 1;
}

/* ---------------- DOC file: validate magic truoc khi xu ly tiep ---------------- */
int ReadBinaryFile(const char *filename)
{
    FILE *f = fopen(filename, "rb");   /* "rb" = read binary */
    if (!f) {
        fprintf(stderr, "Loi: khong mo duoc file '%s' de doc\n", filename);
        return 0;
    }

    struct FILE_HDR hdr;
    size_t n = fread(&hdr, sizeof(hdr), 1, f);
    if (n != 1) {
        fprintf(stderr, "[DOC] Loi: file '%s' qua nho, khong du header\n", filename);
        fclose(f);
        return 0;
    }

    printf("\n[DOC] File '%s':\n", filename);
    printf("  magic   = \"%.4s\"  (hex: %02X %02X %02X %02X)\n",
           hdr.magic, (unsigned char)hdr.magic[0], (unsigned char)hdr.magic[1],
           (unsigned char)hdr.magic[2], (unsigned char)hdr.magic[3]);
    printf("  version = %d\n", hdr.version);
    printf("  dataSize= %d byte\n", hdr.dataSize);

    /* ===== BUOC VALIDATE QUAN TRONG NHAT: kiem tra magic ===== */
    if (memcmp(hdr.magic, MAGIC_VALUE, 4) != 0) {
        printf("  ==> LOI: magic KHONG khop (mong doi \"%s\")!\n", MAGIC_VALUE);
        printf("  ==> Day co the la file hong, sai dinh dang, hoac bi gia mao.\n");
        printf("  ==> TU CHOI xu ly tiep phan du lieu con lai.\n");
        fclose(f);
        return 0;
    }
    printf("  ==> Magic HOP LE, tiep tuc doc du lieu...\n");

    /* Kiem tra them: dataSize hop ly khong (khong am, khong qua lon bat thuong) */
    if (hdr.dataSize < 0 || hdr.dataSize > 100 * 1024 * 1024) {
        printf("  ==> LOI: dataSize bat thuong (%d), tu choi cap phat bo nho.\n", hdr.dataSize);
        fclose(f);
        return 0;
    }

    /* Da qua validate - an toan de doc phan du lieu that */
    int count = hdr.dataSize / (int)sizeof(int);
    int *payload = (int *)malloc(hdr.dataSize);
    if (!payload) {
        fprintf(stderr, "  Loi: khong du bo nho de doc %d byte\n", hdr.dataSize);
        fclose(f);
        return 0;
    }

    size_t readCount = fread(payload, sizeof(int), count, f);
    if ((int)readCount != count) {
        printf("  ==> CANH BAO: file bi cat cut, chi doc duoc %zu/%d so nguyen\n",
               readCount, count);
    } else {
        printf("  Du lieu (%d so nguyen): ", count);
        for (int i = 0; i < count; i++) printf("%d ", payload[i]);
        printf("\n");
    }

    free(payload);
    fclose(f);
    return 1;
}

/* ---------------- Tao file GIA/HONG de demo validate that bai ---------------- */
void CreateCorruptFile(const char *filename)
{
    FILE *f = fopen(filename, "wb");
    if (!f) return;

    struct FILE_HDR hdr;
    memcpy(hdr.magic, "XXXX", 4);   /* magic SAI - co tinh gia mao/hong */
    hdr.version  = FORMAT_VERSION;
    hdr.dataSize = 16;

    int fake_data[4] = { -1, -1, -1, -1 };

    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(fake_data, sizeof(int), 4, f);
    fclose(f);

    printf("[GHI] Da tao file GIA '%s' voi magic sai (\"XXXX\" thay vi \"%s\")\n",
           filename, MAGIC_VALUE);
}

int main(void)
{
    printf("========== DEMO: BINARY FILE PARSER ==========\n");
    printf("sizeof(struct FILE_HDR) = %zu byte  (magic=4 + version=4 + dataSize=4)\n\n",
           sizeof(struct FILE_HDR));

    /* ---- Kich ban 1: file HOP LE ---- */
    int du_lieu[5] = { 10, 20, 30, 40, 50 };
    WriteBinaryFile("data.bin", du_lieu, 5);
    ReadBinaryFile("data.bin");

    printf("\n----------------------------------------------------\n");

    /* ---- Kich ban 2: file GIA/HONG (magic sai) ---- */
    CreateCorruptFile("data_corrupt.bin");
    ReadBinaryFile("data_corrupt.bin");

    printf("\n==========  Nhan phim bat ky de dong  ==========\n");
    return 0;
}
