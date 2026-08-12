#ifndef PEREADER_H
#define PEREADER_H
/*
 * pereader.h - Module doc file PE (Portable Executable) thuan tay
 * ===================================================================
 * KHONG dung API phan tich PE cua Windows (ImageNtHeader, LoadLibraryEx...).
 *
 * Vi sao phai tu parse:
 *   1. Cac API do TU CHOI file PE hong - ma file hong chinh la thu
 *      ta can phat hien (MALFORMED_PE / STRUCT_CORRUPT).
 *   2. LoadLibraryEx co the THUC THI code trong file - cuc ky nguy
 *      hiem khi dang quet malware.
 *   3. Chung che giau chi tiet ma rule can doc.
 *
 * Ta chi dung dinh nghia STRUCT trong <winnt.h> (IMAGE_DOS_HEADER...).
 * Do la khai bao kieu du lieu, khong phai loi goi API - hoan toan hop le.
 *
 * KHAI NIEM COT LOI: RVA vs FILE OFFSET
 * -------------------------------------
 * File PE ton tai o HAI BO CUC khac nhau:
 *
 *   TREN DIA                       TRONG RAM
 *   can chinh FileAlignment (512)  can chinh SectionAlignment (4096)
 *   dia chi goi la "file offset"   dia chi goi la "RVA"
 *
 * MOI con tro trong PE deu la RVA. Muon doc tu file phai quy doi
 * bang RvaToFileOffset(). Sai ham nay la sai toan bo phan phan tich.
 */

#include <windows.h>

/* ===== Ma trang thai (dung ten theo de bai) ===== */
#define PE_OK              0
#define PE_ERR_IO          1   /* khong mo/doc duoc file */
#define PE_MALFORMED_PE    2   /* khong phai PE, thieu MZ / PE\0\0, file qua ngan */
#define PE_STRUCT_CORRUPT  3   /* dung la PE nhung so lieu vo ly */

/* ===== Gioi han ===== */
#define PE_MAX_SECTIONS     96
#define PE_MAX_RISKY        48
#define PE_MAX_READ         (64UL * 1024 * 1024)   /* doc toi da 64MB */

/* ===== Nhom API rui ro (nhom C) ===== */
#define RISK_PROCESS   0
#define RISK_PERSIST   1
#define RISK_NETWORK   2
#define RISK_CRYPTO    3
#define RISK_GROUPS    4

/* ===== Trang thai chu ky (nhom E) ===== */
#define SIGN_UNSIGNED       0
#define SIGN_VALID          1
#define SIGN_INVALID        2
#define SIGN_UNKNOWN        3

/* ==================================================================
 * THONG TIN 1 SECTION
 * ================================================================== */
typedef struct {
    char      name[9];              /* Name[8] + '\0' */
    DWORD     virtualAddress;       /* RVA cua section trong RAM */
    DWORD     virtualSize;          /* kich thuoc trong RAM */
    DWORD     sizeOfRawData;        /* kich thuoc tren dia */
    DWORD     pointerToRawData;     /* file offset tren dia */
    DWORD     characteristics;      /* co R/W/X */
    double    entropy;              /* entropy Shannon that (0..8) */
    BOOL      isExec, isWrite, isRead;
    BOOL      nameWeird;            /* ten rong / ky tu la */
} PeSection;

/* ==================================================================
 * KET QUA PHAN TICH 1 FILE PE
 * ================================================================== */
typedef struct {
    /* --- trang thai --- */
    int       status;               /* PE_OK / PE_MALFORMED_PE / ... */
    char      errMsg[160];

    /* --- 11 thong so de bai yeu cau --- */
    WORD      machine;              /* IMAGE_FILE_MACHINE_I386 / AMD64 ... */
    WORD      subsystem;            /* GUI / CUI / NATIVE ... */
    BOOL      isDll;
    BOOL      isDriver;
    BOOL      isManaged;            /* .NET - co COM Descriptor directory */
    BOOL      isSigned;             /* co Security Directory */
    BOOL      hasDebug;
    BOOL      hasRichHeader;
    DWORD     entryPointRva;
    ULONGLONG imageBase;
    WORD      sectionCount;

    /* --- phu tro cho rule --- */
    BOOL      isPE32Plus;           /* TRUE = PE32+ (64-bit) */
    DWORD     timeDateStamp;
    DWORD     sectionAlignment;
    DWORD     fileAlignment;
    DWORD     numberOfRvaAndSizes;
    DWORD     sizeOfImage;
    DWORD     sizeOfHeaders;
    WORD      characteristics;
    WORD      dllCharacteristics;
    ULONGLONG fileSize;

    PeSection sections[PE_MAX_SECTIONS];

    /* --- DataDirectory (16 muc) --- */
    DWORD     dirRva[16];
    DWORD     dirSize[16];
    BOOL      dirOutOfFile;         /* co directory tro ra ngoai file */

    /* --- nhom C: import / export / TLS --- */
    BOOL      hasTls;
    DWORD     tlsCallbackCount;
    BOOL      hasDelayImport;
    BOOL      hasExport;
    DWORD     exportCount;
    BOOL      exportNameWeird;
    int       importDllCount;
    int       importApiCount;
    int       riskHit[RISK_GROUPS];             /* so API rui ro moi nhom */
    char      riskyApis[PE_MAX_RISKY][48];      /* ten cac API da bat gap */
    int       riskyApiCount;

    /* --- nhom D: resource --- */
    BOOL      hasVersionInfo;
    BOOL      hasIcon;
    BOOL      hasManifest;
    DWORD     biggestRcData;        /* RCDATA lon nhat (byte) */
    double    rcDataEntropy;

    /* --- nhom B: overlay --- */
    ULONGLONG overlayOffset;
    ULONGLONG overlaySize;

    /* --- nhom E: chu ky --- */
    int       signState;            /* SIGN_xxx */
    DWORD     securityDirOffset;    /* LUU Y: la FILE OFFSET, khong phai RVA */
    DWORD     securityDirSize;

    /* --- tong quat --- */
    double    fileEntropy;          /* entropy 1MB dau file */
} PeInfo;

/* ==================================================================
 * HAM CHINH: doc va phan tich toan bo file PE
 * Tra ve PE_OK / PE_MALFORMED_PE / PE_STRUCT_CORRUPT / PE_ERR_IO
 * ================================================================== */
int PeRead(const char *path, PeInfo *info);

/* ==================================================================
 * QUY DOI RVA -> FILE OFFSET (ham cot loi)
 * Tra ve 0 neu RVA khong nam trong section nao (out of range).
 * ================================================================== */
DWORD RvaToFileOffset(const PeInfo *info, DWORD rva);

/* ===== Tien ich ===== */
double      PeEntropy(const BYTE *buf, DWORD len);
const char *PeStatusName(int status);
const char *PeMachineName(WORD machine);
const char *PeSubsystemName(WORD subsystem);
const char *PeSignStateName(int st);
const char *PeRiskGroupName(int g);

#endif /* PEREADER_H */
