#ifndef ENGINEAPI_H
#define ENGINEAPI_H
/*
 * engineapi.h - Hop dong API giua engine.dll va service.exe
 * ===================================================================
 * O bai 5.1, service tu khai bao typedef con tro ham trong service.c.
 * Cach do de lech: sua chu ky ham trong engine.c ma quen sua service.c
 * -> compiler khong bao loi, chuong trinh crash luc chay.
 *
 * O 5.2 ta dat chung mot header: ca engine va service deu include,
 * lech la compiler bao ngay.
 */

#include <windows.h>

/* ===== Version engine 5.2 ===== */
#define ENGINE_VERSION_MAJOR  2
#define ENGINE_VERSION_MINOR  0

/* ===== Ma nguon ket qua ===== */
#define SCAN_SRC_ENGINE  0
#define SCAN_SRC_CACHE   1

/* ==================================================================
 * KET QUA QUET CHI TIET
 * ------------------------------------------------------------------
 * 5.1 chi tra ve mot so int (verdict). 5.2 can nhieu hon: diem so
 * dang so thuc (vi nhom D co +0.5), trang thai parse PE, va danh
 * sach rule da kich hoat de nguoi dung hieu VI SAO bi cham diem.
 * ================================================================== */
#pragma pack(push, 8)
typedef struct {
    double    score;          /* tong diem (so thuc vi co +0.5) */
    int       verdict;        /* VERDICT_SAFE / SUSPICIOUS / MALICIOUS */
    int       peStatus;       /* PE_OK / PE_MALFORMED_PE / PE_STRUCT_CORRUPT */
    int       isPe;           /* 1 = la file PE hop le */

    /* 11 thong so de bai yeu cau */
    int       machine;
    int       subsystem;
    int       isDll;
    int       isDriver;
    int       isManaged;
    int       isSigned;
    int       signState;      /* SIGN_UNSIGNED / VALID / INVALID */
    int       hasDebug;
    int       hasRichHeader;
    DWORD     entryPointRva;
    ULONGLONG imageBase;
    int       sectionCount;

    /* tom tat de hien thi */
    char      peStatusText[32];
    char      detail[1400];   /* liet ke rule da kich hoat, phan cach bang ';' */
} EngineResult;
#pragma pack(pop)

/* ===== Kieu con tro callback bao tien do ===== */
typedef void (*ProgressCallback)(int stage, int percent, void *userData);

/* ===== Chu ky 6 ham export cua engine.dll =====
 * 5.1 co 4 ham. 5.2 them 2:
 *   EngineScanFileEx    -> tra ket qua chi tiet
 *   EngineGetFingerprint-> dau van tay engine, dung de vo hieu cache
 *                          khi nang cap engine (yeu cau phan 2) */
typedef int  (*FnEngineInitialize)(const char *configJson);
typedef int  (*FnEngineScanFile)(const char *path, int options, ProgressCallback cb, void *userData);
typedef int  (*FnEngineScanFileEx)(const char *path, int options, ProgressCallback cb, void *userData, EngineResult *out);
typedef int  (*FnEngineGetVersion)(void);
typedef DWORD(*FnEngineGetFingerprint)(void);
typedef void (*FnEngineShutdown)(void);

#endif /* ENGINEAPI_H */
