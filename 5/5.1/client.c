#define _CRT_SECURE_NO_WARNINGS
/*
 * engine.c - Scan Engine DLL (bai 5.1)
 * ===================================================================
 * Export 4 ham theo kieu versioned API:
 *   EngineInitialize(configJson)
 *   EngineScanFile(path, options, callback)
 *   EngineGetVersion()
 *   EngineShutdown()
 *
 * Logic tinh severity (demo):
 *   - File nam ngoai C:\           -> severity nen = HIGH (2 diem)
 *   - Duoi .exe .dll .sys .js ...  -> +1
 *   - Size > 50MB                  -> +1
 *   - Entropy (gia lap) > nguong   -> +1
 *   Tong diem -> SAFE / SUSPICIOUS / MALICIOUS
 *
 * Build: tao DLL project, dinh nghia ENGINE_EXPORTS.
 *   cl /LD engine.c   (tao engine.dll)
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

 /* Macro export.
  * LUU Y: truoc day dung #ifdef ENGINE_EXPORTS, phu thuoc vao cai dat
  * Preprocessor trong Visual Studio - de quen/de sai. Vi file nay CHI
  * duoc dung de build DLL, ta luon dat dllexport cho chac chan.
  *
  * extern "C" de phong truong hop file bi bien dich nhu C++ (khi do ten
  * ham se bi "mangling" -> GetProcAddress tim khong ra). */
#ifdef __cplusplus
#define ENGINE_API extern "C" __declspec(dllexport)
#else
#define ENGINE_API __declspec(dllexport)
#endif

  /* ===== Phien ban engine ===== */
#define ENGINE_VERSION_MAJOR 1
#define ENGINE_VERSION_MINOR 0

/* ===== Cac stage bao cao qua callback ===== */
#define STAGE_OPEN     1
#define STAGE_READ     2
#define STAGE_ANALYZE  3
#define STAGE_REPORT   4

/* ===== Ket qua verdict ===== */
#define VERDICT_SAFE       0
#define VERDICT_SUSPICIOUS 1
#define VERDICT_MALICIOUS  2

/* Kieu con tro ham callback: engine goi ham nay de bao tien do */
typedef void (*ProgressCallback)(int stage, int percent, void* userData);

/* Bien trang thai engine (da khoi tao chua) */
static BOOL g_initialized = FALSE;

/* ==================================================================
 * EngineGetVersion - tra ve phien ban dang so (major*100 + minor)
 * ================================================================== */
ENGINE_API int EngineGetVersion(void)
{
    return ENGINE_VERSION_MAJOR * 100 + ENGINE_VERSION_MINOR;
}

/* ==================================================================
 * EngineInitialize - khoi tao engine voi cau hinh JSON
 * (demo: chi danh dau da khoi tao, khong parse JSON that)
 * ================================================================== */
ENGINE_API int EngineInitialize(const char* configJson)
{
    (void)configJson;   /* demo: bo qua noi dung config */
    g_initialized = TRUE;
    return 0;   /* 0 = thanh cong */
}

/* ==================================================================
 * EngineShutdown - don dep engine
 * ================================================================== */
ENGINE_API void EngineShutdown(void)
{
    g_initialized = FALSE;
}

/* ------------------------------------------------------------------
 * Ham phu: kiem tra duoi file co thuoc danh sach "nguy hiem" khong
 * ------------------------------------------------------------------ */
static BOOL IsDangerousExtension(const char* path)
{
    const char* dangerous[] = { ".exe", ".dll", ".sys", ".js", ".vbs", ".ps1", NULL };
    const char* dot = strrchr(path, '.');   /* tim dau '.' cuoi cung */
    int i;

    if (!dot) return FALSE;

    for (i = 0; dangerous[i]; i++) {
        if (_stricmp(dot, dangerous[i]) == 0) return TRUE;  /* so sanh khong phan biet hoa thuong */
    }
    return FALSE;
}

/* ------------------------------------------------------------------
 * Ham phu: gia lap tinh entropy cua file (do "hon loan" cua du lieu).
 * Entropy cao thuong gap o file da nen/ma hoa (co the la malware).
 * Demo: doc 1KB dau, dem so byte khac nhau, chuan hoa ve 0..8.
 * ------------------------------------------------------------------ */
static double CalcEntropySim(const char* path)
{
    HANDLE hFile;
    BYTE buf[1024];
    DWORD read = 0;
    int freq[256] = { 0 };
    int distinct = 0;
    int i;

    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0.0;

    ReadFile(hFile, buf, sizeof(buf), &read, NULL);
    CloseHandle(hFile);

    for (i = 0; i < (int)read; i++) freq[buf[i]]++;
    for (i = 0; i < 256; i++) if (freq[i] > 0) distinct++;

    /* distinct 0..256 -> chuan hoa ve 0..8 (gia lap entropy Shannon) */
    return (double)distinct / 256.0 * 8.0;
}

/* ==================================================================
 * EngineScanFile - quet 1 file, bao tien do qua callback,
 *                  tra ve verdict (SAFE/SUSPICIOUS/MALICIOUS)
 * ================================================================== */
ENGINE_API int EngineScanFile(const char* path, int options, ProgressCallback cb, void* userData)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULONGLONG size = 0;
    int severity = 0;
    double entropy;

    (void)options;

    if (!g_initialized) return -1;   /* chua khoi tao */

    /* --- STAGE OPEN --- */
    if (cb) cb(STAGE_OPEN, 10, userData);

    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad))
        return -2;   /* khong mo duoc file */

    size = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;

    /* --- STAGE READ --- */
    if (cb) cb(STAGE_READ, 40, userData);

    /* --- STAGE ANALYZE --- */
    if (cb) cb(STAGE_ANALYZE, 70, userData);

    /* Rule 1: file ngoai C:\ -> nen HIGH (2 diem) */
    if (!(path[0] == 'C' || path[0] == 'c') || path[1] != ':') {
        severity += 2;
    }
    else {
        /* Trong C:\ van tinh nhung diem thap hon */
        severity += 0;
    }

    /* Rule 2: duoi nguy hiem -> +1 */
    if (IsDangerousExtension(path)) severity += 1;

    /* Rule 3: size > 50MB -> +1 */
    if (size > (ULONGLONG)50 * 1024 * 1024) severity += 1;

    /* Rule 4: entropy gia lap > 6.5 -> +1 */
    entropy = CalcEntropySim(path);
    if (entropy > 6.5) severity += 1;

    /* --- STAGE REPORT --- */
    if (cb) cb(STAGE_REPORT, 100, userData);

    /* Map tong diem -> verdict */
    if (severity >= 3)      return VERDICT_MALICIOUS;
    else if (severity >= 1) return VERDICT_SUSPICIOUS;
    else                    return VERDICT_SAFE;
}

/* ==================================================================
 * DllMain - diem vao DLL (khong lam gi dac biet o demo nay)
 * ================================================================== */
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    (void)hInst; (void)reserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}