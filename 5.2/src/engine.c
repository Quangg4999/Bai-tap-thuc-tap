#define _CRT_SECURE_NO_WARNINGS
/*
 * engine.c - Scan Engine DLL 5.2
 * ===================================================================
 * Nang cap tu 5.1:
 *   5.1: 4 rule tho (ngoai o C, duoi file, size, entropy gia lap)
 *   5.2: parse PE that + ~30 rule chia 5 nhom A-E + verify chu ky
 *
 * BUILD - LUU Y BAT BUOC:
 *   Project engine phai them "wintrust.lib" vao
 *   Linker -> Input -> Additional Dependencies.
 *   Quen la loi: unresolved external symbol WinVerifyTrust.
 */

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>

/* Tu dong link wintrust.lib - khong can vao Properties -> Linker -> Input.
 * Thieu dong nay se loi: unresolved external symbol WinVerifyTrust */
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include "pereader.h"
#include "engineapi.h"
#include "protocol.h"

/* Macro export.
 * KHONG dung #ifdef ENGINE_EXPORTS nhu 5.1 - cach do phu thuoc vao
 * viec nho dat Preprocessor Definitions trong Visual Studio, quen mot
 * lan la DLL build ra co BANG EXPORT RONG ma khong bao loi gi.
 * File nay CHI dung de build DLL nen luon dllexport.
 * extern "C" de phong bi bien dich nhu C++ (name mangling lam
 * GetProcAddress tim khong ra ten ham). */
#ifdef __cplusplus
#define ENGINE_API extern "C" __declspec(dllexport)
#else
#define ENGINE_API __declspec(dllexport)
#endif

static BOOL g_initialized = FALSE;

/* Cau hinh nguong - co the doc tu configJson trong ban that */
static double g_thrSuspicious = 2.0;
static double g_thrMalicious   = 5.0;
static double g_secExecEntropy = 7.4;   /* nguong entropy section thuc thi */

/* ==================================================================
 * Ghi them mot dong ly do vao chuoi detail
 * ================================================================== */
static void AddReason(EngineResult *r, double pts, const char *fmt, ...)
{
    char line[220];
    char full[260];
    va_list ap;
    size_t cur, add;

    va_start(ap, fmt);
    _vsnprintf(line, sizeof(line) - 1, fmt, ap);
    line[sizeof(line) - 1] = '\0';
    va_end(ap);

    sprintf(full, "%+.1f %s; ", pts, line);

    cur = strlen(r->detail);
    add = strlen(full);
    if (cur + add < sizeof(r->detail) - 1) {
        strcat(r->detail, full);
    }
    r->score += pts;
}

/* ==================================================================
 * NHOM E - VERIFY CHU KY AUTHENTICODE BANG WinVerifyTrust
 * ------------------------------------------------------------------
 * Day la phan "that" nhat cua bai: goi dung co che ma Windows dung
 * de kiem tra chu ky so cua file thuc thi.
 *
 * Ba diem de sai:
 *   1. Duong dan phai la UNICODE (WCHAR*) -> phai chuyen doi
 *   2. Phai goi LAN THU HAI voi WTD_STATEACTION_CLOSE de dong handle.
 *      Quen la ro ri tai nguyen - service chay 24/7 se can kiet.
 *   3. Phai link wintrust.lib
 * ================================================================== */
static int VerifySignature(const char *path)
{
    WCHAR wpath[MAX_PATH * 2];
    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fileInfo;
    WINTRUST_DATA winTrustData;
    LONG status;
    int result;

    if (MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH * 2) == 0)
        return SIGN_UNKNOWN;

    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct      = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = wpath;

    ZeroMemory(&winTrustData, sizeof(winTrustData));
    winTrustData.cbStruct            = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice          = WTD_UI_NONE;          /* khong hien hop thoai */
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;      /* khong tra CRL (cham + can mang) */
    winTrustData.dwUnionChoice       = WTD_CHOICE_FILE;
    winTrustData.dwStateAction       = WTD_STATEACTION_VERIFY;
    winTrustData.pFile               = &fileInfo;

    status = WinVerifyTrust(NULL, &guidAction, &winTrustData);

    switch (status) {
        case ERROR_SUCCESS:
            result = SIGN_VALID;
            break;
        case TRUST_E_NOSIGNATURE:
        case TRUST_E_SUBJECT_FORM_UNKNOWN:
        case TRUST_E_PROVIDER_UNKNOWN:
            result = SIGN_UNSIGNED;
            break;
        case TRUST_E_EXPLICIT_DISTRUST:
        case TRUST_E_SUBJECT_NOT_TRUSTED:
        case CRYPT_E_SECURITY_SETTINGS:
        case CERT_E_EXPIRED:
        case CERT_E_CHAINING:
        case CERT_E_UNTRUSTEDROOT:
        case TRUST_E_BAD_DIGEST:
            result = SIGN_INVALID;
            break;
        default:
            result = SIGN_INVALID;
            break;
    }

    /* BAT BUOC: goi lan hai de dong state handle */
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &winTrustData);

    return result;
}

/* ==================================================================
 * Kiem tra luy thua cua 2:  n & (n-1) == 0
 *   8 = 1000, 7 = 0111 -> AND = 0     (dung)
 *   6 = 0110, 5 = 0101 -> AND = 0100  (sai)
 * ================================================================== */
static BOOL IsPowerOfTwoPub(DWORD n) { return n != 0 && (n & (n - 1)) == 0; }

/* ==================================================================
 * NHOM A - HEADER & METADATA BAT THUONG
 * ================================================================== */
static void RuleGroupA(const PeInfo *pe, EngineResult *r)
{
    DWORD now = (DWORD)time(NULL);
    int i;
    BOOL epInSection = FALSE;

    /* A1: TimeDateStamp = 0, qua cu (truoc 1995), hoac o TUONG LAI.
     * Timestamp tuong lai la dau hieu ro rang cua viec sua header. */
    if (pe->timeDateStamp == 0) {
        AddReason(r, 1.0, "TimeDateStamp = 0 (bi xoa)");
    } else if (pe->timeDateStamp < 788918400UL) {          /* 1995-01-01 */
        AddReason(r, 1.0, "TimeDateStamp qua cu (truoc 1995)");
    } else if (pe->timeDateStamp > now + 86400UL) {        /* qua ngay mai */
        AddReason(r, 1.0, "TimeDateStamp nam trong tuong lai");
    }

    /* A2: AddressOfEntryPoint nam ngoai moi section.
     * EP phai tro toi code thuc thi duoc. Nam ngoai section nghia la
     * tro vao vung khong duoc nap -> chuong trinh khong the chay binh
     * thuong -> gan nhu chac chan da bi che bien. */
    if (pe->entryPointRva == 0) {
        if (!pe->isDll) AddReason(r, 2.0, "AddressOfEntryPoint = 0 tren file EXE");
    } else {
        for (i = 0; i < pe->sectionCount; i++) {
            const PeSection *s = &pe->sections[i];
            DWORD vs = s->virtualSize ? s->virtualSize : s->sizeOfRawData;
            if (pe->entryPointRva >= s->virtualAddress &&
                pe->entryPointRva <  s->virtualAddress + vs) {
                epInSection = TRUE;
                /* Bonus: EP nam trong section KHONG thuc thi cung la la */
                if (!s->isExec)
                    AddReason(r, 2.0, "EntryPoint nam trong section '%s' khong co co X", s->name);
                break;
            }
        }
        if (!epInSection)
            AddReason(r, 2.0, "EntryPoint RVA 0x%X nam ngoai moi section", pe->entryPointRva);
    }

    /* A3: SectionAlignment / FileAlignment di thuong.
     * Chuan: ca hai phai la luy thua cua 2; FileAlignment trong
     * khoang 512..64K; SectionAlignment >= FileAlignment. */
    if (!IsPowerOfTwoPub(pe->fileAlignment) || pe->fileAlignment < 512 || pe->fileAlignment > 65536)
        AddReason(r, 1.0, "FileAlignment di thuong (%u)", pe->fileAlignment);
    else if (!IsPowerOfTwoPub(pe->sectionAlignment))
        AddReason(r, 1.0, "SectionAlignment khong phai luy thua cua 2 (%u)", pe->sectionAlignment);
    else if (pe->sectionAlignment < pe->fileAlignment)
        AddReason(r, 1.0, "SectionAlignment < FileAlignment");

    /* A4: NumberOfRvaAndSizes khong hop le, hoac directory tro ra ngoai file */
    if (pe->numberOfRvaAndSizes == 0 || pe->numberOfRvaAndSizes > 16)
        AddReason(r, 2.0, "NumberOfRvaAndSizes = %u (khong hop le)", pe->numberOfRvaAndSizes);
    if (pe->dirOutOfFile)
        AddReason(r, 2.0, "Co DataDirectory tro ra ngoai file");
}

/* ==================================================================
 * NHOM B - SECTION ANOMALIES
 * ================================================================== */
static void RuleGroupB(const PeInfo *pe, EngineResult *r)
{
    int i, j;
    BOOL weirdName = FALSE, dupName = FALSE;
    BOOL foundWX = FALSE;
    int highEntropyExec = 0;

    for (i = 0; i < pe->sectionCount; i++) {
        const PeSection *s = &pe->sections[i];

        if (s->nameWeird) weirdName = TRUE;

        /* Ten trung nhau */
        for (j = i + 1; j < pe->sectionCount; j++) {
            if (strcmp(s->name, pe->sections[j].name) == 0) dupName = TRUE;
        }

        /* B2: vua Writable vua eXecutable.
         * Code binh thuong nam o section chi doc + thuc thi. Vua ghi
         * vua chay = dau hieu code TU SUA MINH (self-modifying), thu
         * ma packer va malware hay dung. */
        if (s->isWrite && s->isExec) {
            if (!foundWX) {
                AddReason(r, 2.0, "Section '%s' vua Writable vua eXecutable (W+X)", s->name);
                foundWX = TRUE;
            }
        }

        /* B3: section thuc thi nhung entropy cao */
        if (s->isExec && s->entropy > g_secExecEntropy && s->sizeOfRawData > 1024) {
            highEntropyExec++;
            if (highEntropyExec == 1)
                AddReason(r, 1.0, "Section thuc thi '%s' entropy %.2f > %.1f (da nen/ma hoa)",
                          s->name, s->entropy, g_secExecEntropy);
        }
    }

    if (weirdName) AddReason(r, 1.0, "Co section ten bat thuong");
    if (dupName)   AddReason(r, 1.0, "Co hai section trung ten");

    /* B4: overlay - du lieu sau section cuoi cung.
     * Phan nay khong duoc nap vao RAM khi chay -> malware hay giau
     * payload o day de vuot qua may quet chi nhin phan duoc nap. */
    if (pe->overlaySize > 0) {
        if (pe->overlaySize > 5UL * 1024 * 1024)
            AddReason(r, 2.0, "Overlay rat lon: %.1f MB", (double)pe->overlaySize / 1048576.0);
        else if (pe->overlaySize > 256UL * 1024)
            AddReason(r, 1.0, "Overlay: %.0f KB", (double)pe->overlaySize / 1024.0);
    }

    /* B5: so section bat thuong */
    if (pe->sectionCount > 12)
        AddReason(r, 1.0, "So section = %d (nhieu bat thuong)", pe->sectionCount);
    else if (pe->sectionCount < 2)
        AddReason(r, 1.0, "So section = %d (qua it)", pe->sectionCount);
}

/* ==================================================================
 * NHOM C - IMPORTS / EXPORTS / TLS / DELAY-LOAD
 * ================================================================== */
static void RuleGroupC(const PeInfo *pe, EngineResult *r)
{
    int g;
    int groupsHit = 0;

    /* C1: moi NHOM API rui ro gap duoc +1, cap toi da 4 diem.
     * Cham diem theo NHOM chu khong theo tung ham: mot chuong trinh
     * dung 10 ham mang van chi la "co dung mang", khong nguy hiem gap
     * 10 lan mot chuong trinh dung 1 ham. */
    for (g = 0; g < RISK_GROUPS; g++) {
        if (pe->riskHit[g] > 0) {
            groupsHit++;
            AddReason(r, 1.0, "Import API nhom %s (%d ham)", PeRiskGroupName(g), pe->riskHit[g]);
        }
    }

    /* Bonus: dung ca 3 nhom Process + Network + Crypto = mau hinh
     * dien hinh cua ransomware / RAT */
    if (pe->riskHit[RISK_PROCESS] > 0 && pe->riskHit[RISK_NETWORK] > 0 && pe->riskHit[RISK_CRYPTO] > 0)
        AddReason(r, 1.0, "Ket hop Process + Network + Crypto (mau hinh RAT/ransomware)");

    /* C2: TLS callback chay TRUOC entry point.
     * Debugger mac dinh dung o EP, nen code trong TLS callback da chay
     * xong truoc khi nguoi phan tich kip nhin. Ky thuat chong phan tich
     * kinh dien -> +2. */
    if (pe->hasTls && pe->tlsCallbackCount > 0)
        AddReason(r, 2.0, "Co %u TLS callback (chay truoc EntryPoint)", pe->tlsCallbackCount);
    else if (pe->hasTls)
        AddReason(r, 0.5, "Co TLS directory nhung khong co callback");

    /* C3: delay-import ket hop voi API rui ro.
     * Delay-load lam ham chi duoc nap khi goi -> bang import tinh
     * "sach" hon khi nhin luot. */
    if (pe->hasDelayImport && groupsHit > 0)
        AddReason(r, 1.0, "Co Delay-Import ket hop API rui ro");

    /* C4: import qua it - dau hieu packer (moi thu duoc nap dong) */
    if (pe->importApiCount > 0 && pe->importApiCount < 5 && !pe->isManaged)
        AddReason(r, 1.0, "Chi import %d ham (dau hieu packer/nap dong)", pe->importApiCount);

    /* C5: export bat thuong voi DLL */
    if (pe->isDll) {
        if (pe->exportCount > 500)
            AddReason(r, 1.0, "DLL export %u ham (qua nhieu)", pe->exportCount);
        if (pe->exportNameWeird)
            AddReason(r, 1.0, "Ten ham export chua ky tu la");
    } else if (pe->hasExport && pe->exportCount > 0) {
        AddReason(r, 0.5, "File EXE nhung co bang export (%u ham)", pe->exportCount);
    }
}

/* ==================================================================
 * NHOM D - RESOURCES & VERSION INFO
 * ================================================================== */
static void RuleGroupD(const PeInfo *pe, EngineResult *r)
{
    /* D1: khong co VersionInfo. Phan mem thuong mai/he thong gan nhu
     * luon co (ten cong ty, phien ban, ban quyen). Thieu -> dang ngo. */
    if (!pe->hasVersionInfo && !pe->isDriver)
        AddReason(r, 1.0, "Khong co VersionInfo (thieu CompanyName)");

    /* D2: RCDATA lon hoac entropy cao = payload giau trong resource */
    if (pe->biggestRcData > 1024UL * 1024)
        AddReason(r, 1.0, "RCDATA lon: %.0f KB", (double)pe->biggestRcData / 1024.0);
    if (pe->rcDataEntropy > 7.5)
        AddReason(r, 1.0, "RCDATA entropy %.2f (da nen/ma hoa)", pe->rcDataEntropy);

    /* D3: GUI app thieu icon/manifest -> +0.5 (diem le, ly do de bai
     * yeu cau score dang so thuc) */
    if (pe->subsystem == 2) {   /* WINDOWS_GUI */
        if (!pe->hasIcon)     AddReason(r, 0.5, "GUI app khong co icon");
        if (!pe->hasManifest) AddReason(r, 0.5, "GUI app khong co manifest");
    }

    /* D4: thieu Rich header o file khong phai .NET */
    if (!pe->hasRichHeader && !pe->isManaged)
        AddReason(r, 0.5, "Khong co Rich header (khong build bang toolchain MS)");
}

/* ==================================================================
 * NHOM E - AUTHENTICODE SIGNATURE
 * ================================================================== */
static void RuleGroupE(const PeInfo *pe, EngineResult *r, int signState)
{
    switch (signState) {
        case SIGN_VALID:
            /* Chu ky hop le -> GIAM diem (thuong cho file dang tin) */
            AddReason(r, -2.0, "Chu ky Authenticode hop le");
            break;

        case SIGN_INVALID:
            /* Nguy hiem nhat: CO chu ky nhung khong hop le. Nghia la
             * file da bi SUA sau khi ky, hoac chu ky gia mao. */
            AddReason(r, 2.0, "Co chu ky nhung KHONG hop le (file da bi sua?)");
            break;

        case SIGN_UNSIGNED:
            /* Khong ky: rat nhieu phan mem hop phap cung khong ky,
             * nen chi +1 khi file nam o vi tri dang ngo. */
            if (pe->isDriver)
                AddReason(r, 2.0, "Driver khong co chu ky (Windows yeu cau bat buoc)");
            else
                AddReason(r, 1.0, "File khong co chu ky so");
            break;

        default:
            break;
    }

    /* E2: co Security Directory nhung tro ra ngoai file */
    if (pe->isSigned && pe->dirOutOfFile)
        AddReason(r, 1.0, "Security Directory tro ra ngoai file");
}

/* ==================================================================
 * RULE DU PHONG cho file KHONG PHAI PE
 * Giu lai logic 5.1 de moi file deu co verdict.
 * ================================================================== */
static void RuleNonPe(const char *path, EngineResult *r)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULONGLONG size = 0;
    const char *dot;

    if (GetFileAttributesExA(path, GetFileExInfoStandard, &fad))
        size = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;

    if (!(path[0] == 'C' || path[0] == 'c') || path[1] != ':')
        AddReason(r, 1.0, "File nam ngoai o C:");

    dot = strrchr(path, '.');
    if (dot) {
        const char *risky[] = { ".js", ".vbs", ".ps1", ".bat", ".cmd", ".scr", ".hta", NULL };
        int i;
        for (i = 0; risky[i]; i++) {
            if (_stricmp(dot, risky[i]) == 0) {
                AddReason(r, 2.0, "Duoi script rui ro (%s)", dot);
                break;
            }
        }
    }

    if (size > (ULONGLONG)50 * 1024 * 1024)
        AddReason(r, 1.0, "Kich thuoc > 50MB");
}

/* ==================================================================
 * QUY DIEM -> VERDICT
 * ================================================================== */
static int ScoreToVerdict(double score)
{
    if (score >= g_thrMalicious)  return VERDICT_MALICIOUS;
    if (score >= g_thrSuspicious) return VERDICT_SUSPICIOUS;
    return VERDICT_SAFE;
}

/* ==================================================================
 * API EXPORT
 * ================================================================== */
ENGINE_API int EngineGetVersion(void)
{
    return ENGINE_VERSION_MAJOR * 100 + ENGINE_VERSION_MINOR;   /* = 200 */
}

/* ==================================================================
 * EngineGetFingerprint - DAU VAN TAY ENGINE
 * ------------------------------------------------------------------
 * Day la ham MOI, sinh ra de giai quyet yeu cau phan 2 cua de bai:
 * "cache phai co phuong an khi update engine moi".
 *
 * Van de: engine 1.0 cham a.exe = SAFE. Nang len engine 2.0 co them
 * rule TLS callback -> le ra a.exe phai la MALICIOUS. Nhung cache van
 * tra SAFE -> MALWARE LOT LUOI VI CACHE.
 *
 * Giai phap: tron version + so luong rule + cac nguong vao mot con so.
 * Doi bat ky thu gi -> fingerprint doi -> toan bo cache tu dong vo hieu.
 * ================================================================== */
ENGINE_API DWORD EngineGetFingerprint(void)
{
    DWORD fp = 0x5A2E0000UL;
    fp ^= (DWORD)(ENGINE_VERSION_MAJOR * 100 + ENGINE_VERSION_MINOR);
    fp ^= (DWORD)(g_thrSuspicious * 10) << 8;
    fp ^= (DWORD)(g_thrMalicious   * 10) << 12;
    fp ^= (DWORD)(g_secExecEntropy * 10) << 16;
    fp ^= 30;   /* so rule hien tai - tang moi khi them rule */
    return fp;
}

ENGINE_API int EngineInitialize(const char *configJson)
{
    /* Ban that se parse JSON. O day chi doc vai khoa don gian
     * de chung minh config co tac dung that. */
    if (configJson && *configJson) {
        const char *p = strstr(configJson, "\"execEntropy\":");
        if (p) {
            double v = atof(p + 14);
            if (v > 5.0 && v <= 8.0) g_secExecEntropy = v;
        }
    }
    g_initialized = TRUE;
    return 0;
}

ENGINE_API void EngineShutdown(void)
{
    g_initialized = FALSE;
}

/* ==================================================================
 * EngineScanFileEx - HAM QUET CHINH cua 5.2
 * ================================================================== */
ENGINE_API int EngineScanFileEx(const char *path, int options,
                                ProgressCallback cb, void *userData,
                                EngineResult *out)
{
    PeInfo pe;
    EngineResult r;
    int st;

    (void)options;

    if (!g_initialized) return -1;
    if (!path || !out)  return -2;

    memset(&r, 0, sizeof(r));
    r.score    = 0.0;
    r.detail[0] = '\0';

    /* --- STAGE OPEN --- */
    if (cb) cb(STAGE_OPEN, 10, userData);

    /* --- STAGE PARSE: doc cau truc PE --- */
    if (cb) cb(STAGE_PARSE, 30, userData);
    st = PeRead(path, &pe);

    r.peStatus = st;
    strncpy(r.peStatusText, PeStatusName(st), sizeof(r.peStatusText) - 1);

    if (st == PE_ERR_IO) {
        strcpy(r.detail, "Khong mo duoc file");
        r.verdict = VERDICT_ERROR;
        r.isPe    = 0;
        *out = r;
        return VERDICT_ERROR;
    }

    if (st == PE_MALFORMED_PE) {
        /* Khong phai PE -> dung bo rule du phong (giong 5.1) */
        r.isPe = 0;
        if (cb) cb(STAGE_ANALYZE, 60, userData);
        RuleNonPe(path, &r);
        if (cb) cb(STAGE_REPORT, 100, userData);
        r.verdict = ScoreToVerdict(r.score);
        *out = r;
        return r.verdict;
    }

    if (st == PE_STRUCT_CORRUPT) {
        /* Dung la PE nhung cau truc hong - RAT dang ngo.
         * File hop phap khong bao gio co section vuot kich thuoc file. */
        r.isPe = 1;
        AddReason(&r, 4.0, "STRUCT_CORRUPT: %s", pe.errMsg);
        if (cb) cb(STAGE_REPORT, 100, userData);
        r.verdict = ScoreToVerdict(r.score);
        r.sectionCount = pe.sectionCount;
        r.machine = pe.machine;
        *out = r;
        return r.verdict;
    }

    /* ---------- PE hop le: chay day du 5 nhom rule ---------- */
    r.isPe          = 1;
    r.machine       = pe.machine;
    r.subsystem     = pe.subsystem;
    r.isDll         = pe.isDll;
    r.isDriver      = pe.isDriver;
    r.isManaged     = pe.isManaged;
    r.isSigned      = pe.isSigned;
    r.hasDebug      = pe.hasDebug;
    r.hasRichHeader = pe.hasRichHeader;
    r.entryPointRva = pe.entryPointRva;
    r.imageBase     = pe.imageBase;
    r.sectionCount  = pe.sectionCount;

    if (cb) cb(STAGE_ANALYZE, 55, userData);

    RuleGroupA(&pe, &r);
    RuleGroupB(&pe, &r);
    RuleGroupC(&pe, &r);
    RuleGroupD(&pe, &r);

    /* --- STAGE SIGNATURE: buoc cham nhat, tach rieng stage --- */
    if (cb) cb(STAGE_SIGNATURE, 85, userData);
    {
        int signState = pe.isSigned ? VerifySignature(path) : SIGN_UNSIGNED;
        r.signState = signState;
        RuleGroupE(&pe, &r, signState);
    }

    /* Diem khong duoc am (chu ky hop le tru 2 diem co the lam am) */
    if (r.score < 0.0) r.score = 0.0;

    if (cb) cb(STAGE_REPORT, 100, userData);

    r.verdict = ScoreToVerdict(r.score);
    if (r.detail[0] == '\0') strcpy(r.detail, "Khong co dau hieu bat thuong");

    *out = r;
    return r.verdict;
}

/* ==================================================================
 * EngineScanFile - giu chu ky cu de tuong thich
 * ================================================================== */
ENGINE_API int EngineScanFile(const char *path, int options,
                              ProgressCallback cb, void *userData)
{
    EngineResult r;
    return EngineScanFileEx(path, options, cb, userData, &r);
}

/* ==================================================================
 * DllMain
 * QUY TAC VANG: tuyet doi khong lam viec nang trong day (khong
 * LoadLibrary khac, khong tao thread, khong cho khoa). Windows giu
 * "loader lock" khi goi DllMain -> rat de deadlock.
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
