#define _CRT_SECURE_NO_WARNINGS
/*
 * service.c - Scan Service 5.2
 * ===================================================================
 * Nang cap tu 5.1:
 *   [MOI] Outbound queue + luong gui rieng cho moi session
 *         -> worker KHONG BAO GIO cham vao pipe -> het deadlock tan goc
 *   [MOI] Backpressure: drop event VERBOSE, giu event CRITICAL
 *   [MOI] Resume: giu vong dem event da gui, phat lai khi client noi lai
 *   [MOI] Pipe co Security Descriptor (thay vi DACL = NULL cua 5.1)
 *   [MOI] Handshake kiem PID that + user that qua impersonation
 *   [MOI] Policy: deny-list duong dan + rate limit token bucket
 *   [NANG CAP] Cache: bang bam, ghi ra file, co engineFingerprint
 *
 * Che do chay:
 *   service.exe              -> menu
 *   service.exe console      -> chay trong cua so console
 *   service.exe install / uninstall / start / stop / status
 */

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "protocol.h"
#include "framing.h"
#include "pereader.h"
#include "engineapi.h"

/* ================= Cau hinh ================= */
#define SERVICE_NAME        "AvScanSvc52"
#define SERVICE_DISPLAY     "AV Scan Service 5.2"
#define ENGINE_DLL          "engine.dll"

#define MAX_WORKERS         4
#define MAX_JOBS            512
#define MAX_SESSIONS        32
#define CACHE_BUCKETS       4096
#define CACHE_TTL_SEC       600       /* 10 phut */
#define OUTQ_SIZE            128     /* suc chua hang doi gui moi session */
#define RESUME_RING         64        /* so event giu lai de phat lai */
#define SESSION_GRACE_MS    10000     /* giu session 10s sau khi mat ket noi */
#define RATE_MAX_TOKENS     10.0      /* toi da 10 request don */
#define RATE_REFILL_PER_SEC 2.0       /* rot lai 2 token moi giay */
#define IO_TIMEOUT_MS       3000

/* ==================================================================
 * DEMO YEU CAU 1.5-1.7: mo phong CLIENT CHAM
 * ------------------------------------------------------------------
 * Dat > 0 de lam cham luong gui, tai tao dung tinh huong thuc te:
 * client ban in ra console -> ngung doc pipe -> hang doi gui day.
 * Dat 0 khi chay binh thuong.
 * ================================================================== */
#define SENDER_DELAY_MS     0

/* ================= Con tro ham engine ================= */
static HMODULE                g_hEngine       = NULL;
static FnEngineInitialize     g_EngineInit    = NULL;
static FnEngineScanFile       g_EngineScan    = NULL;
static FnEngineScanFileEx     g_EngineScanEx  = NULL;
static FnEngineGetVersion     g_EngineVer     = NULL;
static FnEngineGetFingerprint g_EngineFp      = NULL;
static FnEngineShutdown       g_EngineStop    = NULL;
static DWORD                  g_engineFingerprint = 0;

/* ================= Duong dan ================= */
static char g_exeDir[MAX_PATH]     = {0};
static char g_enginePath[MAX_PATH] = {0};
static char g_logPath[MAX_PATH]    = {0};
static char g_cachePath[MAX_PATH]  = {0};
static int  g_consoleMode          = 0;

/* ================= Event ra ngoai ================= */
typedef struct {
    DWORD seq;
    WORD  type;
    int   cls;                    /* EVCLASS_CRITICAL / EVCLASS_VERBOSE */
    DWORD len;
    char  payload[512];
} OutEvent;

/* ================= Session ================= */
typedef struct {
    volatile LONG used;
    int           sessionId;
    HANDLE        hPipe;
    volatile LONG connected;
    DWORD         disconnectTick;

    char          clientId[64];
    DWORD         clientPid;
    char          user[128];

    /* --- hang doi gui (outbound queue) --- */
    OutEvent      q[OUTQ_SIZE];
    int           qHead, qTail, qCount;
    HANDLE        hQMutex;
    HANDLE        hQSem;
    HANDLE        hSender;
    volatile LONG seqNext;
    volatile LONG droppedVerbose;
    volatile LONG flowPending;
    volatile LONG stopSender;

    /* --- vong dem phuc vu RESUME --- */
    OutEvent      ring[RESUME_RING];
    int           ringPos;
    int           ringCount;
    HANDLE        hRingMutex;
} Session;

static Session       g_sessions[MAX_SESSIONS];
static HANDLE        g_hSessMutex = NULL;
static volatile LONG g_sessionSeq = 0;

/* ================= Job ================= */
#define JS_PENDING   0
#define JS_RUNNING   1
#define JS_DONE      2
#define JS_CANCELLED 3
#define JS_FAILED    4

typedef struct {
    int           jobId;
    char          path[MAX_PATH];
    int           priority;
    int           timeoutMs;
    volatile LONG state;
    volatile LONG cancelFlag;
    int           sessionId;
    DWORD         startTick;
    int           verdict;
    double        score;
} Job;

static Job           g_jobs[MAX_JOBS];        /* bang tra cuu theo jobId */
static Job          *g_queue[MAX_JOBS];       /* hang doi con tro */
static int           g_qCount = 0;
static volatile LONG g_jobCount = 0;
static HANDLE        g_hQueueMutex = NULL;
static HANDLE        g_hJobSem     = NULL;

/* ================= Cache v2 ================= */
typedef struct {
    int       used;
    DWORD     hash;
    char      path[MAX_PATH];
    FILETIME  lastWrite;
    ULONGLONG size;
    DWORD     engineFp;
    int       verdict;
    double    score;
    __int64   storedAt;      /* time() luc luu */
} CacheEntry;

static CacheEntry *g_cache = NULL;
static HANDLE      g_hCacheMutex = NULL;
static volatile LONG g_cacheHits = 0, g_cacheMiss = 0, g_cacheCount = 0;

/* ================= Policy ================= */
typedef struct {
    int    used;
    char   clientId[64];
    double tokens;
    DWORD  lastTick;
} RateBucket;

static RateBucket g_rate[MAX_SESSIONS];
static HANDLE     g_hRateMutex = NULL;

static const char *g_denyList[] = {
    "C:\\WINDOWS\\SYSTEM32",
    "C:\\WINDOWS\\SYSWOW64",
    "C:\\WINDOWS\\WINSXS",
    NULL
};

/* ================= Throttle ================= */
#define THR_IDLE       0
#define THR_BUSY       1
#define THR_OVERLOADED 2
static volatile LONG g_throttle = THR_IDLE;
static volatile LONG g_cpuPct   = 0;
static volatile LONG g_ramPct   = 0;

/* ================= Telemetry ================= */
static volatile LONG g_totalJobs = 0, g_doneJobs = 0, g_failJobs = 0, g_cancelJobs = 0;
static volatile LONG g_pending = 0, g_running = 0;
static volatile LONG g_droppedTotal = 0, g_flowEvents = 0;
static volatile LONG g_crcErrors = 0, g_handshakeFails = 0, g_policyDenies = 0, g_rateDenies = 0;
static volatile LONG g_resumeCount = 0;
static double        g_scanTimes[MAX_JOBS];
static volatile LONG g_scanTimeCount = 0;
static HANDLE        g_hTeleMutex = NULL;
static HANDLE        g_hLogMutex  = NULL;

/* ================= Dieu khien chung ================= */
static HANDLE g_hStopEvent = NULL;
static HANDLE g_hWorkers[MAX_WORKERS] = {0};
static HANDLE g_hThrottleThread = NULL, g_hTeleThread = NULL;
static HANDLE g_hPipeThread = NULL, g_hReaperThread = NULL;

static SERVICE_STATUS        g_svcStatus;
static SERVICE_STATUS_HANDLE g_svcStatusHandle = NULL;
static HANDLE                g_hSvcStopEvent   = NULL;

/* ==================================================================
 * TIEN ICH: duong dan + log
 * ================================================================== */
static void InitPaths(void)
{
    char exePath[MAX_PATH];
    char *slash;

    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    strcpy(g_exeDir, exePath);
    slash = strrchr(g_exeDir, '\\');
    if (slash) *slash = '\0';

    /* Duong dan TUYET DOI cho engine.dll.
     * Bat buoc: khi chay dang Windows Service, SCM khoi dong voi thu muc
     * lam viec la C:\Windows\System32 -> LoadLibrary("engine.dll") se tim
     * o do va that bai. Day la rao can da gap o 5.1. */
    sprintf(g_enginePath, "%s\\%s", g_exeDir, ENGINE_DLL);
    sprintf(g_logPath,    "%s\\service52.log", g_exeDir);
    sprintf(g_cachePath,  "%s\\cache52.bin",   g_exeDir);
}

static void LogMsg(const char *fmt, ...)
{
    char buf[1024], timeStr[32], line[1100];
    va_list ap;
    time_t now;
    struct tm tmv;
    FILE *f;

    va_start(ap, fmt);
    _vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    buf[sizeof(buf) - 1] = '\0';
    va_end(ap);

    now = time(NULL);
    /* localtime_s thay vi localtime: localtime tra ve con tro toi
     * BUFFER TINH DUNG CHUNG -> nhieu luong goi cung luc se tranh chap.
     * Bai hoc tu 5.1. */
    localtime_s(&tmv, &now);
    strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &tmv);
    sprintf(line, "[%s] %s", timeStr, buf);

    if (g_hLogMutex) WaitForSingleObject(g_hLogMutex, 2000);

    if (g_consoleMode) printf("%s\n", line);

    f = fopen(g_logPath, "a");
    if (f) { fprintf(f, "%s\n", line); fclose(f); }

    if (g_hLogMutex) ReleaseMutex(g_hLogMutex);
}

/* ==================================================================
 * NAP ENGINE DONG
 * ================================================================== */
static BOOL LoadEngine(void)
{
    g_hEngine = LoadLibraryA(g_enginePath);
    if (!g_hEngine) {
        LogMsg("LOI: khong nap duoc %s (ma loi %lu)", g_enginePath, GetLastError());
        LogMsg("     Kiem tra: engine.dll co nam canh service.exe? Cung x64?");
        return FALSE;
    }

    g_EngineInit   = (FnEngineInitialize)     GetProcAddress(g_hEngine, "EngineInitialize");
    g_EngineScan   = (FnEngineScanFile)       GetProcAddress(g_hEngine, "EngineScanFile");
    g_EngineScanEx = (FnEngineScanFileEx)     GetProcAddress(g_hEngine, "EngineScanFileEx");
    g_EngineVer    = (FnEngineGetVersion)     GetProcAddress(g_hEngine, "EngineGetVersion");
    g_EngineFp     = (FnEngineGetFingerprint) GetProcAddress(g_hEngine, "EngineGetFingerprint");
    g_EngineStop   = (FnEngineShutdown)       GetProcAddress(g_hEngine, "EngineShutdown");

    if (!g_EngineInit || !g_EngineScanEx || !g_EngineVer || !g_EngineFp || !g_EngineStop) {
        LogMsg("LOI: thieu ham export trong engine.dll");
        LogMsg("     Kiem tra macro ENGINE_API co dllexport khong.");
        FreeLibrary(g_hEngine);
        g_hEngine = NULL;
        return FALSE;
    }

    g_EngineInit("{\"execEntropy\":7.4}");
    g_engineFingerprint = g_EngineFp();

    LogMsg("Da nap engine.dll, phien ban = %d, fingerprint = 0x%08X",
           g_EngineVer(), g_engineFingerprint);
    return TRUE;
}

/* ==================================================================
 * CACHE v2 - BANG BAM + BEN VUNG + FINGERPRINT
 * ================================================================== */

/* Ham bam FNV-1a: don gian, phan bo deu, du dung cho bai nay */
static DWORD HashPath(const char *s)
{
    DWORD h = 2166136261UL;
    while (*s) {
        h ^= (DWORD)(BYTE)toupper((unsigned char)*s);  /* Windows khong phan biet hoa thuong */
        h *= 16777619UL;
        s++;
    }
    return h;
}

static BOOL CacheInit(void)
{
    g_cache = (CacheEntry *)calloc(CACHE_BUCKETS, sizeof(CacheEntry));
    return g_cache != NULL;
}

/* Nap cache tu file.
 * DIEM MAU CHOT: neu engineFingerprint trong file khac fingerprint
 * hien tai -> BO TOAN BO cache. Day la cach chong "malware lot luoi
 * vi cache cu" khi nang cap engine. */
static void CacheLoad(void)
{
    FILE *f;
    DWORD magic = 0, fp = 0, count = 0, i;

    f = fopen(g_cachePath, "rb");
    if (!f) { LogMsg("Cache: chua co file cu, bat dau rong"); return; }

    if (fread(&magic, 4, 1, f) != 1 || magic != 0x32435641UL) {  /* "AVC2" */
        LogMsg("Cache: magic sai, bo qua file cu");
        fclose(f); return;
    }
    if (fread(&fp, 4, 1, f) != 1) { fclose(f); return; }
    if (fread(&count, 4, 1, f) != 1) { fclose(f); return; }

    if (fp != g_engineFingerprint) {
        LogMsg("Cache: fingerprint cu 0x%08X != moi 0x%08X -> VO HIEU TOAN BO (%lu muc)",
               fp, g_engineFingerprint, count);
        fclose(f);
        DeleteFileA(g_cachePath);
        return;
    }

    for (i = 0; i < count; i++) {
        CacheEntry e;
        DWORD slot, probe;
        if (fread(&e, sizeof(CacheEntry), 1, f) != 1) break;
        if (!e.used) continue;

        slot = e.hash % CACHE_BUCKETS;
        for (probe = 0; probe < CACHE_BUCKETS; probe++) {
            DWORD idx = (slot + probe) % CACHE_BUCKETS;
            if (!g_cache[idx].used) {
                g_cache[idx] = e;
                InterlockedIncrement(&g_cacheCount);
                break;
            }
        }
    }
    fclose(f);
    LogMsg("Cache: nap lai %ld muc tu dia (fingerprint khop)", g_cacheCount);
}

static void CacheSave(void)
{
    FILE *f;
    DWORD magic = 0x32435641UL, count = 0, i;

    if (!g_cache) return;
    if (g_hCacheMutex) WaitForSingleObject(g_hCacheMutex, 5000);

    for (i = 0; i < CACHE_BUCKETS; i++) if (g_cache[i].used) count++;

    f = fopen(g_cachePath, "wb");
    if (f) {
        fwrite(&magic, 4, 1, f);
        fwrite(&g_engineFingerprint, 4, 1, f);
        fwrite(&count, 4, 1, f);
        for (i = 0; i < CACHE_BUCKETS; i++)
            if (g_cache[i].used) fwrite(&g_cache[i], sizeof(CacheEntry), 1, f);
        fclose(f);
        LogMsg("Cache: da ghi %lu muc ra %s", count, g_cachePath);
    }

    if (g_hCacheMutex) ReleaseMutex(g_hCacheMutex);
}

/* Tra cuu. Key gom 4 thanh phan:
 *   path + lastWriteTime + size + engineFingerprint
 * (5.1 chi co 3 thanh phan dau -> khong biet engine da doi) */
static BOOL CacheLookup(const char *path, FILETIME lw, ULONGLONG size,
                        int *outVerdict, double *outScore)
{
    DWORD h = HashPath(path);
    DWORD slot = h % CACHE_BUCKETS, probe;
    BOOL found = FALSE;
    __int64 now = (__int64)time(NULL);

    if (!g_cache) return FALSE;
    if (WaitForSingleObject(g_hCacheMutex, 5000) != WAIT_OBJECT_0) return FALSE;

    for (probe = 0; probe < CACHE_BUCKETS; probe++) {
        DWORD idx = (slot + probe) % CACHE_BUCKETS;
        CacheEntry *e = &g_cache[idx];

        if (!e->used) break;              /* o trong -> chac chan khong co */
        if (e->hash != h) continue;
        if (_stricmp(e->path, path) != 0) continue;

        if (e->lastWrite.dwLowDateTime  == lw.dwLowDateTime &&
            e->lastWrite.dwHighDateTime == lw.dwHighDateTime &&
            e->size     == size &&
            e->engineFp == g_engineFingerprint &&
            (now - e->storedAt) < CACHE_TTL_SEC) {
            *outVerdict = e->verdict;
            *outScore   = e->score;
            found = TRUE;
        } else {
            e->used = 0;                  /* het han / khong khop -> xoa */
            InterlockedDecrement(&g_cacheCount);
        }
        break;
    }

    ReleaseMutex(g_hCacheMutex);
    if (found) InterlockedIncrement(&g_cacheHits);
    else       InterlockedIncrement(&g_cacheMiss);
    return found;
}

static void CacheStore(const char *path, FILETIME lw, ULONGLONG size, int verdict, double score)
{
    DWORD h = HashPath(path);
    DWORD slot = h % CACHE_BUCKETS, probe;

    if (!g_cache) return;
    if (WaitForSingleObject(g_hCacheMutex, 5000) != WAIT_OBJECT_0) return;

    for (probe = 0; probe < CACHE_BUCKETS; probe++) {
        DWORD idx = (slot + probe) % CACHE_BUCKETS;
        CacheEntry *e = &g_cache[idx];

        if (!e->used || (e->hash == h && _stricmp(e->path, path) == 0)) {
            if (!e->used) InterlockedIncrement(&g_cacheCount);
            e->used = 1;
            e->hash = h;
            strncpy(e->path, path, MAX_PATH - 1);
            e->path[MAX_PATH - 1] = '\0';
            e->lastWrite = lw;
            e->size      = size;
            e->engineFp  = g_engineFingerprint;
            e->verdict   = verdict;
            e->score     = score;
            e->storedAt  = (__int64)time(NULL);
            break;
        }
    }

    ReleaseMutex(g_hCacheMutex);
}

/* ==================================================================
 * POLICY - DENY LIST
 * ------------------------------------------------------------------
 * BAY BAT BUOC BIET: so sanh chuoi duong dan tho la KHONG DU.
 * Ke tan cong co the vuot qua bang:
 *   C:\Windows\..\Windows\System32\x.exe   (path traversal)
 *   c:\windows\system32\x.exe              (khac hoa thuong)
 *   C:\Progra~1\...                        (ten 8.3 kieu DOS)
 * Phai CHUAN HOA bang GetFullPathName + GetLongPathName truoc.
 * ================================================================== */
static BOOL CanonicalPath(const char *in, char *out, DWORD outSize)
{
    char full[MAX_PATH];
    DWORD n;

    n = GetFullPathNameA(in, MAX_PATH, full, NULL);   /* xu ly ".." va "." */
    if (n == 0 || n >= MAX_PATH) return FALSE;

    n = GetLongPathNameA(full, out, outSize);          /* bung ten 8.3 */
    if (n == 0 || n >= outSize) {
        strncpy(out, full, outSize - 1);
        out[outSize - 1] = '\0';
    }
    return TRUE;
}

static BOOL PolicyAllowPath(const char *path, char *canonOut, DWORD canonSize)
{
    char upper[MAX_PATH];
    int i;

    if (!CanonicalPath(path, canonOut, canonSize)) return FALSE;

    strncpy(upper, canonOut, MAX_PATH - 1);
    upper[MAX_PATH - 1] = '\0';
    _strupr(upper);

    for (i = 0; g_denyList[i]; i++) {
        size_t n = strlen(g_denyList[i]);
        if (_strnicmp(upper, g_denyList[i], n) == 0) return FALSE;
    }
    return TRUE;
}

/* ==================================================================
 * POLICY - RATE LIMIT (thuat toan token bucket)
 * ------------------------------------------------------------------
 * Moi clientId co mot "xo" chua token, toi da RATE_MAX_TOKENS.
 * Cu moi giay rot them RATE_REFILL_PER_SEC token.
 * Moi request lay 1 token; het token -> tu choi.
 *
 * Uu diem so voi dem don gian: cho phep BUNG NO NGAN (10 job lien
 * tiep OK) nhung gioi han TOC DO TRUNG BINH dai han.
 * ================================================================== */
static BOOL PolicyAllowRate(const char *clientId)
{
    DWORD now = GetTickCount();
    int i, freeSlot = -1;
    BOOL allow = FALSE;

    if (WaitForSingleObject(g_hRateMutex, 2000) != WAIT_OBJECT_0) return TRUE;

    for (i = 0; i < MAX_SESSIONS; i++) {
        if (!g_rate[i].used) { if (freeSlot < 0) freeSlot = i; continue; }
        if (strcmp(g_rate[i].clientId, clientId) == 0) {
            double elapsed = (double)(now - g_rate[i].lastTick) / 1000.0;
            g_rate[i].tokens += elapsed * RATE_REFILL_PER_SEC;
            if (g_rate[i].tokens > RATE_MAX_TOKENS) g_rate[i].tokens = RATE_MAX_TOKENS;
            g_rate[i].lastTick = now;

            if (g_rate[i].tokens >= 1.0) { g_rate[i].tokens -= 1.0; allow = TRUE; }
            ReleaseMutex(g_hRateMutex);
            if (!allow) InterlockedIncrement(&g_rateDenies);
            return allow;
        }
    }

    if (freeSlot >= 0) {
        g_rate[freeSlot].used = 1;
        strncpy(g_rate[freeSlot].clientId, clientId, 63);
        g_rate[freeSlot].clientId[63] = '\0';
        g_rate[freeSlot].tokens   = RATE_MAX_TOKENS - 1.0;
        g_rate[freeSlot].lastTick = now;
        allow = TRUE;
    } else {
        allow = TRUE;   /* het cho theo doi -> cho qua */
    }

    ReleaseMutex(g_hRateMutex);
    return allow;
}

/* ==================================================================
 * SESSION - HANG DOI GUI + LUONG GUI RIENG
 * ------------------------------------------------------------------
 * DAY LA THAY DOI KIEN TRUC QUAN TRONG NHAT CUA 5.2.
 *
 * 5.1: Worker --WriteFile (timeout 3s)--> pipe
 *      Worker van phai CHO, chi la cho co gioi han. Van cham.
 *
 * 5.2: Worker --push--> [Outbound Queue] --> SenderThread --> pipe
 *      Worker day tin vao hang doi roi DI TIEP NGAY. Khong bao gio
 *      cham vao pipe. Client cham bao nhieu cung khong anh huong worker.
 * ================================================================== */
static DWORD WINAPI SenderThread(LPVOID param);

static Session *SessionCreate(HANDLE hPipe)
{
    int i;
    Session *s = NULL;

    WaitForSingleObject(g_hSessMutex, INFINITE);
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].used) {
            s = &g_sessions[i];
            break;
        }
    }
    if (!s) { ReleaseMutex(g_hSessMutex); return NULL; }

    ZeroMemory(s, sizeof(Session));
    s->used       = 1;
    s->sessionId  = (int)InterlockedIncrement(&g_sessionSeq);
    s->hPipe      = hPipe;
    s->connected  = 1;
    s->seqNext    = 0;
    s->hQMutex    = CreateMutexA(NULL, FALSE, NULL);
    s->hRingMutex = CreateMutexA(NULL, FALSE, NULL);
    s->hQSem      = CreateSemaphoreA(NULL, 0, OUTQ_SIZE * 4, NULL);
    ReleaseMutex(g_hSessMutex);

    s->hSender = CreateThread(NULL, 0, SenderThread, s, 0, NULL);
    return s;
}

static Session *SessionFind(int sessionId)
{
    int i;
    Session *s = NULL;
    WaitForSingleObject(g_hSessMutex, INFINITE);
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].used && g_sessions[i].sessionId == sessionId) {
            s = &g_sessions[i];
            break;
        }
    }
    ReleaseMutex(g_hSessMutex);
    return s;
}

static void SessionDestroy(Session *s)
{
    if (!s) return;

    InterlockedExchange(&s->stopSender, 1);
    if (s->hQSem) ReleaseSemaphore(s->hQSem, 1, NULL);
    if (s->hSender) {
        WaitForSingleObject(s->hSender, 3000);
        CloseHandle(s->hSender);
    }
    if (s->hPipe != INVALID_HANDLE_VALUE && s->hPipe != NULL) {
        FlushFileBuffers(s->hPipe);
        DisconnectNamedPipe(s->hPipe);
        CloseHandle(s->hPipe);
    }
    if (s->hQMutex)    CloseHandle(s->hQMutex);
    if (s->hRingMutex) CloseHandle(s->hRingMutex);
    if (s->hQSem)      CloseHandle(s->hQSem);

    WaitForSingleObject(g_hSessMutex, INFINITE);
    ZeroMemory(s, sizeof(Session));
    ReleaseMutex(g_hSessMutex);
}

/* Danh dau mat ket noi nhung CHUA xoa session - cho client resume */
static void SessionMarkDisconnected(Session *s)
{
    if (!s) return;
    InterlockedExchange(&s->connected, 0);
    s->disconnectTick = GetTickCount();
    if (s->hPipe != INVALID_HANDLE_VALUE && s->hPipe != NULL) {
        DisconnectNamedPipe(s->hPipe);
        CloseHandle(s->hPipe);
        s->hPipe = INVALID_HANDLE_VALUE;
    }
    LogMsg("Session %d mat ket noi, giu %d ms cho RESUME", s->sessionId, SESSION_GRACE_MS);
}

/* ==================================================================
 * DAY MOT EVENT VAO HANG DOI GUI
 * ------------------------------------------------------------------
 * Khi hang doi day:
 *   VERBOSE  -> bo (drop), tang bo dem, bat co FLOW_CONTROL
 *   CRITICAL -> tim mot event VERBOSE trong hang de DAY RA, lay cho.
 *               Neu khong co verbose nao thi danh bo cai cu nhat.
 * Nguyen tac: THA MAT TIEN DO CHU KHONG MAT KET QUA.
 * ================================================================== */
static BOOL SessionPush(Session *s, WORD type, int cls, const char *payload)
{
    DWORD len;
    OutEvent *ev;

    if (!s || !s->used) return FALSE;
    len = payload ? (DWORD)strlen(payload) : 0;
    if (len > 511) len = 511;

    if (WaitForSingleObject(s->hQMutex, 2000) != WAIT_OBJECT_0) return FALSE;

    if (s->qCount >= OUTQ_SIZE) {
        if (cls == EVCLASS_VERBOSE) {
            /* Bo event nay */
            InterlockedIncrement(&s->droppedVerbose);
            InterlockedIncrement(&g_droppedTotal);
            InterlockedExchange(&s->flowPending, 1);
            ReleaseMutex(s->hQMutex);
            return FALSE;
        } else {
            /* CRITICAL: tim event verbose de day ra lay cho */
            int i, victim = -1;
            for (i = 0; i < s->qCount; i++) {
                int idx = (s->qHead + i) % OUTQ_SIZE;
                if (s->q[idx].cls == EVCLASS_VERBOSE) { victim = idx; break; }
            }
            if (victim >= 0) {
                /* Don cac phan tu sau victim len 1 o */
                int i2 = victim;
                while (((i2 + 1) % OUTQ_SIZE) != s->qTail) {
                    s->q[i2] = s->q[(i2 + 1) % OUTQ_SIZE];
                    i2 = (i2 + 1) % OUTQ_SIZE;
                }
                s->qTail = i2;
                s->qCount--;
                InterlockedIncrement(&s->droppedVerbose);
                InterlockedIncrement(&g_droppedTotal);
                InterlockedExchange(&s->flowPending, 1);
            } else {
                /* Toan critical -> bo cai cu nhat */
                s->qHead = (s->qHead + 1) % OUTQ_SIZE;
                s->qCount--;
            }
        }
    }

    ev = &s->q[s->qTail];
    ev->seq = (DWORD)InterlockedIncrement(&s->seqNext);
    ev->type = type;
    ev->cls  = cls;
    ev->len  = len;
    if (len > 0) memcpy(ev->payload, payload, len);
    ev->payload[len] = '\0';

    s->qTail = (s->qTail + 1) % OUTQ_SIZE;
    s->qCount++;

    ReleaseMutex(s->hQMutex);
    ReleaseSemaphore(s->hQSem, 1, NULL);
    return TRUE;
}

/* Luu event da gui vao vong dem, phuc vu RESUME */
static void RingStore(Session *s, const OutEvent *ev)
{
    if (WaitForSingleObject(s->hRingMutex, 1000) != WAIT_OBJECT_0) return;
    s->ring[s->ringPos] = *ev;
    s->ringPos = (s->ringPos + 1) % RESUME_RING;
    if (s->ringCount < RESUME_RING) s->ringCount++;
    ReleaseMutex(s->hRingMutex);
}

/* ==================================================================
 * LUONG GUI - moi session mot luong
 * ================================================================== */
static DWORD WINAPI SenderThread(LPVOID param)
{
    Session *s = (Session *)param;
    HANDLE waits[2];

    waits[0] = s->hQSem;
    waits[1] = g_hStopEvent;

    while (1) {
        OutEvent ev;
        DWORD w;
        BOOL has = FALSE;

        w = WaitForMultipleObjects(2, waits, FALSE, 500);
        if (w == WAIT_OBJECT_0 + 1) break;                 /* dung service */
        if (s->stopSender) break;

        /* Lay 1 event khoi hang doi */
        if (WaitForSingleObject(s->hQMutex, 1000) == WAIT_OBJECT_0) {
            if (s->qCount > 0) {
                ev = s->q[s->qHead];
                s->qHead = (s->qHead + 1) % OUTQ_SIZE;
                s->qCount--;
                has = TRUE;
            }
            ReleaseMutex(s->hQMutex);
        }

        if (!has) continue;

        /* DEMO: lam cham phia gui de hang doi kip day */
        if (SENDER_DELAY_MS > 0) Sleep(SENDER_DELAY_MS);

        /* Chi gui khi dang co ket noi. ... */
        if (s->connected && s->hPipe != INVALID_HANDLE_VALUE) {
            int rc = FrameSend(s->hPipe, TRUE, ev.type, ev.seq, ev.payload, ev.len, IO_TIMEOUT_MS);
            if (rc != ERR_NONE) {
                LogMsg("Session %d: gui that bai (%s) -> danh dau mat ket noi",
                       s->sessionId, FrameErrName(rc));
                SessionMarkDisconnected(s);
            }
        }
        RingStore(s, &ev);

        /* Neu vua drop event -> bao FLOW_CONTROL cho client biet */
        if (InterlockedExchange(&s->flowPending, 0)) {
            char fc[128];
            sprintf(fc, "dropped=%ld|reason=outbound_queue_full|class=verbose",
                    s->droppedVerbose);
            InterlockedIncrement(&g_flowEvents);
            if (s->connected && s->hPipe != INVALID_HANDLE_VALUE) {
                FrameSend(s->hPipe, TRUE, MSG_FLOW_CONTROL,
                          (DWORD)InterlockedIncrement(&s->seqNext),
                          fc, (DWORD)strlen(fc), IO_TIMEOUT_MS);
            }
        }
    }
    return 0;
}

/* ==================================================================
 * PHAT LAI EVENT SAU KHI RESUME
 * ================================================================== */
static int SessionReplay(Session *s, DWORD lastSeq)
{
    int i, sent = 0;
    OutEvent snapshot[RESUME_RING];
    int count;

    if (WaitForSingleObject(s->hRingMutex, 2000) != WAIT_OBJECT_0) return 0;
    count = s->ringCount;
    for (i = 0; i < count; i++) {
        int idx = (s->ringPos - count + i + RESUME_RING * 2) % RESUME_RING;
        snapshot[i] = s->ring[idx];
    }
    ReleaseMutex(s->hRingMutex);

    for (i = 0; i < count; i++) {
        if (snapshot[i].seq <= lastSeq) continue;
        if (FrameSend(s->hPipe, TRUE, snapshot[i].type, snapshot[i].seq,
                      snapshot[i].payload, snapshot[i].len, IO_TIMEOUT_MS) == ERR_NONE)
            sent++;
    }
    return sent;
}

/* ==================================================================
 * THROTTLE
 * ================================================================== */
static ULONGLONG FtToULL(const FILETIME *ft)
{
    return ((ULONGLONG)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
}

static DWORD WINAPI ThrottleThread(LPVOID param)
{
    (void)param;
    while (WaitForSingleObject(g_hStopEvent, 2000) == WAIT_TIMEOUT) {
        FILETIME i1, k1, u1, i2, k2, u2;
        MEMORYSTATUSEX ms;
        ULONGLONG idle, kern, user, total;
        double cpu = 0.0;
        LONG newState;

        /* CPU khong co API tra ve "% hien tai". Phai LAY MAU 2 LAN roi
         * tinh hieu - dung nguyen ly da hoc o bai 2.2 va 3.2. */
        GetSystemTimes(&i1, &k1, &u1);
        Sleep(500);
        GetSystemTimes(&i2, &k2, &u2);

        idle = FtToULL(&i2) - FtToULL(&i1);
        kern = FtToULL(&k2) - FtToULL(&k1);
        user = FtToULL(&u2) - FtToULL(&u1);
        total = kern + user;   /* kernel DA bao gom idle, khong cong them */
        if (total > 0) cpu = (double)(total - idle) * 100.0 / (double)total;

        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);

        InterlockedExchange(&g_cpuPct, (LONG)cpu);
        InterlockedExchange(&g_ramPct, (LONG)ms.dwMemoryLoad);

        if (cpu > 90.0 || ms.dwMemoryLoad > 92)      newState = THR_OVERLOADED;
        else if (cpu > 70.0 || ms.dwMemoryLoad > 80) newState = THR_BUSY;
        else                                          newState = THR_IDLE;

        if (newState != g_throttle) {
            const char *names[] = { "IDLE", "BUSY", "OVERLOADED" };
            LogMsg("Throttle: %s -> %s (CPU %.0f%%, RAM %u%%)",
                   names[g_throttle], names[newState], cpu, ms.dwMemoryLoad);
            InterlockedExchange(&g_throttle, newState);
        }
    }
    return 0;
}

/* ==================================================================
 * TELEMETRY
 * ================================================================== */
static int CompareDouble(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

static DWORD WINAPI TelemetryThread(LPVOID param)
{
    (void)param;
    while (WaitForSingleObject(g_hStopEvent, 5000) == WAIT_TIMEOUT) {
        double sum = 0.0, avg = 0.0, p95 = 0.0;
        double copy[MAX_JOBS];
        int n, i;
        LONG hits = g_cacheHits, miss = g_cacheMiss;
        int hitPct = (hits + miss) > 0 ? (int)(hits * 100 / (hits + miss)) : 0;

        if (WaitForSingleObject(g_hTeleMutex, 2000) == WAIT_OBJECT_0) {
            n = (int)g_scanTimeCount;
            if (n > MAX_JOBS) n = MAX_JOBS;
            for (i = 0; i < n; i++) copy[i] = g_scanTimes[i];
            ReleaseMutex(g_hTeleMutex);
        } else n = 0;

        if (n > 0) {
            for (i = 0; i < n; i++) sum += copy[i];
            avg = sum / n;
            qsort(copy, n, sizeof(double), CompareDouble);
            /* p95 = "95% job nhanh hon con so nay". Dung p95 thay max
             * vi max de bi nhieu boi 1 truong hop ca biet. */
            p95 = copy[(int)(n * 0.95) >= n ? n - 1 : (int)(n * 0.95)];
        }

        LogMsg("[TELEMETRY] total=%ld done=%ld fail=%ld cancel=%ld | pending=%ld running=%ld "
               "| cacheHit=%d%% (%ld muc) | avg=%.0fms p95=%.0fms "
               "| dropped=%ld flow=%ld | crcErr=%ld hsFail=%ld denyPath=%ld denyRate=%ld resume=%ld "
               "| CPU=%ld%% RAM=%ld%%",
               g_totalJobs, g_doneJobs, g_failJobs, g_cancelJobs, g_pending, g_running,
               hitPct, g_cacheCount, avg, p95,
               g_droppedTotal, g_flowEvents, g_crcErrors, g_handshakeFails,
               g_policyDenies, g_rateDenies, g_resumeCount,
               g_cpuPct, g_ramPct);
    }
    return 0;
}

/* ==================================================================
 * REAPER - don session het han cho RESUME
 * ================================================================== */
static DWORD WINAPI ReaperThread(LPVOID param)
{
    (void)param;
    while (WaitForSingleObject(g_hStopEvent, 2000) == WAIT_TIMEOUT) {
        int i;
        for (i = 0; i < MAX_SESSIONS; i++) {
            Session *s = &g_sessions[i];
            if (!s->used || s->connected) continue;
            if (GetTickCount() - s->disconnectTick > SESSION_GRACE_MS) {
                LogMsg("Session %d het han RESUME -> giai phong", s->sessionId);
                SessionDestroy(s);
            }
        }
    }
    return 0;
}

/* ==================================================================
 * CALLBACK TIEN DO TU ENGINE
 * Chi day tin vao hang doi - KHONG cham vao pipe.
 * ================================================================== */
static void ProgressCb(int stage, int percent, void *userData)
{
    Job *job = (Job *)userData;
    Session *s;
    char buf[160];

    if (!job) return;
    s = SessionFind(job->sessionId);
    if (!s) return;

    sprintf(buf, "jobId=%d|stage=%d|percent=%d", job->jobId, stage, percent);
    /* PROGRESS la VERBOSE -> duoc phep bo khi hang doi day */
    SessionPush(s, MSG_PROGRESS, EVCLASS_VERBOSE, buf);
}

/* ==================================================================
 * WORKER THREAD
 * ================================================================== */
static DWORD WINAPI WorkerThread(LPVOID param)
{
    int id = (int)(INT_PTR)param;
    HANDLE waits[2];

    waits[0] = g_hJobSem;
    waits[1] = g_hStopEvent;

    LogMsg("Worker %d san sang", id);

    while (1) {
        Job *job = NULL;
        DWORD w;
        Session *s;
        WIN32_FILE_ATTRIBUTE_DATA fad;
        ULONGLONG size = 0;
        int verdict = VERDICT_SAFE;
        double score = 0.0;
        BOOL fromCache = FALSE;
        EngineResult er;
        char msg[900];
        DWORD t0;

        /* Cho DONG THOI 2 su kien: co job moi HOAC lenh dung.
         * Neu chi cho semaphore, luc dung service worker se ngu mai. */
        w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0 + 1) break;

        /* Lay job khoi hang doi */
        if (WaitForSingleObject(g_hQueueMutex, 5000) == WAIT_OBJECT_0) {
            if (g_qCount > 0) {
                int i;
                job = g_queue[0];
                for (i = 1; i < g_qCount; i++) g_queue[i - 1] = g_queue[i];
                g_qCount--;
                InterlockedDecrement(&g_pending);
            }
            ReleaseMutex(g_hQueueMutex);
        }
        if (!job) continue;

        if (job->cancelFlag) {
            InterlockedExchange(&job->state, JS_CANCELLED);
            InterlockedIncrement(&g_cancelJobs);
            s = SessionFind(job->sessionId);
            if (s) {
                sprintf(msg, "jobId=%d|state=CANCELLED", job->jobId);
                SessionPush(s, MSG_STATUS, EVCLASS_CRITICAL, msg);
            }
            continue;
        }

        /* --- Throttle: hoan job LOW khi may qua tai --- */
        if (g_throttle == THR_OVERLOADED && job->priority == PRIORITY_LOW) {
            s = SessionFind(job->sessionId);
            if (s) {
                sprintf(msg, "jobId=%d|reason=OVERLOADED|cpu=%ld|ram=%ld",
                        job->jobId, g_cpuPct, g_ramPct);
                SessionPush(s, MSG_DELAYED, EVCLASS_CRITICAL, msg);
            }
            /* Day lai cuoi hang doi */
            if (WaitForSingleObject(g_hQueueMutex, 5000) == WAIT_OBJECT_0) {
                if (g_qCount < MAX_JOBS) {
                    g_queue[g_qCount++] = job;
                    InterlockedIncrement(&g_pending);
                    ReleaseSemaphore(g_hJobSem, 1, NULL);
                }
                ReleaseMutex(g_hQueueMutex);
            }
            Sleep(500);
            continue;
        }

        InterlockedExchange(&job->state, JS_RUNNING);
        InterlockedIncrement(&g_running);
        t0 = GetTickCount();
        job->startTick = t0;
        s = SessionFind(job->sessionId);

        /* --- Lay metadata file de lam key cache --- */
        if (!GetFileAttributesExA(job->path, GetFileExInfoStandard, &fad)) {
            InterlockedExchange(&job->state, JS_FAILED);
            InterlockedIncrement(&g_failJobs);
            InterlockedDecrement(&g_running);
            if (s) {
                sprintf(msg, "%d|Khong mo duoc file: %s", ERR_ENGINE, job->path);
                SessionPush(s, MSG_ERROR, EVCLASS_CRITICAL, msg);
            }
            continue;
        }
        size = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;

        /* --- FAST PATH: tra cuu cache --- */
        if (CacheLookup(job->path, fad.ftLastWriteTime, size, &verdict, &score)) {
            fromCache = TRUE;
            /* Cache hit -> KHONG goi engine -> khong co callback ->
             * client se KHONG thay dong PROGRESS nao. Day la hien tuong
             * quan sat duoc de chung minh cache dang hoat dong. */
        } else {
            memset(&er, 0, sizeof(er));
            verdict = g_EngineScanEx(job->path, 0, ProgressCb, job, &er);
            score   = er.score;

            if (verdict == VERDICT_ERROR) {
                InterlockedExchange(&job->state, JS_FAILED);
                InterlockedIncrement(&g_failJobs);
                InterlockedDecrement(&g_running);
                if (s) {
                    sprintf(msg, "%d|Engine loi khi quet %s", ERR_ENGINE, job->path);
                    SessionPush(s, MSG_ERROR, EVCLASS_CRITICAL, msg);
                }
                continue;
            }

            CacheStore(job->path, fad.ftLastWriteTime, size, verdict, score);

            /* Gui thong tin PE chi tiet (VERBOSE - bo duoc neu ban) */
            if (s && er.isPe) {
                char pe[520];
                sprintf(pe, "jobId=%d|machine=%s|subsystem=%s|isDll=%d|isDriver=%d|"
                            "isManaged=%d|isSigned=%d|sign=%s|hasDebug=%d|hasRich=%d|"
                            "epRva=0x%X|imageBase=0x%llX|sections=%d",
                        job->jobId,
                        PeMachineName((WORD)er.machine),
                        PeSubsystemName((WORD)er.subsystem),
                        er.isDll, er.isDriver, er.isManaged, er.isSigned,
                        PeSignStateName(er.signState),
                        er.hasDebug, er.hasRichHeader,
                        er.entryPointRva, (unsigned long long)er.imageBase,
                        er.sectionCount);
                SessionPush(s, MSG_PEINFO, EVCLASS_VERBOSE, pe);
            }
        }

        /* --- Ghi telemetry --- */
        {
            double ms = (double)(GetTickCount() - t0);
            if (WaitForSingleObject(g_hTeleMutex, 2000) == WAIT_OBJECT_0) {
                LONG idx = g_scanTimeCount;
                if (idx < MAX_JOBS) { g_scanTimes[idx] = ms; g_scanTimeCount = idx + 1; }
                ReleaseMutex(g_hTeleMutex);
            }
        }

        job->verdict = verdict;
        job->score   = score;
        InterlockedExchange(&job->state, job->cancelFlag ? JS_CANCELLED : JS_DONE);
        InterlockedDecrement(&g_running);
        if (job->cancelFlag) InterlockedIncrement(&g_cancelJobs);
        else                 InterlockedIncrement(&g_doneJobs);

        /* --- Gui ket qua (CRITICAL - khong bao gio bi drop) --- */
        if (s) {
            const char *vn = (verdict == VERDICT_MALICIOUS) ? "MALICIOUS" :
                             (verdict == VERDICT_SUSPICIOUS) ? "SUSPICIOUS" : "SAFE";
            if (fromCache) {
                sprintf(msg, "jobId=%d|verdict=%s|score=%.1f|fromCache=1|detail=(ket qua tu cache)",
                        job->jobId, vn, score);
            } else {
                sprintf(msg, "jobId=%d|verdict=%s|score=%.1f|fromCache=0|pe=%s|detail=%.700s",
                        job->jobId, vn, score, er.peStatusText, er.detail);
            }
            SessionPush(s, MSG_RESULT, EVCLASS_CRITICAL, msg);
        }
    }

    LogMsg("Worker %d dung", id);
    return 0;
}

/* ==================================================================
 * TAO JOB
 * ================================================================== */
static int CreateJob(const char *path, int priority, int timeoutMs, int sessionId)
{
    int jobId;
    Job *job;
    int slot;

    /* InterlockedIncrement: phep ++ thong thuong gom 3 lenh may
     * (doc, cong, ghi). Hai luong co the cung doc gia tri 5 roi cung
     * ghi 6 -> TRUNG jobId. Lenh nguyen tu chong duoc dieu do. */
    jobId = (int)InterlockedIncrement(&g_jobCount);
    slot  = jobId % MAX_JOBS;
    job   = &g_jobs[slot];

    ZeroMemory(job, sizeof(Job));
    job->jobId     = jobId;
    strncpy(job->path, path, MAX_PATH - 1);
    job->priority  = priority;
    job->timeoutMs = timeoutMs;
    job->state     = JS_PENDING;
    job->sessionId = sessionId;

    if (WaitForSingleObject(g_hQueueMutex, 5000) != WAIT_OBJECT_0) return -1;

    if (g_qCount >= MAX_JOBS) { ReleaseMutex(g_hQueueMutex); return -1; }

    if (priority == PRIORITY_HIGH) {
        /* Chen len DAU hang doi: don moi phan tu lui 1 o.
         * Worker luon lay tu dau -> job HIGH ra truoc. */
        int i;
        for (i = g_qCount; i > 0; i--) g_queue[i] = g_queue[i - 1];
        g_queue[0] = job;
    } else {
        g_queue[g_qCount] = job;
    }
    g_qCount++;
    InterlockedIncrement(&g_pending);
    InterlockedIncrement(&g_totalJobs);

    ReleaseMutex(g_hQueueMutex);
    ReleaseSemaphore(g_hJobSem, 1, NULL);   /* "tieng chuong" danh thuc 1 worker */
    return jobId;
}

static Job *FindJob(int jobId)
{
    int slot = jobId % MAX_JOBS;
    if (g_jobs[slot].jobId == jobId) return &g_jobs[slot];
    return NULL;
}

/* ==================================================================
 * KIEM TRA DANH TINH CLIENT (handshake nghiem ngat)
 * ------------------------------------------------------------------
 * 5.1 tin hoan toan vao nhung gi client khai. 5.2 kiem chung:
 *   1. PID khai bao phai KHOP voi PID that cua process ben kia pipe
 *      (GetNamedPipeClientProcessId - kernel tra loi, khong the gia mao)
 *   2. Ten user phai khop voi token that
 *      (ImpersonateNamedPipeClient -> tam "khoac ao" client -> GetUserName)
 * ================================================================== */
static BOOL VerifyClientIdentity(HANDLE hPipe, DWORD claimedPid, const char *claimedUser,
                                 char *realUserOut, DWORD realUserSize)
{
    ULONG realPid = 0;
    char realUser[128] = {0};
    DWORD n = sizeof(realUser);
    BOOL ok = TRUE;

    /* --- Kiem PID --- */
    if (GetNamedPipeClientProcessId(hPipe, &realPid)) {
        if (claimedPid != 0 && realPid != claimedPid) {
            LogMsg("Handshake: PID khai %lu != PID that %lu -> TU CHOI", claimedPid, realPid);
            return FALSE;
        }
        /* Process phai con song */
        {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, realPid);
            if (!hProc) {
                LogMsg("Handshake: khong mo duoc process %lu -> TU CHOI", realPid);
                return FALSE;
            }
            CloseHandle(hProc);
        }
    }

    /* --- Kiem user qua impersonation --- */
    if (ImpersonateNamedPipeClient(hPipe)) {
        if (GetUserNameA(realUser, &n)) {
            strncpy(realUserOut, realUser, realUserSize - 1);
            realUserOut[realUserSize - 1] = '\0';
            if (claimedUser && claimedUser[0] && _stricmp(claimedUser, realUser) != 0) {
                LogMsg("Handshake: user khai '%s' != user that '%s' -> TU CHOI",
                       claimedUser, realUser);
                ok = FALSE;
            }
        }
        /* BAT BUOC: tra lai danh tinh cua service.
         * Quen RevertToSelf -> luong nay tiep tuc chay duoi quyen client,
         * co the mat quyen ghi log/mo file. Lo hong bao mat nghiem trong. */
        RevertToSelf();
    }

    return ok;
}

/* ==================================================================
 * LUONG PHUC VU 1 CLIENT
 * ================================================================== */
static DWORD WINAPI ClientThread(LPVOID param)
{
    HANDLE hPipe = (HANDLE)param;
    FrameReader fr;
    Session *sess = NULL;
    char value[MAX_VALUE_SIZE + 1];
    char reply[600];
    WORD type;
    DWORD seq, len;
    int rc;
    BOOL running = TRUE;

    FrameReaderInit(&fr, hPipe, TRUE);

    /* ---------- Tin dau tien BAT BUOC la HELLO hoac RESUME ---------- */
    rc = FrameRecv(&fr, &type, &seq, value, MAX_VALUE_SIZE, &len, 10000);
    if (rc != ERR_NONE) {
        if (rc == ERR_BAD_CHECKSUM) InterlockedIncrement(&g_crcErrors);
        LogMsg("Ket noi moi: doc that bai (%s)", FrameErrName(rc));
        sprintf(reply, "%d|%s", rc, FrameErrName(rc));
        FrameSend(hPipe, TRUE, MSG_ERROR, 0, reply, (DWORD)strlen(reply), IO_TIMEOUT_MS);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        return 0;
    }
    value[len] = '\0';

    /* ================= RESUME ================= */
    if (type == MSG_RESUME) {
        int sid = 0; DWORD lastSeq = 0;
        char *bar = strchr(value, '|');
        if (bar) { *bar = '\0'; lastSeq = (DWORD)atoi(bar + 1); }
        sid = atoi(value);

        sess = SessionFind(sid);
        if (!sess) {
            InterlockedIncrement(&g_handshakeFails);
            sprintf(reply, "%d|Session %d khong ton tai hoac da het han", ERR_SESSION_UNKNOWN, sid);
            FrameSend(hPipe, TRUE, MSG_ERROR, 0, reply, (DWORD)strlen(reply), IO_TIMEOUT_MS);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            return 0;
        }

        /* Gan pipe moi vao session cu */
        sess->hPipe = hPipe;
        InterlockedExchange(&sess->connected, 1);
        InterlockedIncrement(&g_resumeCount);

        sprintf(reply, "sessionId=%d|resumedFrom=%lu", sess->sessionId, lastSeq);
        FrameSend(hPipe, TRUE, MSG_RESUMED, 0, reply, (DWORD)strlen(reply), IO_TIMEOUT_MS);

        {
            int n = SessionReplay(sess, lastSeq);
            LogMsg("Session %d RESUME thanh cong, phat lai %d event (tu seq > %lu)",
                   sess->sessionId, n, lastSeq);
        }
    }
    /* ================= HELLO ================= */
    else if (type == MSG_HELLO) {
        char clientId[64] = "unknown", user[128] = "";
        DWORD pid = 0;
        char realUser[128] = "";
        char *p;

        /* Dinh dang: clientId|pid|user|version */
        p = strtok(value, "|");
        if (p) { strncpy(clientId, p, 63); clientId[63] = '\0'; }
        p = strtok(NULL, "|");
        if (p) pid = (DWORD)atoi(p);
        p = strtok(NULL, "|");
        if (p) { strncpy(user, p, 127); user[127] = '\0'; }

        if (!VerifyClientIdentity(hPipe, pid, user, realUser, sizeof(realUser))) {
            InterlockedIncrement(&g_handshakeFails);
            sprintf(reply, "%d|Xac thuc danh tinh that bai", ERR_HANDSHAKE);
            FrameSend(hPipe, TRUE, MSG_ERROR, 0, reply, (DWORD)strlen(reply), IO_TIMEOUT_MS);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            return 0;
        }

        sess = SessionCreate(hPipe);
        if (!sess) {
            sprintf(reply, "%d|Het cho session", ERR_PIPE);
            FrameSend(hPipe, TRUE, MSG_ERROR, 0, reply, (DWORD)strlen(reply), IO_TIMEOUT_MS);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            return 0;
        }
        strncpy(sess->clientId, clientId, 63);
        strncpy(sess->user, realUser[0] ? realUser : user, 127);
        sess->clientPid = pid;

        sprintf(reply, "sessionId=%d|serverVersion=%d|engineFp=0x%08X|"
                       "policy=denySystem32,rateLimit%.0f/s|maxValue=%d",
                sess->sessionId, g_EngineVer(), g_engineFingerprint,
                RATE_REFILL_PER_SEC, MAX_VALUE_SIZE);
        FrameSend(hPipe, TRUE, MSG_WELCOME, 0, reply, (DWORD)strlen(reply), IO_TIMEOUT_MS);

        LogMsg("Session %d mo: client='%s' pid=%lu user='%s'",
               sess->sessionId, sess->clientId, sess->clientPid, sess->user);
    }
    else {
        /* Tin dau tien khong phai HELLO/RESUME -> cat ket noi.
         * Muc dich handshake: xac nhan doi ben noi cung giao thuc. */
        InterlockedIncrement(&g_handshakeFails);
        sprintf(reply, "%d|Tin dau tien phai la HELLO hoac RESUME", ERR_HANDSHAKE);
        FrameSend(hPipe, TRUE, MSG_ERROR, 0, reply, (DWORD)strlen(reply), IO_TIMEOUT_MS);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        return 0;
    }

    /* ---------- Vong lap phuc vu ---------- */
    while (running && WaitForSingleObject(g_hStopEvent, 0) == WAIT_TIMEOUT) {
        rc = FrameRecv(&fr, &type, &seq, value, MAX_VALUE_SIZE, &len, 60000);

        if (rc == ERR_TIMEOUT) continue;          /* client im lang, cho tiep */
        if (rc == ERR_BAD_CHECKSUM) {
            InterlockedIncrement(&g_crcErrors);
            sprintf(reply, "%d|%s", ERR_BAD_CHECKSUM, FrameErrName(ERR_BAD_CHECKSUM));
            SessionPush(sess, MSG_ERROR, EVCLASS_CRITICAL, reply);
            continue;                              /* goi hong nhung con dong bo */
        }
        if (rc != ERR_NONE) {
            /* Mat ket noi hoac lech pha -> khong xoa session ngay,
             * giu 10s cho client RESUME. */
            LogMsg("Session %d: doc that bai (%s)", sess->sessionId, FrameErrName(rc));
            SessionMarkDisconnected(sess);
            return 0;
        }
        value[len] = '\0';

        switch (type) {
        case MSG_SCAN: {
            char path[MAX_PATH] = {0}, canon[MAX_PATH] = {0};
            int priority = PRIORITY_NORMAL, timeoutMs = 30000, jobId;
            char *p;

            p = strtok(value, "|");
            if (p) { strncpy(path, p, MAX_PATH - 1); }
            p = strtok(NULL, "|");
            if (p) priority = atoi(p);
            p = strtok(NULL, "|");
            if (p) timeoutMs = atoi(p);

            /* --- Policy 1: rate limit --- */
            if (!PolicyAllowRate(sess->clientId)) {
                sprintf(reply, "%d|Vuot gioi han toc do, thu lai sau", ERR_RATE_LIMITED);
                SessionPush(sess, MSG_ERROR, EVCLASS_CRITICAL, reply);
                break;
            }

            /* --- Policy 2: deny-list duong dan --- */
            if (!PolicyAllowPath(path, canon, sizeof(canon))) {
                InterlockedIncrement(&g_policyDenies);
                sprintf(reply, "%d|Duong dan bi chan boi policy: %s", ERR_POLICY_DENIED, canon);
                SessionPush(sess, MSG_ERROR, EVCLASS_CRITICAL, reply);
                LogMsg("Session %d: TU CHOI quet '%s' (deny-list)", sess->sessionId, canon);
                break;
            }

            jobId = CreateJob(canon, priority, timeoutMs, sess->sessionId);
            if (jobId < 0) {
                sprintf(reply, "%d|Hang doi day", ERR_PIPE);
                SessionPush(sess, MSG_ERROR, EVCLASS_CRITICAL, reply);
                break;
            }

            /* Tra ACCEPTED NGAY, truoc khi job duoc xu ly.
             * Day la kien truc bat dong bo: client biet jobId lien de
             * co the QUERY hoac CANCEL ve sau. */
            sprintf(reply, "jobId=%d|path=%s|priority=%d", jobId, canon, priority);
            SessionPush(sess, MSG_ACCEPTED, EVCLASS_CRITICAL, reply);
            break;
        }

        case MSG_QUERY: {
            int jobId = atoi(value);
            Job *j = FindJob(jobId);
            const char *st = "UNKNOWN";
            if (j) {
                switch (j->state) {
                    case JS_PENDING:   st = "PENDING";   break;
                    case JS_RUNNING:   st = "RUNNING";   break;
                    case JS_DONE:      st = "DONE";      break;
                    case JS_CANCELLED: st = "CANCELLED"; break;
                    case JS_FAILED:    st = "FAILED";    break;
                }
                sprintf(reply, "jobId=%d|state=%s|priority=%d|score=%.1f",
                        jobId, st, j->priority, j->score);
            } else {
                sprintf(reply, "jobId=%d|state=UNKNOWN", jobId);
            }
            SessionPush(sess, MSG_STATUS, EVCLASS_CRITICAL, reply);
            break;
        }

        case MSG_CANCEL: {
            int jobId = atoi(value);
            Job *j = FindJob(jobId);
            if (j && (j->state == JS_PENDING || j->state == JS_RUNNING)) {
                InterlockedExchange(&j->cancelFlag, 1);
                sprintf(reply, "jobId=%d|state=CANCEL_REQUESTED", jobId);
            } else {
                sprintf(reply, "jobId=%d|state=KHONG_HUY_DUOC", jobId);
            }
            SessionPush(sess, MSG_STATUS, EVCLASS_CRITICAL, reply);
            break;
        }

        case MSG_BYE:
            LogMsg("Session %d: client gui BYE", sess->sessionId);
            running = FALSE;
            break;

        default:
            sprintf(reply, "%d|Loai tin khong ho tro: 0x%04X", ERR_BAD_REQUEST, type);
            SessionPush(sess, MSG_ERROR, EVCLASS_CRITICAL, reply);
            break;
        }
    }

    /* Client dong tu te -> khong can giu cho RESUME */
    SessionDestroy(sess);
    return 0;
}

/* ==================================================================
 * TAO SECURITY DESCRIPTOR CHO PIPE
 * ------------------------------------------------------------------
 * 5.1 dung DACL = NULL, nghia la CHO PHEP TAT CA - bat ky ai tren may,
 * ke ca tai khoan Guest, cung ket noi va ra lenh quet duoc.
 *
 * 5.2 dung SDDL (Security Descriptor Definition Language) - cach viet
 * ACL bang chuoi, don gian hon nhieu so voi dung API ACL tho:
 *   D:            -> phan DACL
 *   (A;;GA;;;SY)  -> Allow, Generic All, cho SYSTEM
 *   (A;;GA;;;BA)  -> Allow, Generic All, cho Builtin Administrators
 *   (A;;0x12019B;;;IU) -> Allow doc/ghi cho Interactive Users
 *                          (dung nguoi dang dang nhap tren may - khop
 *                           yeu cau "chi user cung session")
 * ================================================================== */
static BOOL BuildPipeSecurity(SECURITY_ATTRIBUTES *sa, PSECURITY_DESCRIPTOR *psd)
{
    const char *sddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;IU)";

    *psd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl, SDDL_REVISION_1, psd, NULL)) {
        LogMsg("CANH BAO: khong tao duoc Security Descriptor (loi %lu), dung mac dinh",
               GetLastError());
        return FALSE;
    }

    ZeroMemory(sa, sizeof(SECURITY_ATTRIBUTES));
    sa->nLength = sizeof(SECURITY_ATTRIBUTES);
    sa->lpSecurityDescriptor = *psd;
    sa->bInheritHandle = FALSE;

    LogMsg("Pipe security: SDDL = %s", sddl);
    LogMsg("  SY = SYSTEM (toan quyen) | BA = Administrators (toan quyen)");
    LogMsg("  IU = Interactive Users (doc/ghi) | KHONG co Everyone");

    return TRUE;
}

/* ==================================================================
 * LUONG PIPE SERVER
 * ================================================================== */
static DWORD WINAPI PipeServerThread(LPVOID param)
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR psd = NULL;
    BOOL haveSa;

    (void)param;
    haveSa = BuildPipeSecurity(&sa, &psd);

    LogMsg("Pipe server lang nghe tai %s", PIPE_NAME);

    while (WaitForSingleObject(g_hStopEvent, 0) == WAIT_TIMEOUT) {
        HANDLE hPipe;
        OVERLAPPED ov;
        HANDLE hEv;
        BOOL connected = FALSE;

        hPipe = CreateNamedPipeA(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,   /* BYTE mode: ta tu framing */
            PIPE_UNLIMITED_INSTANCES,
            65536, 65536,        /* buffer lon de giam kha nang day */
            0,
            haveSa ? &sa : NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            LogMsg("LOI: CreateNamedPipe that bai (%lu)", GetLastError());
            Sleep(1000);
            continue;
        }

        /* Cho ket noi kieu overlapped de con thoat duoc khi dung service */
        hEv = CreateEventA(NULL, TRUE, FALSE, NULL);
        ZeroMemory(&ov, sizeof(ov));
        ov.hEvent = hEv;

        if (!ConnectNamedPipe(hPipe, &ov)) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                HANDLE waits[2] = { hEv, g_hStopEvent };
                DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
                if (w == WAIT_OBJECT_0) connected = TRUE;
                else { CancelIo(hPipe); CloseHandle(hEv); CloseHandle(hPipe); break; }
            } else if (err == ERROR_PIPE_CONNECTED) {
                connected = TRUE;
            }
        } else connected = TRUE;

        CloseHandle(hEv);

        if (connected) {
            HANDLE hT = CreateThread(NULL, 0, ClientThread, hPipe, 0, NULL);
            if (hT) CloseHandle(hT);
            else { DisconnectNamedPipe(hPipe); CloseHandle(hPipe); }
        } else {
            CloseHandle(hPipe);
        }
    }

    if (psd) LocalFree(psd);
    LogMsg("Pipe server dung");
    return 0;
}

/* ==================================================================
 * KHOI DONG / DUNG HE THONG
 * ================================================================== */
static BOOL StartEngineSystem(void)
{
    int i;

    g_hLogMutex   = CreateMutexA(NULL, FALSE, NULL);
    g_hQueueMutex = CreateMutexA(NULL, FALSE, NULL);
    g_hCacheMutex = CreateMutexA(NULL, FALSE, NULL);
    g_hTeleMutex  = CreateMutexA(NULL, FALSE, NULL);
    g_hSessMutex  = CreateMutexA(NULL, FALSE, NULL);
    g_hRateMutex  = CreateMutexA(NULL, FALSE, NULL);
    g_hJobSem     = CreateSemaphoreA(NULL, 0, MAX_JOBS, NULL);
    g_hStopEvent  = CreateEventA(NULL, TRUE, FALSE, NULL);

    if (!LoadEngine()) return FALSE;

    if (!CacheInit()) { LogMsg("LOI: khong cap phat duoc cache"); return FALSE; }
    CacheLoad();

    for (i = 0; i < MAX_WORKERS; i++)
        g_hWorkers[i] = CreateThread(NULL, 0, WorkerThread, (LPVOID)(INT_PTR)i, 0, NULL);

    g_hThrottleThread = CreateThread(NULL, 0, ThrottleThread,   NULL, 0, NULL);
    g_hTeleThread     = CreateThread(NULL, 0, TelemetryThread,  NULL, 0, NULL);
    g_hReaperThread   = CreateThread(NULL, 0, ReaperThread,     NULL, 0, NULL);
    g_hPipeThread     = CreateThread(NULL, 0, PipeServerThread, NULL, 0, NULL);

    LogMsg("Service 5.2 san sang (%d worker, cache %d o, TTL %ds)",
           MAX_WORKERS, CACHE_BUCKETS, CACHE_TTL_SEC);
    return TRUE;
}

static void StopEngineSystem(void)
{
    int i;
    LogMsg("Dang dung service...");

    SetEvent(g_hStopEvent);
    ReleaseSemaphore(g_hJobSem, MAX_WORKERS, NULL);

    /* Danh thuc PipeServerThread dang ket trong ConnectNamedPipe bang
     * cach GIA VO lam client ket noi vao. Thu thuat rat thuc dung:
     * khong co cach nao khac de go mot luong dang cho ket noi. */
    {
        HANDLE h = CreateFileA(PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }

    for (i = 0; i < MAX_WORKERS; i++)
        if (g_hWorkers[i]) { WaitForSingleObject(g_hWorkers[i], 5000); CloseHandle(g_hWorkers[i]); }

    if (g_hPipeThread)     { WaitForSingleObject(g_hPipeThread, 5000);     CloseHandle(g_hPipeThread); }
    if (g_hThrottleThread) { WaitForSingleObject(g_hThrottleThread, 5000); CloseHandle(g_hThrottleThread); }
    if (g_hTeleThread)     { WaitForSingleObject(g_hTeleThread, 5000);     CloseHandle(g_hTeleThread); }
    if (g_hReaperThread)   { WaitForSingleObject(g_hReaperThread, 5000);   CloseHandle(g_hReaperThread); }

    for (i = 0; i < MAX_SESSIONS; i++)
        if (g_sessions[i].used) SessionDestroy(&g_sessions[i]);

    CacheSave();

    /* Thu tu BAT BUOC: cho engine tu don truoc, roi moi go DLL.
     * Nguoc lai se crash vi con tro ham tro vao vung da bi go. */
    if (g_EngineStop) g_EngineStop();
    if (g_hEngine)    FreeLibrary(g_hEngine);

    if (g_cache) { free(g_cache); g_cache = NULL; }

    LogMsg("Service da dung.");

    if (g_hStopEvent)  CloseHandle(g_hStopEvent);
    if (g_hJobSem)     CloseHandle(g_hJobSem);
    if (g_hQueueMutex) CloseHandle(g_hQueueMutex);
    if (g_hCacheMutex) CloseHandle(g_hCacheMutex);
    if (g_hTeleMutex)  CloseHandle(g_hTeleMutex);
    if (g_hSessMutex)  CloseHandle(g_hSessMutex);
    if (g_hRateMutex)  CloseHandle(g_hRateMutex);
    if (g_hLogMutex)   CloseHandle(g_hLogMutex);
}

/* ==================================================================
 * CHE DO CONSOLE
 * ================================================================== */
static int RunAsConsole(void)
{
    g_consoleMode = 1;
    printf("========== AV SCAN SERVICE 5.2 (Console) ==========\n\n");

    if (!StartEngineSystem()) {
        printf("\nKhoi dong that bai. Xem %s\n", g_logPath);
        return 1;
    }

    printf("\nNhan ENTER de dung service...\n\n");
    getchar();

    StopEngineSystem();
    return 0;
}

/* ==================================================================
 * CHE DO WINDOWS SERVICE
 * ================================================================== */
static void ReportSvcStatus(DWORD state, DWORD exitCode, DWORD waitHint)
{
    static DWORD checkPoint = 1;

    g_svcStatus.dwCurrentState  = state;
    g_svcStatus.dwWin32ExitCode = exitCode;
    g_svcStatus.dwWaitHint      = waitHint;

    g_svcStatus.dwControlsAccepted =
        (state == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED)
        g_svcStatus.dwCheckPoint = 0;
    else
        g_svcStatus.dwCheckPoint = checkPoint++;

    SetServiceStatus(g_svcStatusHandle, &g_svcStatus);
}

static void WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    switch (ctrlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 15000);
            if (g_hSvcStopEvent) SetEvent(g_hSvcStopEvent);
            break;
        default:
            break;
    }
}

static void WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
    (void)argc; (void)argv;

    g_svcStatusHandle = RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_svcStatusHandle) return;

    ZeroMemory(&g_svcStatus, sizeof(g_svcStatus));
    g_svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 10000);

    g_hSvcStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_hSvcStopEvent) { ReportSvcStatus(SERVICE_STOPPED, GetLastError(), 0); return; }

    /* Service chay trong Session 0 - phien khong co man hinh.
     * Moi printf bay vao hu vo. Vi vay LogMsg luon ghi ra FILE. */
    g_consoleMode = 0;

    if (!StartEngineSystem()) {
        ReportSvcStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
    LogMsg("Chay o che do Windows Service.");

    WaitForSingleObject(g_hSvcStopEvent, INFINITE);

    StopEngineSystem();
    CloseHandle(g_hSvcStopEvent);
    ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

static int RunAsService(void)
{
    SERVICE_TABLE_ENTRYA table[] = {
        { (LPSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)ServiceMain },
        { NULL, NULL }
    };
    if (!StartServiceCtrlDispatcherA(table)) {
        printf("Loi: lenh 'runservice' chi danh cho SCM goi.\n");
        printf("Muon chay trong cua so nay, dung: service.exe console\n");
        return 1;
    }
    return 0;
}

/* ==================================================================
 * QUAN LY SERVICE
 * ================================================================== */
static void PrintErr(const char *what)
{
    DWORD e = GetLastError();
    char *msg = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                   FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, e, 0, (LPSTR)&msg, 0, NULL);
    printf("%s that bai. Ma loi %lu: %s\n", what, e, msg ? msg : "(khong ro)");
    if (msg) LocalFree(msg);
}

static int InstallService(void)
{
    SC_HANDLE scm, svc;
    char binPath[MAX_PATH + 32];
    char exePath[MAX_PATH];
    SERVICE_FAILURE_ACTIONSA sfa;
    SC_ACTION actions[3];
    int i;

    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    /* CANH BAO: duong dan chua ky tu ngoai ASCII se pha BINARY_PATH_NAME.
     * Day la loi da gap o bai 3.2 - service cai duoc nhung khong khoi
     * dong duoc voi ma loi 2 (khong tim thay file). */
    for (i = 0; exePath[i]; i++) {
        if ((unsigned char)exePath[i] > 127) {
            printf("LOI: duong dan chua ky tu khong phai ASCII:\n  %s\n", exePath);
            printf("Hay chuyen chuong trinh sang thu muc nhu D:\\AvScan52\\bin\\\n");
            return 1;
        }
    }

    sprintf(binPath, "\"%s\" runservice", exePath);

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { PrintErr("OpenSCManager"); return 1; }

    svc = CreateServiceA(scm, SERVICE_NAME, SERVICE_DISPLAY,
                         SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                         SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                         binPath, NULL, NULL, NULL, NULL, NULL);
    if (!svc) { PrintErr("CreateService"); CloseServiceHandle(scm); return 1; }

    /* Tu khoi dong lai neu bi kill - dac quyen cua Windows Service */
    actions[0].Type = SC_ACTION_RESTART; actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART; actions[1].Delay = 5000;
    actions[2].Type = SC_ACTION_NONE;    actions[2].Delay = 0;

    ZeroMemory(&sfa, sizeof(sfa));
    sfa.dwResetPeriod = 86400;
    sfa.cActions      = 3;
    sfa.lpsaActions   = actions;
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

    printf("Da cai dat '%s'.\n", SERVICE_DISPLAY);
    printf("Duong dan: %s\n", binPath);
    printf("Chay: service.exe start\n");

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int UninstallService(void)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS st;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { PrintErr("OpenSCManager"); return 1; }

    svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (!svc) { PrintErr("OpenService"); CloseServiceHandle(scm); return 1; }

    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    Sleep(1000);

    if (DeleteService(svc)) printf("Da go '%s'.\n", SERVICE_DISPLAY);
    else PrintErr("DeleteService");

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int StartSvc(void)
{
    SC_HANDLE scm, svc;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { PrintErr("OpenSCManager"); return 1; }
    svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_START);
    if (!svc) { PrintErr("OpenService"); CloseServiceHandle(scm); return 1; }
    if (StartServiceA(svc, 0, NULL)) printf("Da gui lenh START.\n");
    else PrintErr("StartService");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int StopSvc(void)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS st;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { PrintErr("OpenSCManager"); return 1; }
    svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_STOP);
    if (!svc) { PrintErr("OpenService"); CloseServiceHandle(scm); return 1; }
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) printf("Da gui lenh STOP.\n");
    else PrintErr("ControlService");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int ShowStatus(void)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;
    const char *name = "?";

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { PrintErr("OpenSCManager"); return 1; }
    svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!svc) {
        printf("Service '%s' chua duoc cai dat.\n", SERVICE_NAME);
        CloseServiceHandle(scm);
        return 1;
    }

    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        switch (ssp.dwCurrentState) {
            case SERVICE_STOPPED:          name = "STOPPED";          break;
            case SERVICE_START_PENDING:    name = "START_PENDING";    break;
            case SERVICE_STOP_PENDING:     name = "STOP_PENDING";     break;
            case SERVICE_RUNNING:          name = "RUNNING";          break;
            default:                       name = "OTHER";            break;
        }
        printf("Trang thai: %s   (PID = %lu)\n", name, ssp.dwProcessId);
    } else PrintErr("QueryServiceStatusEx");

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static void ShowMenu(void)
{
    printf("========== AV SCAN SERVICE 5.2 ==========\n\n");
    printf("  service.exe console      - chay trong cua so nay (de xem log)\n");
    printf("  service.exe install      - dang ky voi Windows (can quyen Admin)\n");
    printf("  service.exe uninstall    - go dang ky\n");
    printf("  service.exe start        - khoi dong service\n");
    printf("  service.exe stop         - dung service\n");
    printf("  service.exe status       - xem trang thai\n\n");
    printf("Thu muc lam viec : %s\n", g_exeDir);
    printf("Engine           : %s\n", g_enginePath);
    printf("Log              : %s\n", g_logPath);
    printf("Cache            : %s\n\n", g_cachePath);
    printf("Theo doi log thoi gian thuc (PowerShell):\n");
    printf("  Get-Content \"%s\" -Wait -Tail 30\n\n", g_logPath);
}

/* ==================================================================
 * MAIN
 * ================================================================== */
int main(int argc, char *argv[])
{
    InitPaths();

    if (argc < 2) { ShowMenu(); return 0; }

    if      (_stricmp(argv[1], "console")    == 0) return RunAsConsole();
    else if (_stricmp(argv[1], "runservice") == 0) return RunAsService();
    else if (_stricmp(argv[1], "install")    == 0) return InstallService();
    else if (_stricmp(argv[1], "uninstall")  == 0) return UninstallService();
    else if (_stricmp(argv[1], "start")      == 0) return StartSvc();
    else if (_stricmp(argv[1], "stop")       == 0) return StopSvc();
    else if (_stricmp(argv[1], "status")     == 0) return ShowStatus();

    printf("Tham so khong hop le: %s\n\n", argv[1]);
    ShowMenu();
    return 1;
}
