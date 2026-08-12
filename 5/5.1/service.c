#define _CRT_SECURE_NO_WARNINGS
/*
 * service.c - Scan Service (bai 5.1) - HO TRO 2 CHE DO
 * ===================================================================
 * CHE DO 1: Console Service  -> chay nhu .exe thuong, thay log truc tiep
 * CHE DO 2: Windows Service  -> SCM quan ly, chay nen, tu khoi dong lai
 *
 * Cach dung:
 *   service.exe                -> hien MENU chon che do
 *   service.exe console        -> chay Console Service
 *   service.exe install        -> cai dat Windows Service (can Admin)
 *   service.exe uninstall      -> go bo Windows Service
 *   service.exe start          -> khoi dong Windows Service
 *   service.exe stop           -> dung Windows Service
 *   service.exe status         -> xem trang thai
 *   service.exe runservice     -> (SCM goi, nguoi dung KHONG go)
 * ===================================================================
 * 5 module:
 *   a) Pipe Server & Protocol  - Named Pipe + TLV + handshake
 *   b) Job Queue + Worker Pool - hang doi job, worker xu ly, jobId
 *   c) Throttle                - do CPU/RAM, may trang thai IDLE/BUSY/OVERLOADED
 *   d) Cache                   - key path+time+size, TTL 10 phut, thread-safe
 *   e) Telemetry               - thong ke, ghi log
 *
 * Nap engine.dll dong (LoadLibrary + GetProcAddress).
 *
 * Build: Console Application (.exe), x64.
 *   Link: Advapi32.lib (da co #pragma comment ben duoi).
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "protocol.h"

/* Advapi32: cac ham quan ly service (OpenSCManager, CreateService...)
   va bao mat (InitializeSecurityDescriptor, SetSecurityDescriptorDacl) */
#pragma comment(lib, "Advapi32.lib")

/* ================= Cau hinh ================= */
#define MAX_WORKERS      4
#define MAX_JOBS         1000
#define MAX_CACHE        512
#define CACHE_TTL_SEC    600      /* 10 phut */
#define ENGINE_DLL_NAME  "engine.dll"
#define LOG_FILE_NAME    "service.log"
#define DIAG_FLAG_NAME   "diag.on"

/* Ten dang ky voi SCM (che do Windows Service) */
#define SVC_NAME         "AvScanSvc"
#define SVC_DISPLAY      "AV Scan Service (Bai 5.1)"

/* ================= Con tro ham engine (nap dong) ================= */
typedef void (*ProgressCallback)(int stage, int percent, void *userData);
typedef int  (*FnEngineInitialize)(const char *);
typedef int  (*FnEngineScanFile)(const char *, int, ProgressCallback, void *);
typedef int  (*FnEngineGetVersion)(void);
typedef void (*FnEngineShutdown)(void);

static HMODULE            g_hEngine = NULL;
static FnEngineInitialize g_EngineInit = NULL;
static FnEngineScanFile   g_EngineScan = NULL;
static FnEngineGetVersion g_EngineVer  = NULL;
static FnEngineShutdown   g_EngineShutdown = NULL;

/* ================= Trang thai job ================= */
#define JOB_PENDING    0
#define JOB_RUNNING    1
#define JOB_DONE       2
#define JOB_CANCELLED  3
#define JOB_DELAYED    4

typedef struct {
    int      jobId;
    char     path[MAX_PATH];
    int      priority;
    int      timeoutMs;
    volatile LONG state;
    int      verdict;
    BOOL     fromCache;
    HANDLE   hClientPipe;   /* pipe de gui progress/result ve dung client */
    HANDLE   hPipeWriteMutex; /* khoa ghi pipe (nhieu luong cung ghi 1 pipe) */
} Job;

/* ================= Hang doi job ================= */
static Job   g_jobs[MAX_JOBS];
static volatile LONG g_jobCount = 0;    /* tong so job da tao (cung la jobId ke tiep) */
static int   g_queue[MAX_JOBS];         /* hang doi chua chi so job */
static volatile LONG g_qHead = 0, g_qTail = 0;
static HANDLE g_hQueueMutex = NULL;
static HANDLE g_hJobSem     = NULL;     /* dem so job trong hang doi */

/* ================= Cache ================= */
typedef struct {
    char      path[MAX_PATH];
    FILETIME  lastWrite;
    ULONGLONG size;
    int       verdict;
    time_t    cachedAt;
    BOOL      used;
} CacheEntry;

static CacheEntry g_cache[MAX_CACHE];
static HANDLE g_hCacheMutex = NULL;

/* ================= Throttle ================= */
#define STATE_IDLE       0
#define STATE_BUSY       1
#define STATE_OVERLOADED 2
static volatile LONG g_systemState = STATE_IDLE;

/* ================= Telemetry ================= */
static volatile LONG g_totalJobs   = 0;
static volatile LONG g_doneJobs    = 0;
static volatile LONG g_failedJobs  = 0;
static volatile LONG g_cancelJobs  = 0;
static volatile LONG g_cacheHits   = 0;
static volatile LONG g_pendingJobs = 0;
static volatile LONG g_runningJobs = 0;
static double g_scanTimes[MAX_JOBS];    /* thoi gian quet tung job (ms) */
static volatile LONG g_scanTimeCount = 0;
static HANDLE g_hTelemetryMutex = NULL;

/* ================= Dieu khien chung ================= */
static HANDLE g_hStopEvent = NULL;
static volatile LONG g_running = 1;
static HANDLE g_hLogMutex = NULL;      /* tao 1 lan trong main, tranh race */
static int    g_diag = 0;              /* 1 = in log chan doan tung buoc */

/* ---- Duong dan TUYET DOI (bat buoc cho che do Windows Service) ----
   SCM khoi dong service voi thu muc lam viec la C:\Windows\System32,
   nen moi duong dan tuong doi deu sai. Phai tu tinh duong dan that. */
static char g_exeDir[MAX_PATH]     = "";
static char g_exePath[MAX_PATH]    = "";
static char g_enginePath[MAX_PATH] = "";
static char g_logPath[MAX_PATH]    = "";
static char g_diagPath[MAX_PATH]   = "";

/* 1 = che do console (co man hinh), 0 = Windows Service (khong man hinh) */
static int g_consoleMode = 1;

/* ---- Bien danh cho che do Windows Service ---- */
static SERVICE_STATUS        g_SvcStatus       = {0};
static SERVICE_STATUS_HANDLE g_SvcStatusHandle = NULL;
static HANDLE                g_hSvcStopEvent   = NULL;

/* ==================================================================
 * TIEN ICH: ghi log ra file (co khoa de nhieu luong ghi an toan)
 * ================================================================== */
/* ==================================================================
 * TINH DUONG DAN TUYET DOI - GOI DAU TIEN TRONG main()
 * ------------------------------------------------------------------
 * Lay duong dan cua chinh file .exe, cat bo ten file de duoc thu muc,
 * roi ghep ra duong dan engine.dll / service.log / diag.on.
 * Nho vay ca 2 che do deu tim dung file, du thu muc lam viec khac nhau.
 * ================================================================== */
static void InitPaths(void)
{
    char *lastSlash;

    GetModuleFileNameA(NULL, g_exePath, MAX_PATH);   /* vd: C:\AvScanSvc\service.exe */
    strcpy(g_exeDir, g_exePath);

    lastSlash = strrchr(g_exeDir, '\\');            /* tim dau '\' cuoi cung */
    if (lastSlash) *lastSlash = '\0';                /* cat bo ten file */

    snprintf(g_enginePath, MAX_PATH, "%s\\%s", g_exeDir, ENGINE_DLL_NAME);
    snprintf(g_logPath,    MAX_PATH, "%s\\%s", g_exeDir, LOG_FILE_NAME);
    snprintf(g_diagPath,   MAX_PATH, "%s\\%s", g_exeDir, DIAG_FLAG_NAME);
}

/* Bat che do chan doan neu: co bien moi truong AVSCAN_DIAG=1 (console)
   HOAC co file diag.on trong thu muc .exe (dung duoc ca 2 che do). */
static void InitDiagFlag(void)
{
    char envBuf[8];
    if (GetEnvironmentVariableA("AVSCAN_DIAG", envBuf, sizeof(envBuf)) > 0 && envBuf[0] == '1')
        g_diag = 1;
    if (GetFileAttributesA(g_diagPath) != INVALID_FILE_ATTRIBUTES)
        g_diag = 1;
}

static void LogMsg(const char *fmt, ...)
{
    char buf[512];
    va_list args;
    time_t now;
    struct tm lt;
    char timeStr[32];
    FILE *f;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    now = time(NULL);
    /* localtime() KHONG an toan da luong (tra ve buffer tinh dung chung).
       Dung localtime_s de moi luong co ban sao rieng. */
    if (localtime_s(&lt, &now) != 0) strcpy(timeStr, "??:??:??");
    else strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &lt);

    /* Timeout 3 giay: neu khong lay duoc khoa thi van in, khong treo luong */
    if (g_hLogMutex && WaitForSingleObject(g_hLogMutex, 3000) == WAIT_OBJECT_0) {
        /* Che do Windows Service chay trong Session 0 - KHONG CO man hinh,
           printf se bay vao hu vo. Chi in khi o che do console. */
        if (g_consoleMode) printf("[%s] %s\n", timeStr, buf);
        f = fopen(g_logPath, "a");           /* LUON ghi ra file */
        if (f) { fprintf(f, "[%s] %s\n", timeStr, buf); fclose(f); }
        ReleaseMutex(g_hLogMutex);
    } else {
        if (g_consoleMode) printf("[%s] %s\n", timeStr, buf);
    }
}

/* ==================================================================
 * NAP ENGINE DLL DONG
 * ================================================================== */
static BOOL LoadEngine(void)
{
    /* Dung duong dan TUYET DOI, khong dung "engine.dll" tuong doi:
       o che do Windows Service, thu muc lam viec la C:\Windows\System32. */
    g_hEngine = LoadLibraryA(g_enginePath);
    if (!g_hEngine) {
        LogMsg("Loi: khong nap duoc %s (ma loi %lu)", g_enginePath, GetLastError());
        return FALSE;
    }

    g_EngineInit     = (FnEngineInitialize)GetProcAddress(g_hEngine, "EngineInitialize");
    g_EngineScan     = (FnEngineScanFile)  GetProcAddress(g_hEngine, "EngineScanFile");
    g_EngineVer      = (FnEngineGetVersion)GetProcAddress(g_hEngine, "EngineGetVersion");
    g_EngineShutdown = (FnEngineShutdown)  GetProcAddress(g_hEngine, "EngineShutdown");

    if (!g_EngineInit || !g_EngineScan || !g_EngineVer || !g_EngineShutdown) {
        LogMsg("Loi: thieu ham export trong engine.dll");
        return FALSE;
    }

    g_EngineInit("{}");   /* khoi tao voi config rong */
    LogMsg("Da nap engine.dll, phien ban = %d", g_EngineVer());
    return TRUE;
}

/* ==================================================================
 * MODULE d) CACHE - tra va ghi (thread-safe)
 * ================================================================== */
/* Tim trong cache: tra ve verdict neu hit (chua het TTL, file khong doi) */
static BOOL CacheLookup(const char *path, FILETIME lastWrite, ULONGLONG size, int *outVerdict)
{
    int i;
    BOOL hit = FALSE;
    time_t now = time(NULL);

    if (WaitForSingleObject(g_hCacheMutex, 5000) != WAIT_OBJECT_0) { LogMsg("  [CANH BAO] timeout cache mutex"); return hit; }
    for (i = 0; i < MAX_CACHE; i++) {
        if (g_cache[i].used &&
            strcmp(g_cache[i].path, path) == 0 &&
            g_cache[i].size == size &&
            CompareFileTime(&g_cache[i].lastWrite, &lastWrite) == 0) {
            /* Kiem tra TTL */
            if (now - g_cache[i].cachedAt <= CACHE_TTL_SEC) {
                *outVerdict = g_cache[i].verdict;
                hit = TRUE;
            }
            break;
        }
    }
    ReleaseMutex(g_hCacheMutex);
    return hit;
}

/* Ghi ket qua vao cache (tim o trong hoac ghi de o cu nhat) */
static void CacheStore(const char *path, FILETIME lastWrite, ULONGLONG size, int verdict)
{
    int i, slot = -1;
    time_t oldest = 0;

    if (WaitForSingleObject(g_hCacheMutex, 5000) != WAIT_OBJECT_0) { LogMsg("  [CANH BAO] timeout cache mutex (store)"); return; }
    /* Tim o trong truoc */
    for (i = 0; i < MAX_CACHE; i++) {
        if (!g_cache[i].used) { slot = i; break; }
    }
    /* Khong con o trong -> ghi de o cu nhat */
    if (slot == -1) {
        slot = 0;
        oldest = g_cache[0].cachedAt;
        for (i = 1; i < MAX_CACHE; i++) {
            if (g_cache[i].cachedAt < oldest) { oldest = g_cache[i].cachedAt; slot = i; }
        }
    }
    strcpy(g_cache[slot].path, path);
    g_cache[slot].lastWrite = lastWrite;
    g_cache[slot].size      = size;
    g_cache[slot].verdict   = verdict;
    g_cache[slot].cachedAt  = time(NULL);
    g_cache[slot].used      = TRUE;
    ReleaseMutex(g_hCacheMutex);
}

/* ==================================================================
 * MODULE c) THROTTLE - do CPU/RAM, cap nhat trang thai
 * ================================================================== */
static ULONGLONG FtToULL(const FILETIME *ft) {
    return ((ULONGLONG)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
}

static DWORD WINAPI ThrottleThread(LPVOID param)
{
    FILETIME idle1, kern1, user1, idle2, kern2, user2;
    (void)param;

    while (g_running) {
        MEMORYSTATUSEX mem = {0};
        double cpu;
        ULONGLONG idle, kern, user, total;

        /* Do CPU: lay mau 2 lan cach nhau 500ms */
        GetSystemTimes(&idle1, &kern1, &user1);
        Sleep(500);
        GetSystemTimes(&idle2, &kern2, &user2);

        idle = FtToULL(&idle2) - FtToULL(&idle1);
        kern = FtToULL(&kern2) - FtToULL(&kern1);
        user = FtToULL(&user2) - FtToULL(&user1);
        total = kern + user;
        cpu = (total > 0) ? (double)(total - idle) * 100.0 / (double)total : 0.0;

        /* Do RAM */
        mem.dwLength = sizeof(mem);
        GlobalMemoryStatusEx(&mem);

        /* May trang thai */
        if (cpu > 90.0 || mem.dwMemoryLoad > 90) {
            InterlockedExchange(&g_systemState, STATE_OVERLOADED);
        } else if (cpu > 70.0 || mem.dwMemoryLoad > 75) {
            InterlockedExchange(&g_systemState, STATE_BUSY);
        } else {
            InterlockedExchange(&g_systemState, STATE_IDLE);
        }

        Sleep(1000);   /* cap nhat moi ~1.5s */
    }
    return 0;
}

/* ==================================================================
 * MODULE e) TELEMETRY - dinh ky ghi thong ke
 * ================================================================== */
static int CompareDouble(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da < db) ? -1 : (da > db) ? 1 : 0;
}

static DWORD WINAPI TelemetryThread(LPVOID param)
{
    (void)param;
    while (g_running) {
        int i;
        double sum = 0, avg = 0, p95 = 0;
        LONG n;

        Sleep(5000);   /* moi 5 giay ghi 1 lan */

        WaitForSingleObject(g_hTelemetryMutex, INFINITE);
        n = g_scanTimeCount;
        if (n > 0) {
            double *copy = (double *)malloc(n * sizeof(double));
            if (copy) {
                for (i = 0; i < n; i++) { copy[i] = g_scanTimes[i]; sum += copy[i]; }
                avg = sum / n;
                qsort(copy, n, sizeof(double), CompareDouble);
                p95 = copy[(int)(n * 0.95)];   /* phan vi thu 95 */
                free(copy);
            }
        }
        ReleaseMutex(g_hTelemetryMutex);

        {
            double hitRate = (g_totalJobs > 0) ? (double)g_cacheHits * 100.0 / g_totalJobs : 0.0;
            const char *stateName = (g_systemState == STATE_OVERLOADED) ? "OVERLOADED" :
                                    (g_systemState == STATE_BUSY) ? "BUSY" : "IDLE";
            LogMsg("[TELEMETRY] state=%s total=%ld done=%ld fail=%ld cancel=%ld "
                   "cacheHit=%.1f%% pending=%ld running=%ld avg=%.1fms p95=%.1fms",
                   stateName, g_totalJobs, g_doneJobs, g_failedJobs, g_cancelJobs,
                   hitRate, g_pendingJobs, g_runningJobs, avg, p95);
        }
    }
    return 0;
}

/* ==================================================================
 * TANG GIAO TIEP PIPE BAT DONG BO (OVERLAPPED I/O)
 * ------------------------------------------------------------------
 * Voi pipe thuong (PIPE_WAIT), WriteFile KHONG CO cach dat timeout.
 * Neu client cham doc -> WriteFile chan vo han -> treo worker.
 *
 * Giai phap: dung OVERLAPPED. Goi lenh ghi/doc roi CHO CO GIOI HAN;
 * qua han thi CancelIo huy lenh va di tiep.
 * ================================================================== */

/* Ghi du soByte vao pipe, toi da timeoutMs. TRUE = ghi du. */
static BOOL PipeWriteEx(HANDLE hPipe, const void *data, DWORD size, DWORD timeoutMs)
{
    OVERLAPPED ov;
    HANDLE hEvent;
    DWORD written = 0;
    BOOL ok = FALSE;

    if (size == 0) return TRUE;

    hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!hEvent) return FALSE;
    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = hEvent;

    if (WriteFile(hPipe, data, size, &written, &ov)) {
        ok = (written == size);
    } else if (GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(hEvent, timeoutMs) == WAIT_OBJECT_0) {
            ok = GetOverlappedResult(hPipe, &ov, &written, FALSE) && (written == size);
        } else {
            CancelIo(hPipe);   /* qua han -> huy lenh ghi, khong treo */
            ok = FALSE;
        }
    }
    CloseHandle(hEvent);
    return ok;
}

/* Doc du soByte tu pipe. timeoutMs = INFINITE thi cho den khi co du lieu,
   nhung van thoat duoc khi service dung (nho g_hStopEvent). */
static BOOL PipeReadEx(HANDLE hPipe, void *buffer, DWORD size, DWORD timeoutMs)
{
    OVERLAPPED ov;
    HANDLE hEvent;
    DWORD read = 0;
    BOOL ok = FALSE;

    if (size == 0) return TRUE;

    hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!hEvent) return FALSE;
    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = hEvent;

    if (ReadFile(hPipe, buffer, size, &read, &ov)) {
        ok = (read == size);
    } else if (GetLastError() == ERROR_IO_PENDING) {
        HANDLE waits[2] = { hEvent, g_hStopEvent };
        DWORD w = WaitForMultipleObjects(2, waits, FALSE, timeoutMs);
        if (w == WAIT_OBJECT_0) {
            ok = GetOverlappedResult(hPipe, &ov, &read, FALSE) && (read == size);
        } else {
            CancelIo(hPipe);   /* service dung hoac qua han */
            ok = FALSE;
        }
    }
    CloseHandle(hEvent);
    return ok;
}

/* Gui 1 goi TLV (thay cho TlvSend, co timeout) */
static BOOL SvcSend(HANDLE hPipe, WORD type, const void *value, DWORD length)
{
    TlvHeader hdr;
    hdr.type   = type;
    hdr.length = length;

    if (!PipeWriteEx(hPipe, &hdr, sizeof(hdr), 3000)) return FALSE;
    if (length > 0 && value)
        if (!PipeWriteEx(hPipe, value, length, 3000)) return FALSE;
    return TRUE;
}

/* Nhan 1 goi TLV (thay cho TlvRecv) */
static BOOL SvcRecv(HANDLE hPipe, WORD *outType, void *buffer, DWORD bufSize, DWORD *outLen)
{
    TlvHeader hdr;

    if (!PipeReadEx(hPipe, &hdr, sizeof(hdr), INFINITE)) return FALSE;
    if (hdr.length > bufSize) return FALSE;

    *outType = hdr.type;
    *outLen  = hdr.length;

    if (hdr.length > 0)
        if (!PipeReadEx(hPipe, buffer, hdr.length, 10000)) return FALSE;
    return TRUE;
}

/* ==================================================================
 * GUI TIN TLV VE CLIENT (co khoa vi nhieu luong cung ghi 1 pipe)
 * ================================================================== */
static void SendToClient(Job *job, WORD type, const char *value)
{
    DWORD len = value ? (DWORD)strlen(value) : 0;
    DWORD w;

    /* Pipe da bi danh dau hong (client thoat) -> bo qua, khong gui */
    if (job->hClientPipe == NULL || job->hClientPipe == INVALID_HANDLE_VALUE)
        return;
    if (job->hPipeWriteMutex == NULL)
        return;

    /* QUAN TRONG: cho toi da 2 giay, KHONG cho vo han.
       Neu cho INFINITE ma client da thoat -> worker treo mai mai. */
    w = WaitForSingleObject(job->hPipeWriteMutex, 2000);
    if (w != WAIT_OBJECT_0) {
        job->hClientPipe = INVALID_HANDLE_VALUE;   /* danh dau hong, lan sau khoi thu */
        return;
    }

    /* Gui that bai (client da dong pipe) -> danh dau hong */
    if (g_diag) LogMsg("    [DIAG] job %d: sap WriteFile type=0x%04X", job->jobId, type);
    if (!SvcSend(job->hClientPipe, type, value, len)) {
        job->hClientPipe = INVALID_HANDLE_VALUE;
    }
    if (g_diag) LogMsg("    [DIAG] job %d: WriteFile xong", job->jobId);
    ReleaseMutex(job->hPipeWriteMutex);
}

/* ==================================================================
 * CALLBACK tien do: engine goi -> gui MSG_PROGRESS ve client
 * ================================================================== */
static void ProgressCb(int stage, int percent, void *userData)
{
    Job *job = (Job *)userData;
    char msg[128];
    const char *stageName =
        (stage == 1) ? "open" : (stage == 2) ? "read" :
        (stage == 3) ? "analyze" : "report";

    sprintf(msg, "{\"jobId\":%d,\"stage\":\"%s\",\"percent\":%d}",
            job->jobId, stageName, percent);
    SendToClient(job, MSG_PROGRESS, msg);
}

/* ==================================================================
 * MODULE b) WORKER - lay job tu queue, quet, gui ket qua
 * ================================================================== */
static DWORD WINAPI WorkerThread(LPVOID param)
{
    (void)param;

    while (g_running) {
        int jobIdx;
        Job *job;
        WIN32_FILE_ATTRIBUTE_DATA fad;
        ULONGLONG size;
        int verdict;
        BOOL cacheHit;
        DWORD tStart, tEnd;
        char msg[256];

        /* Cho co job trong hang doi (hoac tin hieu dung) */
        HANDLE waits[2] = { g_hJobSem, g_hStopEvent };
        DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0 + 1) break;   /* stop event */

        /* Lay 1 job tu hang doi */
        WaitForSingleObject(g_hQueueMutex, INFINITE);
        if (g_qHead >= g_qTail) { ReleaseMutex(g_hQueueMutex); continue; }
        jobIdx = g_queue[g_qHead++];
        ReleaseMutex(g_hQueueMutex);

        job = &g_jobs[jobIdx];

        /* Neu job da bi cancel truoc khi chay */
        if (job->state == JOB_CANCELLED) {
            InterlockedDecrement(&g_pendingJobs);
            continue;
        }

        /* --- THROTTLE: neu OVERLOADED va job priority thap -> hoan --- */
        if (g_systemState == STATE_OVERLOADED && job->priority == PRIORITY_LOW) {
            job->state = JOB_DELAYED;
            sprintf(msg, "{\"jobId\":%d,\"reason\":\"system overloaded\"}", job->jobId);
            SendToClient(job, MSG_DELAYED, msg);
            /* Day lai vao cuoi hang doi de thu lai sau */
            Sleep(500);
            WaitForSingleObject(g_hQueueMutex, INFINITE);
            g_queue[g_qTail++] = jobIdx;
            ReleaseMutex(g_hQueueMutex);
            ReleaseSemaphore(g_hJobSem, 1, NULL);
            continue;
        }

        /* Chuyen sang RUNNING */
        InterlockedDecrement(&g_pendingJobs);
        InterlockedIncrement(&g_runningJobs);
        job->state = JOB_RUNNING;
        if (g_diag) LogMsg("  [DIAG] job %d: buoc 1 - bat dau", job->jobId);

        /* Lay thong tin file cho cache key */
        if (!GetFileAttributesExA(job->path, GetFileExInfoStandard, &fad)) {
            InterlockedIncrement(&g_failedJobs);
            InterlockedDecrement(&g_runningJobs);
            job->state = JOB_DONE;
            SendToClient(job, MSG_ERROR, "{\"message\":\"cannot open file\"}");
            continue;
        }
        size = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        if (g_diag) LogMsg("  [DIAG] job %d: buoc 2 - da lay file info", job->jobId);

        tStart = GetTickCount();

        /* --- FAST PATH: tra cache neu file khong doi --- */
        cacheHit = CacheLookup(job->path, fad.ftLastWriteTime, size, &verdict);
        if (g_diag) LogMsg("  [DIAG] job %d: buoc 3 - cache=%d", job->jobId, cacheHit);
        if (cacheHit) {
            InterlockedIncrement(&g_cacheHits);
            job->fromCache = TRUE;
        } else {
            /* Quet that bang engine (co callback bao tien do) */
            verdict = g_EngineScan(job->path, 0, ProgressCb, job);
            job->fromCache = FALSE;
            if (verdict >= 0)
                CacheStore(job->path, fad.ftLastWriteTime, size, verdict);
        }
        if (g_diag) LogMsg("  [DIAG] job %d: buoc 4 - quet xong", job->jobId);

        tEnd = GetTickCount();

        /* Ghi thoi gian quet vao telemetry (CO TIMEOUT, khong cho vo han) */
        if (WaitForSingleObject(g_hTelemetryMutex, 3000) == WAIT_OBJECT_0) {
            if (g_scanTimeCount < MAX_JOBS)
                g_scanTimes[g_scanTimeCount++] = (double)(tEnd - tStart);
            ReleaseMutex(g_hTelemetryMutex);
        } else {
            LogMsg("  [CANH BAO] job %d: timeout khi cho telemetry mutex", job->jobId);
        }
        if (g_diag) LogMsg("  [DIAG] job %d: buoc 5 - da ghi telemetry", job->jobId);

        /* Gui ket qua cuoi */
        job->verdict = verdict;
        job->state   = JOB_DONE;
        {
            const char *vName = (verdict == 2) ? "MALICIOUS" :
                                (verdict == 1) ? "SUSPICIOUS" :
                                (verdict == 0) ? "SAFE" : "ERROR";
            sprintf(msg, "{\"jobId\":%d,\"verdict\":\"%s\",\"fromCache\":%s}",
                    job->jobId, vName, job->fromCache ? "true" : "false");
            SendToClient(job, MSG_RESULT, msg);
        }
        if (g_diag) LogMsg("  [DIAG] job %d: buoc 6 - da gui ket qua", job->jobId);

        InterlockedDecrement(&g_runningJobs);
        InterlockedIncrement(&g_doneJobs);
        LogMsg("Job %d xong: verdict=%d cache=%d (%.0fms)",
               job->jobId, verdict, job->fromCache, (double)(tEnd - tStart));
    }
    return 0;
}

/* ==================================================================
 * TAO JOB MOI, DAY VAO HANG DOI
 * ================================================================== */
static int CreateJob(const char *path, int priority, int timeoutMs,
                     HANDLE hClientPipe, HANDLE hPipeWriteMutex)
{
    int jobId = InterlockedIncrement(&g_jobCount) - 1;   /* lay id roi tang */
    Job *job;

    if (jobId >= MAX_JOBS) return -1;

    job = &g_jobs[jobId];
    job->jobId     = jobId;
    strcpy(job->path, path);
    job->priority  = priority;
    job->timeoutMs = timeoutMs;
    job->state     = JOB_PENDING;
    job->verdict   = -1;
    job->fromCache = FALSE;
    job->hClientPipe = hClientPipe;
    job->hPipeWriteMutex = hPipeWriteMutex;

    InterlockedIncrement(&g_totalJobs);
    InterlockedIncrement(&g_pendingJobs);

    /* Day vao hang doi. Job priority HIGH chen len dau (uu tien). */
    WaitForSingleObject(g_hQueueMutex, INFINITE);
    if (priority == PRIORITY_HIGH) {
        /* Chen len dau: don cac phan tu lui 1 o */
        int i;
        for (i = g_qTail; i > g_qHead; i--) g_queue[i] = g_queue[i - 1];
        g_queue[g_qHead] = jobId;
        g_qTail++;
    } else {
        g_queue[g_qTail++] = jobId;   /* them vao cuoi */
    }
    ReleaseMutex(g_hQueueMutex);

    ReleaseSemaphore(g_hJobSem, 1, NULL);   /* bao co job moi */
    return jobId;
}

/* ==================================================================
 * MODULE a) LUONG PHUC VU 1 CLIENT
 * ================================================================== */
static DWORD WINAPI ClientThread(LPVOID param)
{
    HANDLE hPipe = (HANDLE)param;
    HANDLE hWriteMutex = CreateMutexA(NULL, FALSE, NULL);
    WORD type;
    char value[MAX_VALUE_SIZE + 1];
    DWORD len;
    static volatile LONG sessionCounter = 0;
    int sessionId;

    /* --- HANDSHAKE: cho HELLO --- */
    if (!SvcRecv(hPipe, &type, value, MAX_VALUE_SIZE, &len) || type != MSG_HELLO) {
        CloseHandle(hPipe);
        CloseHandle(hWriteMutex);
        return 0;
    }
    value[len] = '\0';
    sessionId = InterlockedIncrement(&sessionCounter);
    LogMsg("Client ket noi (session %d): %s", sessionId, value);

    /* Tra WELCOME */
    {
        char welcome[256];
        sprintf(welcome, "{\"sessionId\":%d,\"serverVersion\":%d,\"policy\":\"demo\"}",
                sessionId, g_EngineVer());
        WaitForSingleObject(hWriteMutex, INFINITE);
        SvcSend(hPipe, MSG_WELCOME, welcome, (DWORD)strlen(welcome));
        ReleaseMutex(hWriteMutex);
    }

    /* --- VONG LAP NHAN LENH --- */
    while (g_running) {
        if (!SvcRecv(hPipe, &type, value, MAX_VALUE_SIZE, &len)) break;
        value[len] = '\0';

        if (type == MSG_SCAN) {
            /* Parse tho: value = "path|priority|timeout" */
            char path[MAX_PATH]; int prio = PRIORITY_NORMAL, timeout = 30000;
            char *p1 = strchr(value, '|');
            if (p1) {
                *p1 = '\0';
                strcpy(path, value);
                sscanf(p1 + 1, "%d|%d", &prio, &timeout);
            } else {
                strcpy(path, value);
            }

            int jobId = CreateJob(path, prio, timeout, hPipe, hWriteMutex);
            char resp[64];
            sprintf(resp, "{\"jobId\":%d}", jobId);
            WaitForSingleObject(hWriteMutex, INFINITE);
            SvcSend(hPipe, MSG_ACCEPTED, resp, (DWORD)strlen(resp));
            ReleaseMutex(hWriteMutex);
            LogMsg("Nhan SCAN job %d: %s (prio=%d)", jobId, path, prio);

        } else if (type == MSG_QUERY) {
            int jobId = atoi(value);
            char resp[128];
            const char *st = "UNKNOWN";
            if (jobId >= 0 && jobId < g_jobCount) {
                switch (g_jobs[jobId].state) {
                    case JOB_PENDING:   st = "PENDING";   break;
                    case JOB_RUNNING:   st = "RUNNING";   break;
                    case JOB_DONE:      st = "DONE";      break;
                    case JOB_CANCELLED: st = "CANCELLED"; break;
                    case JOB_DELAYED:   st = "DELAYED";   break;
                }
            }
            sprintf(resp, "{\"jobId\":%d,\"state\":\"%s\"}", jobId, st);
            WaitForSingleObject(hWriteMutex, INFINITE);
            SvcSend(hPipe, MSG_STATUS, resp, (DWORD)strlen(resp));
            ReleaseMutex(hWriteMutex);

        } else if (type == MSG_CANCEL) {
            int jobId = atoi(value);
            char resp[128];
            if (jobId >= 0 && jobId < g_jobCount &&
                (g_jobs[jobId].state == JOB_PENDING || g_jobs[jobId].state == JOB_DELAYED)) {
                g_jobs[jobId].state = JOB_CANCELLED;
                InterlockedIncrement(&g_cancelJobs);
                sprintf(resp, "{\"jobId\":%d,\"state\":\"CANCELLED\"}", jobId);
            } else {
                sprintf(resp, "{\"jobId\":%d,\"state\":\"CANNOT_CANCEL\"}", jobId);
            }
            WaitForSingleObject(hWriteMutex, INFINITE);
            SvcSend(hPipe, MSG_STATUS, resp, (DWORD)strlen(resp));
            ReleaseMutex(hWriteMutex);
            LogMsg("Nhan CANCEL job %d", jobId);

        } else if (type == MSG_BYE) {
            break;
        }
    }

    /* --- QUAN TRONG: vo hieu hoa moi job con tro toi pipe nay ---
       Neu khong lam buoc nay, worker se cam con tro toi handle da dong
       -> ghi vao pipe chet -> treo worker vinh vien. */
    {
        LONG i, n = g_jobCount;
        if (n > MAX_JOBS) n = MAX_JOBS;
        for (i = 0; i < n; i++) {
            if (g_jobs[i].hClientPipe == hPipe) {
                g_jobs[i].hClientPipe = INVALID_HANDLE_VALUE;
                /* Job con dang cho -> huy luon, khong ai nhan ket qua nua */
                if (g_jobs[i].state == JOB_PENDING || g_jobs[i].state == JOB_DELAYED) {
                    g_jobs[i].state = JOB_CANCELLED;
                    InterlockedIncrement(&g_cancelJobs);
                }
            }
        }
    }
    Sleep(150);   /* cho worker dang ghi do kip thoat khoi mutex */

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    CloseHandle(hWriteMutex);
    LogMsg("Client session %d dong.", sessionId);
    return 0;
}

/* ==================================================================
 * MODULE a) PIPE SERVER - lang nghe, tao luong cho moi client
 * ================================================================== */
static DWORD WINAPI PipeServerThread(LPVOID param)
{
    /* --- Mo ta bao mat cho pipe ---
       O che do Windows Service, service chay duoi tai khoan LocalSystem
       con client chay duoi tai khoan nguoi dung -> mac dinh client KHONG
       mo duoc pipe. DACL = NULL nghia la "cho phep tat ca". */
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa;

    (void)param;

    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle       = FALSE;

    LogMsg("Pipe server dang lang nghe tai %s", PIPE_NAME);

    while (g_running) {
        OVERLAPPED ov;
        HANDLE hEvent;
        BOOL connected = FALSE;

        HANDLE hPipe = CreateNamedPipeA(
            PIPE_NAME,
            /* FILE_FLAG_OVERLAPPED: BAT BUOC de moi thao tac doc/ghi
               deu co the dat gioi han thoi gian -> khong bao gio treo. */
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536, 65536, 0, &sa);   /* &sa: cho phep client khac tai khoan ket noi */

        if (hPipe == INVALID_HANDLE_VALUE) {
            LogMsg("Loi tao named pipe.");
            break;
        }

        /* --- Cho client ket noi (bat dong bo, co the huy khi dung service) --- */
        hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
        ZeroMemory(&ov, sizeof(ov));
        ov.hEvent = hEvent;

        if (ConnectNamedPipe(hPipe, &ov)) {
            connected = TRUE;
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                connected = TRUE;
            } else if (err == ERROR_IO_PENDING) {
                /* Cho: hoac client ket noi, hoac lenh dung service */
                HANDLE waits[2] = { hEvent, g_hStopEvent };
                DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
                if (w == WAIT_OBJECT_0) {
                    DWORD dummy;
                    connected = GetOverlappedResult(hPipe, &ov, &dummy, FALSE);
                } else {
                    CancelIo(hPipe);   /* dung service -> huy cho */
                }
            }
        }
        CloseHandle(hEvent);

        if (!g_running) { CloseHandle(hPipe); break; }

        if (connected) {
            HANDLE hThread = CreateThread(NULL, 0, ClientThread, (LPVOID)hPipe, 0, NULL);
            if (hThread) CloseHandle(hThread);
            else { CloseHandle(hPipe); }
        } else {
            CloseHandle(hPipe);
        }
    }
    return 0;
}

/* ==================================================================
 * LOI HE THONG - DUNG CHUNG CHO CA 2 CHE DO
 * ------------------------------------------------------------------
 * StartEngineSystem() : khoi tao moi thu (mutex, engine, cac luong)
 * StopEngineSystem()  : dung va don dep
 *
 * Hai che do chi khac nhau o CACH CHO LENH DUNG:
 *   - Console        : getchar() cho nguoi dung nhan Enter
 *   - WindowsService : WaitForSingleObject cho SCM ra lenh
 * ================================================================== */
static HANDLE g_workers[MAX_WORKERS] = {0};
static HANDLE g_hThrottle = NULL, g_hTelemetry = NULL, g_hPipeServer = NULL;

static BOOL StartEngineSystem(void)
{
    int i;

    /* Tao cac doi tuong dong bo hoa */
    g_hQueueMutex     = CreateMutexA(NULL, FALSE, NULL);
    g_hCacheMutex     = CreateMutexA(NULL, FALSE, NULL);
    g_hTelemetryMutex = CreateMutexA(NULL, FALSE, NULL);
    g_hJobSem         = CreateSemaphoreA(NULL, 0, MAX_JOBS, NULL);
    g_hStopEvent      = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_hLogMutex       = CreateMutexA(NULL, FALSE, NULL);

    if (!g_hQueueMutex || !g_hCacheMutex || !g_hTelemetryMutex ||
        !g_hJobSem || !g_hStopEvent || !g_hLogMutex) {
        LogMsg("Loi: khong tao duoc doi tuong dong bo hoa.");
        return FALSE;
    }

    g_running = 1;

    LogMsg("Thu muc lam viec: %s", g_exeDir);
    if (g_diag) LogMsg("Che do chan doan: BAT");

    /* Nap engine (duong dan tuyet doi) */
    if (!LoadEngine()) return FALSE;

    /* Tao worker pool */
    for (i = 0; i < MAX_WORKERS; i++)
        g_workers[i] = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);

    /* Tao cac luong module */
    g_hThrottle   = CreateThread(NULL, 0, ThrottleThread,   NULL, 0, NULL);
    g_hTelemetry  = CreateThread(NULL, 0, TelemetryThread,  NULL, 0, NULL);
    g_hPipeServer = CreateThread(NULL, 0, PipeServerThread, NULL, 0, NULL);

    LogMsg("He thong da san sang (%d worker).", MAX_WORKERS);
    return TRUE;
}

static void StopEngineSystem(void)
{
    int i;

    LogMsg("Dang dung he thong...");
    g_running = 0;
    if (g_hStopEvent) SetEvent(g_hStopEvent);

    /* Danh thuc worker dang cho semaphore */
    for (i = 0; i < MAX_WORKERS; i++)
        if (g_hJobSem) ReleaseSemaphore(g_hJobSem, 1, NULL);

    /* Ket noi gia de danh thuc PipeServerThread khoi ConnectNamedPipe */
    {
        HANDLE hDummy = CreateFileA(PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
                                    0, NULL, OPEN_EXISTING, 0, NULL);
        if (hDummy != INVALID_HANDLE_VALUE) CloseHandle(hDummy);
    }

    WaitForMultipleObjects(MAX_WORKERS, g_workers, TRUE, 3000);
    for (i = 0; i < MAX_WORKERS; i++)
        if (g_workers[i]) { CloseHandle(g_workers[i]); g_workers[i] = NULL; }

    if (g_hThrottle)   { WaitForSingleObject(g_hThrottle, 2000);   CloseHandle(g_hThrottle);   g_hThrottle = NULL; }
    if (g_hTelemetry)  { WaitForSingleObject(g_hTelemetry, 2000);  CloseHandle(g_hTelemetry);  g_hTelemetry = NULL; }
    if (g_hPipeServer) { WaitForSingleObject(g_hPipeServer, 2000); CloseHandle(g_hPipeServer); g_hPipeServer = NULL; }

    if (g_EngineShutdown) g_EngineShutdown();
    if (g_hEngine) { FreeLibrary(g_hEngine); g_hEngine = NULL; }

    if (g_hQueueMutex)     { CloseHandle(g_hQueueMutex);     g_hQueueMutex = NULL; }
    if (g_hCacheMutex)     { CloseHandle(g_hCacheMutex);     g_hCacheMutex = NULL; }
    if (g_hTelemetryMutex) { CloseHandle(g_hTelemetryMutex); g_hTelemetryMutex = NULL; }
    if (g_hJobSem)         { CloseHandle(g_hJobSem);         g_hJobSem = NULL; }
    if (g_hStopEvent)      { CloseHandle(g_hStopEvent);      g_hStopEvent = NULL; }

    LogMsg("He thong da dung.");
    if (g_hLogMutex) { CloseHandle(g_hLogMutex); g_hLogMutex = NULL; }
}

/* ==================================================================
 * CHE DO 1: CONSOLE SERVICE
 * ================================================================== */
static int RunAsConsole(void)
{
    g_consoleMode = 1;

    printf("========== AV SCAN SERVICE - CHE DO CONSOLE ==========\n\n");

    if (!StartEngineSystem()) {
        printf("Khoi dong that bai. Kiem tra engine.dll co cung thu muc khong.\n");
        printf("Nhan ENTER de thoat...");
        getchar();
        return 1;
    }

    printf("\n>>> Nhan ENTER de dung service <<<\n\n");
    getchar();

    StopEngineSystem();
    return 0;
}

/* ==================================================================
 * CHE DO 2: WINDOWS SERVICE
 * ------------------------------------------------------------------
 * 3 thanh phan bat buoc:
 *   ServiceCtrlHandler          - nhan lenh tu SCM
 *   ServiceMain                 - ham chinh cua service
 *   StartServiceCtrlDispatcher  - cau noi voi SCM (goi trong main)
 * ================================================================== */
static void WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    switch (ctrlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            /* Bao SCM: dang trong qua trinh dung */
            g_SvcStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_SvcStatus.dwWaitHint     = 8000;   /* xin toi da 8 giay */
            SetServiceStatus(g_SvcStatusHandle, &g_SvcStatus);

            /* Bat "den bao" de ServiceMain thoat khoi vong cho */
            if (g_hSvcStopEvent) SetEvent(g_hSvcStopEvent);
            break;

        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(g_SvcStatusHandle, &g_SvcStatus);
            break;
    }
}

static void WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
    (void)argc; (void)argv;

    g_consoleMode = 0;   /* khong co man hinh -> chi ghi log ra file */

    /* 1. Dang ky ham nhan lenh voi SCM */
    g_SvcStatusHandle = RegisterServiceCtrlHandlerA(SVC_NAME, ServiceCtrlHandler);
    if (!g_SvcStatusHandle) return;

    /* 2. Bao SCM: dang khoi dong */
    g_SvcStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_SvcStatus.dwCurrentState     = SERVICE_START_PENDING;
    g_SvcStatus.dwControlsAccepted = 0;      /* chua nhan lenh nao khi dang khoi dong */
    g_SvcStatus.dwWin32ExitCode    = 0;
    g_SvcStatus.dwCheckPoint       = 0;
    g_SvcStatus.dwWaitHint         = 10000;
    SetServiceStatus(g_SvcStatusHandle, &g_SvcStatus);

    /* 3. Tao "den bao dung" rieng cho che do service */
    g_hSvcStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_hSvcStopEvent) {
        g_SvcStatus.dwCurrentState  = SERVICE_STOPPED;
        g_SvcStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_SvcStatusHandle, &g_SvcStatus);
        return;
    }

    /* 4. Khoi tao he thong (dung chung voi che do console) */
    if (!StartEngineSystem()) {
        LogMsg("Loi: khoi dong he thong that bai.");
        StopEngineSystem();
        g_SvcStatus.dwCurrentState  = SERVICE_STOPPED;
        g_SvcStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        SetServiceStatus(g_SvcStatusHandle, &g_SvcStatus);
        CloseHandle(g_hSvcStopEvent);
        return;
    }

    /* 5. Bao SCM: da chay OK, tu gio nhan lenh STOP */
    g_SvcStatus.dwCurrentState     = SERVICE_RUNNING;
    g_SvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_SvcStatus.dwWaitHint         = 0;
    SetServiceStatus(g_SvcStatusHandle, &g_SvcStatus);
    LogMsg("===== WINDOWS SERVICE DA KHOI DONG =====");

    /* 6. Cho lenh dung tu SCM (KHONG dung getchar - khong co stdin!) */
    WaitForSingleObject(g_hSvcStopEvent, INFINITE);

    /* 7. Don dep */
    LogMsg("===== WINDOWS SERVICE DANG DUNG =====");
    StopEngineSystem();
    CloseHandle(g_hSvcStopEvent);
    g_hSvcStopEvent = NULL;

    /* 8. Bao SCM: da dung han */
    g_SvcStatus.dwCurrentState = SERVICE_STOPPED;
    g_SvcStatus.dwWaitHint     = 0;
    SetServiceStatus(g_SvcStatusHandle, &g_SvcStatus);
}

static int RunAsService(void)
{
    SERVICE_TABLE_ENTRYA table[] = {
        { (LPSTR)SVC_NAME, ServiceMain },
        { NULL, NULL }
    };
    /* Ham nay KHONG tra ve cho den khi service dung han */
    if (!StartServiceCtrlDispatcherA(table)) return 1;
    return 0;
}

/* ==================================================================
 * QUAN LY WINDOWS SERVICE (install / uninstall / start / stop / status)
 * ================================================================== */
static void PrintErr(const char *what)
{
    DWORD e = GetLastError();
    printf("Loi: %s (ma loi %lu)", what, e);
    if (e == ERROR_ACCESS_DENIED)
        printf("\n  -> Hay chay Command Prompt voi quyen Administrator.");
    else if (e == ERROR_SERVICE_EXISTS)
        printf("\n  -> Service da ton tai. Dung 'uninstall' truoc.");
    else if (e == ERROR_SERVICE_DOES_NOT_EXIST)
        printf("\n  -> Service chua duoc cai dat. Dung 'install' truoc.");
    printf("\n");
}

static int InstallService(void)
{
    SC_HANDLE scm, svc;
    char cmdLine[MAX_PATH + 32];
    SC_ACTION actions[3];
    SERVICE_FAILURE_ACTIONSA fa;

    /* Canh bao duong dan co dau tieng Viet (bai hoc tu bai 3.2) */
    {
        int i;
        for (i = 0; g_exePath[i]; i++) {
            if ((unsigned char)g_exePath[i] > 127) {
                printf("CANH BAO: duong dan chua ky tu khong phai ASCII:\n  %s\n", g_exePath);
                printf("Service se KHONG khoi dong duoc (loi ma 2).\n");
                printf("Hay copy 3 file (service.exe, engine.dll, client.exe)\n");
                printf("sang thu muc khong dau, vi du C:\\AvScanSvc, roi install lai.\n");
                return 1;
            }
        }
    }

    /* Chuoi lenh SCM se chay: "duong_dan\service.exe" runservice */
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" runservice", g_exePath);

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { PrintErr("OpenSCManager"); return 1; }

    svc = CreateServiceA(
        scm,
        SVC_NAME,
        SVC_DISPLAY,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,        /* khoi dong thu cong */
        SERVICE_ERROR_NORMAL,
        cmdLine,
        NULL, NULL, NULL, NULL, NULL);

    if (!svc) { PrintErr("CreateService"); CloseServiceHandle(scm); return 1; }

    /* --- Cau hinh AUTO-RESTART neu bi kill --- */
    actions[0].Type = SC_ACTION_RESTART; actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART; actions[1].Delay = 5000;
    actions[2].Type = SC_ACTION_RESTART; actions[2].Delay = 5000;

    ZeroMemory(&fa, sizeof(fa));
    fa.dwResetPeriod = 86400;    /* 1 ngay khong loi thi reset bo dem */
    fa.cActions      = 3;
    fa.lpsaActions   = actions;

    if (ChangeServiceConfig2A(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa))
        printf("[OK] Da bat auto-restart (5 giay sau khi loi).\n");
    else
        printf("[!] Khong dat duoc auto-restart (ma loi %lu).\n", GetLastError());

    printf("[OK] Da cai dat service '%s'.\n", SVC_NAME);
    printf("     Duong dan: %s\n", cmdLine);
    printf("     Dung 'service.exe start' de khoi dong.\n");

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

    svc = OpenServiceA(scm, SVC_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!svc) { PrintErr("OpenService"); CloseServiceHandle(scm); return 1; }

    /* Dung truoc neu dang chay (khong xoa duoc service dang chay) */
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        printf("Dang dung service...\n");
        Sleep(2000);
    }

    if (DeleteService(svc)) printf("[OK] Da go bo service '%s'.\n", SVC_NAME);
    else                    PrintErr("DeleteService");

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int StartSvc(void)
{
    SC_HANDLE scm, svc;
    int ret = 0;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { PrintErr("OpenSCManager"); return 1; }

    svc = OpenServiceA(scm, SVC_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) { PrintErr("OpenService"); CloseServiceHandle(scm); return 1; }

    if (StartServiceA(svc, 0, NULL)) {
        printf("[OK] Da gui lenh START. Doi vai giay roi kiem tra bang 'status'.\n");
    } else {
        PrintErr("StartService");
        ret = 1;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ret;
}

static int StopSvc(void)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS st;
    int ret = 0;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { PrintErr("OpenSCManager"); return 1; }

    svc = OpenServiceA(scm, SVC_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) { PrintErr("OpenService"); CloseServiceHandle(scm); return 1; }

    if (ControlService(svc, SERVICE_CONTROL_STOP, &st))
        printf("[OK] Da gui lenh STOP.\n");
    else { PrintErr("ControlService"); ret = 1; }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ret;
}

/* Tra ve: -1 = chua cai dat, else = ma trang thai SERVICE_xxx */
static int GetSvcState(void)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;
    int state = -1;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return -1;

    svc = OpenServiceA(scm, SVC_NAME, SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return -1; }

    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&ssp, sizeof(ssp), &needed))
        state = (int)ssp.dwCurrentState;

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return state;
}

static const char *StateName(int st)
{
    switch (st) {
        case -1:                      return "CHUA CAI DAT";
        case SERVICE_STOPPED:         return "DA CAI - DANG DUNG";
        case SERVICE_START_PENDING:   return "DANG KHOI DONG...";
        case SERVICE_STOP_PENDING:    return "DANG DUNG...";
        case SERVICE_RUNNING:         return "DANG CHAY";
        default:                      return "(khac)";
    }
}

static int ShowStatus(void)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;

    printf("Ten service : %s\n", SVC_NAME);
    printf("Ten hien thi: %s\n", SVC_DISPLAY);

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { PrintErr("OpenSCManager"); return 1; }

    svc = OpenServiceA(scm, SVC_NAME, SERVICE_QUERY_STATUS);
    if (!svc) {
        printf("Trang thai  : CHUA CAI DAT\n");
        CloseServiceHandle(scm);
        return 0;
    }

    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        printf("Trang thai  : %s\n", StateName((int)ssp.dwCurrentState));
        if (ssp.dwCurrentState == SERVICE_RUNNING)
            printf("PID         : %lu\n", ssp.dwProcessId);
    }
    printf("File log    : %s\n", g_logPath);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

/* ==================================================================
 * MENU TUONG TAC (khi chay khong co tham so)
 * ================================================================== */
static void ShowMenu(void)
{
    char line[32];
    int choice;

    for (;;) {
        int st = GetSvcState();

        printf("\n========== AV SCAN SERVICE (Bai 5.1) ==========\n");
        printf("Thu muc lam viec : %s\n", g_exeDir);
        printf("Windows Service  : %s\n", StateName(st));
        printf("Che do chan doan : %s\n", g_diag ? "BAT (co file diag.on)" : "TAT");
        printf("\nChon che do:\n");
        printf("  1. Chay CONSOLE SERVICE   (chay ngay, thay log truc tiep)\n");
        printf("  --- Windows Service (can quyen Administrator) ---\n");
        printf("  2. Cai dat service\n");
        printf("  3. Khoi dong service\n");
        printf("  4. Dung service\n");
        printf("  5. Go bo service\n");
        printf("  6. Xem trang thai chi tiet\n");
        printf("  0. Thoat\n");
        printf("\nLua chon: ");

        if (!fgets(line, sizeof(line), stdin)) return;
        choice = atoi(line);

        printf("\n");
        switch (choice) {
            case 1: RunAsConsole();   return;   /* chay xong thi thoat luon */
            case 2: InstallService(); break;
            case 3: StartSvc();       break;
            case 4: StopSvc();        break;
            case 5: UninstallService(); break;
            case 6: ShowStatus();     break;
            case 0: return;
            default: printf("Lua chon khong hop le.\n"); break;
        }
    }
}

/* ==================================================================
 * MAIN - phan nhanh 7 vai tro
 * ================================================================== */
int main(int argc, char *argv[])
{
    /* BAT BUOC goi dau tien: tinh duong dan tuyet doi */
    InitPaths();
    InitDiagFlag();

    if (argc >= 2) {
        if (strcmp(argv[1], "runservice") == 0) {
            /* SCM goi - KHONG phai nguoi dung go */
            return RunAsService();
        }
        if (strcmp(argv[1], "console") == 0)   return RunAsConsole();
        if (strcmp(argv[1], "install") == 0)   return InstallService();
        if (strcmp(argv[1], "uninstall") == 0) return UninstallService();
        if (strcmp(argv[1], "start") == 0)     return StartSvc();
        if (strcmp(argv[1], "stop") == 0)      return StopSvc();
        if (strcmp(argv[1], "status") == 0)    return ShowStatus();

        printf("Tham so khong hop le: %s\n\n", argv[1]);
        printf("Cach dung:\n");
        printf("  service.exe            -> hien menu\n");
        printf("  service.exe console    -> chay Console Service\n");
        printf("  service.exe install    -> cai dat Windows Service\n");
        printf("  service.exe start      -> khoi dong Windows Service\n");
        printf("  service.exe stop       -> dung Windows Service\n");
        printf("  service.exe uninstall  -> go bo Windows Service\n");
        printf("  service.exe status     -> xem trang thai\n");
        return 1;
    }

    /* Khong co tham so -> hien menu */
    ShowMenu();
    return 0;
}
