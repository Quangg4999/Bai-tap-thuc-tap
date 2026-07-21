#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE        /* ep ANSI, tranh loi TCHAR bi cat chuoi nhu bai 2.1 */
#undef _UNICODE
/*
 * Bai 2.2 - Thread Monitor
 * -------------------------------------------------------------------
 * Liet ke toan bo thread cua MOT process nhat dinh, dung
 * CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) + Thread32First/Next.
 * In ra: TID, trang thai thread (that, qua NtQuerySystemInformation -
 * mot API khong chinh thong nhung on dinh va rat pho bien), va
 * % CPU (tu tinh bang GetThreadTimes, lay mau 2 lan cach nhau 1 khoang).
 *
 * QUAN TRONG: chi build duoc tren Windows (Windows API).
 *
 * Build tren Windows (x64), Visual Studio:
 *   - MSVC: cl /Od /std:c11 thread_monitor.c
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

/* ==================================================================
 * PHAN A: Khai bao thu cong cho NtQuerySystemInformation
 * Day la API "khong chinh thong" (undocumented) cua Windows -
 * khong co san trong windows.h, phai tu khai bao struct + nap ham
 * bang GetProcAddress tu ntdll.dll.
 * ================================================================== */

typedef LONG NTSTATUS;
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER Reserved1[3];
    ULONG         Reserved2;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    LONG          Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;   /* 0=Init 1=Ready 2=Running 3=Standby 4=Terminated 5=Waiting ... */
    ULONG         WaitReason;
} SYSTEM_THREAD_INFORMATION;

typedef struct _UNICODE_STRING_MINI {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_MINI;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG                 NextEntryOffset;
    ULONG                 NumberOfThreads;
    LARGE_INTEGER         Reserved1[3];
    LARGE_INTEGER         CreateTime;
    LARGE_INTEGER         UserTime;
    LARGE_INTEGER         KernelTime;
    UNICODE_STRING_MINI   ImageName;
    LONG                  BasePriority;
    HANDLE                ProcessId;
    HANDLE                InheritedFromProcessId;
    ULONG                 HandleCount;
    ULONG                 SessionId;
    ULONG_PTR             PageDirectoryBase;
    SIZE_T                PeakVirtualSize;
    SIZE_T                VirtualSize;
    ULONG                 PageFaultCount;
    SIZE_T                PeakWorkingSetSize;
    SIZE_T                WorkingSetSize;
    SIZE_T                QuotaPeakPagedPoolUsage;
    SIZE_T                QuotaPagedPoolUsage;
    SIZE_T                QuotaPeakNonPagedPoolUsage;
    SIZE_T                QuotaNonPagedPoolUsage;
    SIZE_T                PagefileUsage;
    SIZE_T                PeakPagefileUsage;
    SIZE_T                PrivatePageCount;
    LARGE_INTEGER         ReadOperationCount;
    LARGE_INTEGER         WriteOperationCount;
    LARGE_INTEGER         OtherOperationCount;
    LARGE_INTEGER         ReadTransferCount;
    LARGE_INTEGER         WriteTransferCount;
    LARGE_INTEGER         OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];   /* mang mo rong, so phan tu = NumberOfThreads */
} SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS (WINAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

#define SystemProcessInformation  5

/* Chuyen ma so ThreadState thanh chuoi de nguoi doc de hieu */
const char *ThreadStateToStr(ULONG state)
{
    switch (state) {
        case 0: return "Initialized";
        case 1: return "Ready";
        case 2: return "Running";
        case 3: return "Standby";
        case 4: return "Terminated";
        case 5: return "Waiting";
        case 6: return "Transition";
        case 7: return "DeferredReady";
        default: return "Unknown";
    }
}

/* ==================================================================
 * PHAN B: Ham tien ich - doi FILETIME thanh so nguyen 64-bit de tinh toan
 * ================================================================== */
ULONGLONG FileTimeToULL(const FILETIME *ft)
{
    ULARGE_INTEGER u;
    u.LowPart  = ft->dwLowDateTime;
    u.HighPart = ft->dwHighDateTime;
    return u.QuadPart;
}

/* ==================================================================
 * PHAN C: Liet ke danh sach TID thuoc process muc tieu
 * Dung dung Thread32First/Next nhu de bai yeu cau.
 * ================================================================== */
int CollectThreadIds(DWORD targetPid, DWORD *tidArray, int maxCount)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Loi: khong tao duoc snapshot thread (ma loi: %lu)\n", GetLastError());
        return 0;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);   /* BAT BUOC gan truoc Thread32First, giong PROCESSENTRY32 */

    int count = 0;
    
    if (Thread32First(hSnapshot, &te)) {
        do {
            /* Snapshot TH32CS_SNAPTHREAD chua thread cua TAT CA process tren may,
               phai tu loc lai theo dung PID minh can */
            if (te.th32OwnerProcessID == targetPid) {
                if (count < maxCount) {
                    tidArray[count] = te.th32ThreadID;
                    count++;
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return count;
}

/* ==================================================================
 * PHAN D: Lay trang thai that cua thread qua NtQuerySystemInformation
 * (undocumented API, nhung rat pho bien va on dinh qua nhieu ban Windows)
 * ================================================================== */
int GetThreadStateAndReason(DWORD targetPid, DWORD targetTid, ULONG *outState, ULONG *outReason)
{
    static PFN_NtQuerySystemInformation pNtQuerySystemInformation = NULL;
    if (pNtQuerySystemInformation == NULL) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        pNtQuerySystemInformation =
            (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        if (pNtQuerySystemInformation == NULL) return 0;
    }

    ULONG bufSize = 1 << 16;   /* bat dau voi 64KB, tang dan neu khong du */
    PVOID buffer = NULL;
    NTSTATUS status;

    do {
        buffer = malloc(bufSize);
        if (!buffer) return 0;

        status = pNtQuerySystemInformation(SystemProcessInformation, buffer, bufSize, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(buffer);
            bufSize *= 2;   /* buffer chua du lon, tang gap doi roi thu lai */
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status != 0) {   /* 0 = STATUS_SUCCESS */
        free(buffer);
        return 0;
    }

    int found = 0;
    BYTE *p = (BYTE *)buffer;

    for (;;) {
        SYSTEM_PROCESS_INFORMATION *spi = (SYSTEM_PROCESS_INFORMATION *)p;

        if ((DWORD)(ULONG_PTR)spi->ProcessId == targetPid) {
            for (ULONG i = 0; i < spi->NumberOfThreads; i++) {
                SYSTEM_THREAD_INFORMATION *sti = &spi->Threads[i];
                if ((DWORD)(ULONG_PTR)sti->ClientId.UniqueThread == targetTid) {
                    *outState  = sti->ThreadState;
                    *outReason = sti->WaitReason;
                    found = 1;
                    break;
                }
            }
            break;   /* da tim thay process, khong can duyet tiep */
        }

        if (spi->NextEntryOffset == 0) break;   /* het danh sach */
        p += spi->NextEntryOffset;
    }

    free(buffer);
    return found;
}

/* ==================================================================
 * MAIN
 * ================================================================== */
#define MAX_THREADS 512

int main(void)
{
    printf("========== THREAD MONITOR ==========\n\n");

    DWORD pid;
    printf("Nhap PID cua process can xem thread: ");
    if (scanf("%lu", &pid) != 1) {
        printf("PID khong hop le.\n");
        return 1;
    }

    DWORD tids[MAX_THREADS];
    int threadCount = CollectThreadIds(pid, tids, MAX_THREADS);

    if (threadCount == 0) {
        printf("\nKhong tim thay thread nao cho PID=%lu.\n", pid);
        printf("(Co the PID khong ton tai, hoac process da ket thuc)\n");
        return 1;
    }

    printf("\nDa tim thay %d thread cua process PID=%lu.\n", threadCount, pid);
    printf("Dang lay mau CPU (mat khoang 1 giay)...\n\n");

    /* ---- Buoc 1: lay mau lan 1 (thoi gian CPU + thoi gian thuc) ---- */
    ULONGLONG cpuTime1[MAX_THREADS];
    for (int i = 0; i < threadCount; i++) {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tids[i]);
        if (hThread) {
            FILETIME ftCreate, ftExit, ftKernel, ftUser;
            if (GetThreadTimes(hThread, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                cpuTime1[i] = FileTimeToULL(&ftKernel) + FileTimeToULL(&ftUser);
            } else {
                cpuTime1[i] = 0;
            }
            CloseHandle(hThread);
        } else {
            cpuTime1[i] = 0;
        }
    }
    FILETIME wallStart;
    GetSystemTimeAsFileTime(&wallStart);

    /* ---- Buoc 2: cho 1 khoang thoi gian co dinh de do do lech ---- */
    Sleep(1000);

    /* ---- Buoc 3: lay mau lan 2 ---- */
    ULONGLONG cpuTime2[MAX_THREADS];
    for (int i = 0; i < threadCount; i++) {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tids[i]);
        if (hThread) {
            FILETIME ftCreate, ftExit, ftKernel, ftUser;
            if (GetThreadTimes(hThread, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                cpuTime2[i] = FileTimeToULL(&ftKernel) + FileTimeToULL(&ftUser);
            } else {
                cpuTime2[i] = cpuTime1[i];
            }
            CloseHandle(hThread);
        } else {
            cpuTime2[i] = cpuTime1[i];
        }
    }
    FILETIME wallEnd;
    GetSystemTimeAsFileTime(&wallEnd);

    ULONGLONG wallDelta = FileTimeToULL(&wallEnd) - FileTimeToULL(&wallStart);

    /* ---- In ket qua ---- */
    printf("%-10s %-16s %-14s %s\n", "TID", "Trang thai", "% CPU", "Ly do cho (neu Waiting)");
    printf("--------------------------------------------------------------------------------\n");

    for (int i = 0; i < threadCount; i++) {
        double cpuPercent = 0.0;
        if (wallDelta > 0) {
            ULONGLONG cpuDelta = (cpuTime2[i] >= cpuTime1[i]) ? (cpuTime2[i] - cpuTime1[i]) : 0;
            cpuPercent = (double)cpuDelta * 100.0 / (double)wallDelta;
        }

        ULONG state = 99, reason = 0;
        int gotState = GetThreadStateAndReason(pid, tids[i], &state, &reason);

        char reasonStr[32] = "-";
        if (gotState && state == 5 /* Waiting */) {
            snprintf(reasonStr, sizeof(reasonStr), "%lu", reason);
        }

        printf("%-10lu %-16s %-14.2f %s\n",
               tids[i],
               gotState ? ThreadStateToStr(state) : "(khong ro)",
               cpuPercent,
               reasonStr);
    }

    printf("--------------------------------------------------------------------------------\n");
    printf("Tong so thread: %d\n", threadCount);

    return 0;
}
