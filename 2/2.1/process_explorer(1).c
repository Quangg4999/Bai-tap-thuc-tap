#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE       /* BAT BUOC: ep toan bo Windows API trong file nay dung ANSI (char),
                         khong phu thuoc cau hinh "Character Set" cua project.
                         Neu khong undef, PROCESSENTRY32.szExeFile se la wchar_t (UNICODE)
                         thay vi char, gay loi ten process bi cat con 1 ky tu khi in bang %s. */
#undef _UNICODE
/*
 * Bai 2.1 - Process Explorer mini
 * -------------------------------------------------------------------
 * Dung CreateToolhelp32Snapshot + Process32First/Next de liet ke
 * toan bo process dang chay tren Windows.
 * In ra: PID, ten tien trinh, duong dan, dung luong RAM dang chiem.
 * Mo rong: kill process (OpenProcess + TerminateProcess),
 *          loc process theo ten (khong phan biet hoa/thuong).
 *
 * QUAN TRONG: day la code danh RIENG cho Windows, khong build
 * duoc tren Linux/macOS vi dung Windows API (windows.h, tlhelp32.h).
 *
 * Build tren Windows (x64), Visual Studio:
 *   - MSVC: cl /Od /std:c11 process_explorer.c
 *     (khong can them cau hinh gi, pragma comment o duoi da tu link psapi.lib)
 *   - MinGW-w64: gcc -O0 -std=c11 process_explorer.c -o process_explorer.exe -lpsapi
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#pragma comment(lib, "psapi.lib")   /* de MSVC tu link thu vien can cho GetProcessMemoryInfo */

/* ==================================================================
 * PHAN 1: Ham tien ich - so sanh chuoi con, khong phan biet hoa/thuong
 * ================================================================== */
BOOL ContainsIgnoreCase(const char *haystack, const char *needle)
{
    if (needle == NULL || needle[0] == '\0') return TRUE; /* khong loc gi ca */

    char h[MAX_PATH], n[MAX_PATH];
    size_t i;

    for (i = 0; haystack[i] && i < MAX_PATH - 1; i++) h[i] = (char)tolower((unsigned char)haystack[i]);
    h[i] = '\0';
    for (i = 0; needle[i] && i < MAX_PATH - 1; i++) n[i] = (char)tolower((unsigned char)needle[i]);
    n[i] = '\0';

    return strstr(h, n) != NULL;
}

/* ==================================================================
 * PHAN 2: Lay them thong tin chi tiet cua 1 process (duong dan + RAM)
 * PROCESSENTRY32 (tu snapshot) KHONG co san duong dan day du va RAM,
 * nen phai mo rieng process do bang OpenProcess de hoi them.
 * ================================================================== */
void GetProcessDetail(DWORD pid, char *pathBuf, size_t pathBufSize, SIZE_T *ramBytes)
{
    strcpy(pathBuf, "(khong the truy cap)");
    *ramBytes = 0;

    /* Xin quyen "chi doc thong tin" - khong xin quyen can thiep/sua doi */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return;   /* thuong gap voi process he thong (System, Registry...), khong co quyen truy cap */
    }

    DWORD size = (DWORD)pathBufSize;
    if (QueryFullProcessImageNameA(hProcess, 0, pathBuf, &size)) {
        /* thanh cong, pathBuf da co duong dan day du */
    } else {
        strcpy(pathBuf, "(khong xac dinh duong dan)");
    }

    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        *ramBytes = pmc.WorkingSetSize;   /* RAM vat ly thuc su dang chiem dung */
    }

    CloseHandle(hProcess);   /* LUON dong handle sau khi dung xong */
}

/* ==================================================================
 * PHAN 3: Liet ke toan bo process (co the loc theo ten)
 * ================================================================== */
void ListProcesses(const char *filterKeyword)
{
    /* Buoc 1: "Bam nut chup anh" toan bo danh sach process hien tai */
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Loi: khong tao duoc snapshot (ma loi Windows: %lu)\n", GetLastError());
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);   /* BAT BUOC gan truoc khi goi Process32First */

    /* Buoc 2: Lay process DAU TIEN trong "tam anh" da chup */
    if (!Process32First(hSnapshot, &pe)) {
        printf("Loi: khong lay duoc process dau tien (ma loi: %lu)\n", GetLastError());
        CloseHandle(hSnapshot);
        return;
    }

    printf("%-8s %-28s %-12s %s\n", "PID", "Ten tien trinh", "RAM (KB)", "Duong dan");
    printf("--------------------------------------------------------------------------------\n");

    int count = 0;

    /* Buoc 3: Lap qua TUNG process con lai bang Process32Next, den khi het */
    do {
        if (!ContainsIgnoreCase(pe.szExeFile, filterKeyword)) {
            continue;   /* khong khop tu khoa loc, bo qua, sang process tiep theo */
        }

        char path[MAX_PATH];
        SIZE_T ramBytes;
        GetProcessDetail(pe.th32ProcessID, path, sizeof(path), &ramBytes);

        printf("%-8lu %-28s %-12zu %s\n",
               pe.th32ProcessID, pe.szExeFile, (size_t)(ramBytes / 1024), path);
        count++;

    } while (Process32Next(hSnapshot, &pe));

    printf("--------------------------------------------------------------------------------\n");
    printf("Tong so process hien thi: %d\n\n", count);

    /* Buoc 4: LUON dong handle snapshot khi dung xong, tranh ro tai nguyen (resource leak) */
    CloseHandle(hSnapshot);
}

/* ==================================================================
 * PHAN 4: Kill process theo PID
 * ================================================================== */
BOOL KillProcessByPID(DWORD pid)
{
    /* Buoc 1: Xin quyen "duoc phep buoc dung" process nay */
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        printf("Loi: khong mo duoc process PID=%lu de kill.\n", pid);
        printf("     (co the do PID khong ton tai, hoac khong du quyen - vi du process he thong)\n");
        printf("     Ma loi Windows: %lu\n", GetLastError());
        return FALSE;
    }

    /* Buoc 2: Ra lenh buoc dung ngay lap tuc */
    BOOL ok = TerminateProcess(hProcess, 1);
    if (ok) {
        printf("Da kill THANH CONG process PID=%lu\n", pid);
    } else {
        printf("Loi: khong kill duoc process PID=%lu (ma loi: %lu)\n", pid, GetLastError());
    }

    CloseHandle(hProcess);
    return ok;
}

/* ==================================================================
 * MAIN - menu dieu khien
 * ================================================================== */
int main(void)
{
    printf("========== PROCESS EXPLORER MINI ==========\n\n");

    int running = 1;
    while (running) {
        printf("1. Liet ke TOAN BO process\n");
        printf("2. Liet ke process co LOC theo ten\n");
        printf("3. KILL process theo PID\n");
        printf("0. Thoat\n");
        printf("Chon: ");

        int choice;
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');   /* don du lieu nhap sai */
            continue;
        }

        printf("\n");
        switch (choice) {
            case 1:
                ListProcesses(NULL);
                break;

            case 2: {
                char keyword[256];
                printf("Nhap tu khoa loc ten process (vi du: chrome): ");
                scanf("%255s", keyword);
                printf("\n");
                ListProcesses(keyword);
                break;
            }

            case 3: {
                DWORD pid;
                printf("Nhap PID can kill: ");
                scanf("%lu", &pid);
                printf("\n");
                KillProcessByPID(pid);
                printf("\n");
                break;
            }

            case 0:
                running = 0;
                break;

            default:
                printf("Lua chon khong hop le.\n\n");
        }
    }

    printf("Ket thuc chuong trinh.\n");
    return 0;
}
