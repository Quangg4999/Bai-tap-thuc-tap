#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE
#undef _UNICODE
/*
 * Bai 4.2 - PE Scanner da luong (Windows API + Dialog)
 * ===================================================================
 * Quet 1 thu muc (va thu muc con toi da 10 cap), tim cac file PE,
 * hien thi len ListView. Khong treo giao dien khi quet.
 *
 * Kien thuc su dung:
 *   - FindFirstFile / FindNextFile : duyet file trong thu muc
 *   - CreateThread                 : luong quet chay song song voi UI
 *   - CreateSemaphore              : gioi han so luong worker chay cung luc
 *   - CreateMutex (co ten)         : chong chay chuong trinh 2 lan
 *   - CreateMutex (queue lock)     : bao ve hang doi dung chung
 *   - CreateEvent                  : co hieu "hay dung" khi bam Stop
 *
 * Nhan dien PE theo NOI DUNG (chu ky MZ + PE), khong theo duoi file.
 *
 * Build tren Windows (x64), Visual Studio:
 *   Properties -> Linker -> System -> SubSystem = Windows
 */

#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>      /* SHBrowseForFolder */
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

/* ================= ID cac control ================= */
#define ID_EDIT_PATH   101
#define ID_BTN_BROWSE  102
#define ID_BTN_SCAN    103
#define ID_BTN_STOP    104
#define ID_BTN_CLEAR   105
#define ID_LIST        106
#define ID_STATUS      107

/* Thong diep tu luy tao gui ve UI khi tim thay 1 file PE */
#define WM_FOUND_PE    (WM_USER + 1)
#define WM_SCAN_DONE   (WM_USER + 2)

/* ================= Cau hinh ================= */
#define MAX_DEPTH        10       /* do sau toi da thu muc con */
#define MAX_WORKERS      4        /* so luong worker chay cung luc */
#define QUEUE_CAPACITY   100000   /* suc chua hang doi thu muc */
#define MUTEX_APP_NAME   "PeScanner_SingleInstance_Mutex_v1"

/* ================= Cau truc 1 muc trong hang doi ================= */
typedef struct {
    char path[MAX_PATH];
    int  depth;
} DirItem;

/* ================= Bien toan cuc ================= */
static HWND  g_hMain, g_hEdit, g_hList, g_hStatus;
static HWND  g_hBtnScan, g_hBtnStop;

/* Hang doi thu muc can quet (dung chung boi nhieu worker) */
static DirItem g_queue[QUEUE_CAPACITY];
static volatile LONG g_qHead = 0;   /* vi tri lay ra */
static volatile LONG g_qTail = 0;   /* vi tri them vao */

/* Cac doi tuong dong bo hoa */
static HANDLE g_hAppMutex     = NULL;  /* chong chay 2 lan */
static HANDLE g_hQueueMutex   = NULL;  /* bao ve hang doi */
static HANDLE g_hWorkerSem    = NULL;  /* gioi han so worker */
static HANDLE g_hStopEvent    = NULL;  /* co hieu dung */

static volatile LONG g_activeWorkers = 0;  /* so worker dang chay */
static volatile LONG g_totalFiles    = 0;  /* tong file da duyet */
static volatile LONG g_totalPE       = 0;  /* tong file PE tim duoc */
static volatile LONG g_scanning      = 0;  /* 1 = dang quet */
static HANDLE g_hCoordinator = NULL;       /* handle luong dieu phoi */

/* ==================================================================
 * HANG DOI - them / lay (co khoa Mutex bao ve)
 * ================================================================== */
static BOOL QueuePush(const char *path, int depth)
{
    BOOL ok = FALSE;
    WaitForSingleObject(g_hQueueMutex, INFINITE);   /* khoa */
    if (g_qTail < QUEUE_CAPACITY) {
        strcpy(g_queue[g_qTail].path, path);
        g_queue[g_qTail].depth = depth;
        g_qTail++;
        ok = TRUE;
    }
    ReleaseMutex(g_hQueueMutex);                     /* mo khoa */
    return ok;
}

static BOOL QueuePop(DirItem *out)
{
    BOOL ok = FALSE;
    WaitForSingleObject(g_hQueueMutex, INFINITE);
    if (g_qHead < g_qTail) {
        *out = g_queue[g_qHead];
        g_qHead++;
        ok = TRUE;
    }
    ReleaseMutex(g_hQueueMutex);
    return ok;
}

/* ==================================================================
 * KIEM TRA 1 FILE CO PHAI PE KHONG (doc chu ky MZ + PE)
 * Tai su dung logic bai 4.1, rut gon: chi can validate, khong parse.
 * ================================================================== */
static BOOL IsPeFile(const char *filePath)
{
    HANDLE hFile;
    DWORD  read = 0;
    BYTE   dosBuf[64];
    LONG   e_lfanew;
    DWORD  ntSig = 0;
    BOOL   result = FALSE;

    hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    /* Doc 64 byte dau (DOS Header) */
    if (!ReadFile(hFile, dosBuf, 64, &read, NULL) || read < 64) {
        CloseHandle(hFile);
        return FALSE;
    }

    /* Kiem tra chu ky "MZ" (0x5A4D) */
    if (dosBuf[0] != 'M' || dosBuf[1] != 'Z') {
        CloseHandle(hFile);
        return FALSE;
    }

    /* e_lfanew nam o offset 0x3C (4 byte) */
    e_lfanew = *(LONG *)(dosBuf + 0x3C);
    if (e_lfanew <= 0 || e_lfanew > 0x10000000) {   /* gia tri vo ly */
        CloseHandle(hFile);
        return FALSE;
    }

    /* Nhay toi NT Headers, doc 4 byte chu ky */
    if (SetFilePointer(hFile, e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(hFile);
        return FALSE;
    }
    if (!ReadFile(hFile, &ntSig, 4, &read, NULL) || read < 4) {
        CloseHandle(hFile);
        return FALSE;
    }

    /* Chu ky "PE\0\0" = 0x00004550 */
    if (ntSig == 0x00004550) result = TRUE;

    CloseHandle(hFile);
    return result;
}

/* ==================================================================
 * QUET 1 THU MUC: liet ke file (bang FindFirstFile/FindNextFile),
 * file PE -> gui ve UI; thu muc con -> day vao hang doi.
 * ================================================================== */
static void ScanOneDir(const char *dirPath, int depth)
{
    char pattern[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE hFind;

    /* Tao mau tim "duong_dan\*" de liet ke moi thu */
    snprintf(pattern, sizeof(pattern), "%s\\*", dirPath);

    hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        /* Kiem tra co hieu dung: thoat ngay neu nguoi dung bam Stop */
        if (WaitForSingleObject(g_hStopEvent, 0) == WAIT_OBJECT_0) break;

        /* Bo qua "." va ".." (thu muc hien tai va cha) */
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char fullPath[MAX_PATH];
        snprintf(fullPath, sizeof(fullPath), "%s\\%s", dirPath, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* La thu muc con -> day vao hang doi neu chua vuot do sau */
            if (depth + 1 <= MAX_DEPTH) {
                QueuePush(fullPath, depth + 1);
            }
        } else {
            /* La file -> dem, kiem tra PE */
            InterlockedIncrement(&g_totalFiles);
            if (IsPeFile(fullPath)) {
                InterlockedIncrement(&g_totalPE);
                /* Gui duong dan ve UI (cap phat, UI se giai phong) */
                char *copy = (char *)malloc(strlen(fullPath) + 1);
                if (copy) {
                    strcpy(copy, fullPath);
                    PostMessageA(g_hMain, WM_FOUND_PE, 0, (LPARAM)copy);
                }
            }
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

/* ==================================================================
 * HAM CHAY CUA MOI WORKER THREAD
 * ================================================================== */
static DWORD WINAPI WorkerThread(LPVOID param)
{
    DirItem item;
    (void)param;

    /* Lien tuc lay thu muc tu hang doi ra quet */
    while (WaitForSingleObject(g_hStopEvent, 0) != WAIT_OBJECT_0) {
        if (QueuePop(&item)) {
            ScanOneDir(item.path, item.depth);
        } else {
            /* Hang doi tam rong -> cho 1 chut roi thu lai.
               Neu khong con worker nao dang lam VA hang doi rong -> xong. */
            if (g_qHead >= g_qTail) break;
            Sleep(10);
        }
    }

    /* Worker ket thuc: tra 1 "cho trong" ve semaphore, giam bo dem */
    InterlockedDecrement(&g_activeWorkers);
    ReleaseSemaphore(g_hWorkerSem, 1, NULL);
    return 0;
}

/* ==================================================================
 * LUONG DIEU PHOI: tao va quan ly cac worker
 * ================================================================== */
static DWORD WINAPI CoordinatorThread(LPVOID param)
{
    HANDLE workers[MAX_WORKERS];
    int numCreated = 0;
    int i;
    (void)param;

    /* Tao toi da MAX_WORKERS worker (xin phep semaphore truoc) */
    for (i = 0; i < MAX_WORKERS; i++) {
        WaitForSingleObject(g_hWorkerSem, INFINITE);   /* xin 1 slot */
        if (WaitForSingleObject(g_hStopEvent, 0) == WAIT_OBJECT_0) {
            ReleaseSemaphore(g_hWorkerSem, 1, NULL);
            break;
        }
        InterlockedIncrement(&g_activeWorkers);
        workers[numCreated] = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
        if (workers[numCreated]) numCreated++;
        else {
            InterlockedDecrement(&g_activeWorkers);
            ReleaseSemaphore(g_hWorkerSem, 1, NULL);
        }
    }

    /* Cho tat ca worker ket thuc */
    if (numCreated > 0)
        WaitForMultipleObjects(numCreated, workers, TRUE, INFINITE);

    for (i = 0; i < numCreated; i++)
        if (workers[i]) CloseHandle(workers[i]);

    /* Bao UI: quet xong */
    g_scanning = 0;
    PostMessageA(g_hMain, WM_SCAN_DONE, 0, 0);
    return 0;
}

/* ==================================================================
 * BAT DAU QUET
 * ================================================================== */
static void StartScan(void)
{
    char path[MAX_PATH];
    DWORD attr;

    if (g_scanning) return;   /* dang quet roi */

    /* Lay duong dan tu o text */
    GetWindowTextA(g_hEdit, path, MAX_PATH);
    if (strlen(path) == 0) {
        MessageBoxA(g_hMain, "Hay nhap hoac chon duong dan thu muc.", "Thong bao", MB_ICONINFORMATION);
        return;
    }

    /* Kiem tra duong dan co ton tai va la thu muc */
    attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        MessageBoxA(g_hMain, "Duong dan khong hop le hoac khong phai thu muc.", "Loi", MB_ICONERROR);
        return;
    }

    /* Reset trang thai */
    g_qHead = 0; g_qTail = 0;
    g_totalFiles = 0; g_totalPE = 0;
    g_activeWorkers = 0;
    ResetEvent(g_hStopEvent);      /* tat co hieu dung */
    g_scanning = 1;

    /* Day thu muc goc vao hang doi (depth = 0) */
    QueuePush(path, 0);

    /* Tao lai semaphore voi so slot = MAX_WORKERS */
    if (g_hWorkerSem) CloseHandle(g_hWorkerSem);
    g_hWorkerSem = CreateSemaphoreA(NULL, MAX_WORKERS, MAX_WORKERS, NULL);

    /* Tao luong dieu phoi */
    if (g_hCoordinator) CloseHandle(g_hCoordinator);
    g_hCoordinator = CreateThread(NULL, 0, CoordinatorThread, NULL, 0, NULL);

    /* Cap nhat trang thai nut */
    EnableWindow(g_hBtnScan, FALSE);
    EnableWindow(g_hBtnStop, TRUE);
    SetWindowTextA(g_hStatus, "Dang quet...");
}

/* ==================================================================
 * DUNG QUET
 * ================================================================== */
static void StopScan(void)
{
    if (!g_scanning) return;
    SetEvent(g_hStopEvent);        /* bat co hieu dung */
    SetWindowTextA(g_hStatus, "Dang dung...");
}

/* ==================================================================
 * HOP THOAI CHON THU MUC (Browse)
 * ================================================================== */
static void BrowseFolder(void)
{
    BROWSEINFOA bi = {0};
    LPITEMIDLIST pidl;
    char path[MAX_PATH];

    bi.hwndOwner = g_hMain;
    bi.lpszTitle = "Chon thu muc de quet:";
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    pidl = SHBrowseForFolderA(&bi);
    if (pidl) {
        if (SHGetPathFromIDListA(pidl, path)) {
            SetWindowTextA(g_hEdit, path);
        }
        CoTaskMemFree(pidl);
    }
}

/* ==================================================================
 * WINDOW PROCEDURE
 * ================================================================== */
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {

    case WM_CREATE: {
        LVCOLUMNA col;

        /* O text nhap duong dan */
        CreateWindowA("STATIC", "Duong dan thu muc:",
            WS_CHILD | WS_VISIBLE, 10, 14, 130, 20, hWnd, NULL, NULL, NULL);
        g_hEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            145, 10, 400, 26, hWnd, (HMENU)ID_EDIT_PATH, NULL, NULL);

        /* Nut Browse */
        CreateWindowA("BUTTON", "Browse...",
            WS_CHILD | WS_VISIBLE, 555, 10, 90, 26, hWnd, (HMENU)ID_BTN_BROWSE, NULL, NULL);

        /* Cac nut Scan / Stop / Clear */
        g_hBtnScan = CreateWindowA("BUTTON", "SCAN",
            WS_CHILD | WS_VISIBLE, 145, 46, 90, 30, hWnd, (HMENU)ID_BTN_SCAN, NULL, NULL);
        g_hBtnStop = CreateWindowA("BUTTON", "STOP",
            WS_CHILD | WS_VISIBLE | WS_DISABLED, 245, 46, 90, 30, hWnd, (HMENU)ID_BTN_STOP, NULL, NULL);
        CreateWindowA("BUTTON", "CLEAR",
            WS_CHILD | WS_VISIBLE, 345, 46, 90, 30, hWnd, (HMENU)ID_BTN_CLEAR, NULL, NULL);

        /* ListView ket qua */
        g_hList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | LVS_REPORT,
            10, 86, 635, 380, hWnd, (HMENU)ID_LIST, NULL, NULL);
        ListView_SetExtendedListViewStyle(g_hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        ZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = "#";           col.cx = 50;  ListView_InsertColumn(g_hList, 0, &col);
        col.pszText = "Duong dan file PE"; col.cx = 560; ListView_InsertColumn(g_hList, 1, &col);

        /* Thanh trang thai */
        g_hStatus = CreateWindowA("STATIC", "San sang.",
            WS_CHILD | WS_VISIBLE, 10, 474, 635, 20, hWnd, (HMENU)ID_STATUS, NULL, NULL);

        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
            case ID_BTN_BROWSE: BrowseFolder(); return 0;
            case ID_BTN_SCAN:   StartScan();    return 0;
            case ID_BTN_STOP:   StopScan();     return 0;
            case ID_BTN_CLEAR:
                ListView_DeleteAllItems(g_hList);
                SetWindowTextA(g_hStatus, "Da xoa ket qua.");
                return 0;
        }
        break;

    /* Nhan 1 file PE tu worker thread -> them vao ListView */
    case WM_FOUND_PE: {
        char *path = (char *)lParam;
        if (path) {
            LVITEMA it;
            char num[16];
            int idx = ListView_GetItemCount(g_hList);

            sprintf(num, "%d", idx + 1);
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = idx;
            it.pszText = num;
            ListView_InsertItem(g_hList, &it);
            ListView_SetItemText(g_hList, idx, 1, path);

            free(path);   /* giai phong bo nho worker da cap phat */

            /* Cap nhat thanh trang thai */
            char status[128];
            sprintf(status, "Dang quet... Da duyet %ld file, tim thay %ld file PE.",
                    g_totalFiles, g_totalPE);
            SetWindowTextA(g_hStatus, status);
        }
        return 0;
    }

    /* Quet xong */
    case WM_SCAN_DONE: {
        char status[128];
        sprintf(status, "Xong. Da duyet %ld file, tim thay %ld file PE.",
                g_totalFiles, g_totalPE);
        SetWindowTextA(g_hStatus, status);
        EnableWindow(g_hBtnScan, TRUE);
        EnableWindow(g_hBtnStop, FALSE);
        return 0;
    }

    case WM_DESTROY:
        SetEvent(g_hStopEvent);   /* bao cac luong dung */
        if (g_scanning && g_hCoordinator)
            WaitForSingleObject(g_hCoordinator, 3000);  /* cho toi da 3s */
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

/* ==================================================================
 * WINMAIN
 * ================================================================== */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    WNDCLASSA wc;
    MSG msg;
    INITCOMMONCONTROLSEX icc;

    (void)hPrev; (void)lpCmd;

    /* --- CHONG CHAY 2 LAN: tao Mutex co ten --- */
    g_hAppMutex = CreateMutexA(NULL, TRUE, MUTEX_APP_NAME);
    if (g_hAppMutex == NULL) return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxA(NULL,
            "Chuong trinh da dang chay!\nKhong the mo them mot ban nua.",
            "PE Scanner", MB_ICONWARNING | MB_OK);
        CloseHandle(g_hAppMutex);
        return 0;
    }

    /* --- Khoi tao control chung --- */
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    /* --- Tao cac doi tuong dong bo hoa --- */
    g_hQueueMutex = CreateMutexA(NULL, FALSE, NULL);          /* khoa hang doi */
    g_hStopEvent  = CreateEventA(NULL, TRUE, FALSE, NULL);    /* co hieu dung (manual-reset) */

    /* --- Dang ky lop cua so --- */
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "PeScannerWndClass";
    if (!RegisterClassA(&wc)) return 1;

    g_hMain = CreateWindowExA(0, "PeScannerWndClass",
        "PE Scanner (Bai 4.2) - Quet thu muc tim file PE",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 675, 545,
        NULL, NULL, hInst, NULL);
    if (!g_hMain) return 1;

    ShowWindow(g_hMain, nShow);
    UpdateWindow(g_hMain);

    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    /* --- Don dep --- */
    if (g_hQueueMutex) CloseHandle(g_hQueueMutex);
    if (g_hStopEvent)  CloseHandle(g_hStopEvent);
    if (g_hWorkerSem)  CloseHandle(g_hWorkerSem);
    if (g_hCoordinator) CloseHandle(g_hCoordinator);
    if (g_hAppMutex)   CloseHandle(g_hAppMutex);   /* nha Mutex chong chay 2 lan */

    return (int)msg.wParam;
}
