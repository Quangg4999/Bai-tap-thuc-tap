#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE
#undef _UNICODE
/*
 * Bai 3.2 - Service Controller (day du 3 phan)
 * ===================================================================
 * File nay dong 2 VAI TRO tuy tham so dong lenh:
 *
 *  (A) CHE DO CONTROLLER (chay binh thuong, KHONG tham so dac biet):
 *      - list            : liet ke tat ca Windows Service
 *      - start <ten>     : khoi dong 1 service
 *      - stop  <ten>     : dung 1 service
 *      - install         : cai dat chinh minh thanh service "PerfLoggerSvc"
 *      - uninstall       : go service do
 *      - (khong tham so) : hien menu tuong tac
 *
 *  (B) CHE DO SERVICE (khi SCM goi voi tham so "runservice"):
 *      - Chay nen, moi 60 giay ghi 1 dong log (RAM/CPU/DISK)
 *      - Tu xoay log khi > 1MB hoac qua 5 ngay
 *      - Da cau hinh auto-restart neu bi kill
 *
 * YEU CAU: phai chay voi quyen ADMINISTRATOR (install/uninstall/start/stop).
 *
 * Build tren Windows (x64), Visual Studio:
 *   cl /Od /std:c11 service_controller.c
 *   (Advapi32.lib thuong link san mac dinh)
 *
 * File log ghi tai: C:\PerfLog\perf.log
 */

#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <psapi.h>

#pragma comment(lib, "Advapi32.lib")

/* ================= Cau hinh chung ================= */
#define SERVICE_NAME        "PerfLoggerSvc"
#define SERVICE_DISPLAY     "Perf Logger Service (Bai 3.2)"
#define LOG_DIR             "C:\\PerfLog"
#define LOG_FILE            "C:\\PerfLog\\perf.log"
#define LOG_MAX_BYTES       (1 * 1024 * 1024)      /* 1 MB */
#define LOG_MAX_AGE_SEC     (5 * 24 * 60 * 60)     /* 5 ngay */
#define SAMPLE_INTERVAL_MS  (60 * 1000)            /* 60 giay */

/* ================= Bien toan cuc cho service ================= */
SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle  = NULL;
HANDLE                g_StopEvent      = NULL;

/* ==================================================================
 * TIEN ICH: in loi
 * ================================================================== */
void InFormLoi(const char *hanhDong)
{
    fprintf(stderr, "Loi: %s (ma loi Windows: %lu)\n", hanhDong, GetLastError());
}

/* ==================================================================
 * PHAN 1A: LIET KE TAT CA SERVICE
 * ================================================================== */
void ListServices(void)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm == NULL) {
        InFormLoi("khong mo duoc Service Control Manager");
        return;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;

    /* Goi lan 1 de biet can bao nhieu byte buffer */
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, NULL, 0, &bytesNeeded,
                          &servicesReturned, &resumeHandle, NULL);

    BYTE *buffer = (BYTE *)malloc(bytesNeeded);
    if (!buffer) {
        printf("Khong cap phat duoc bo nho.\n");
        CloseServiceHandle(scm);
        return;
    }

    if (!EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               SERVICE_STATE_ALL, buffer, bytesNeeded,
                               &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
        InFormLoi("khong liet ke duoc service");
        free(buffer);
        CloseServiceHandle(scm);
        return;
    }

    ENUM_SERVICE_STATUS_PROCESSA *services = (ENUM_SERVICE_STATUS_PROCESSA *)buffer;

    printf("\n%-40s %-12s %s\n", "TEN SERVICE", "TRANG THAI", "TEN HIEN THI");
    printf("--------------------------------------------------------------------------------\n");

    for (DWORD i = 0; i < servicesReturned; i++) {
        const char *state;
        switch (services[i].ServiceStatusProcess.dwCurrentState) {
            case SERVICE_RUNNING:          state = "RUNNING";     break;
            case SERVICE_STOPPED:          state = "STOPPED";     break;
            case SERVICE_PAUSED:           state = "PAUSED";      break;
            case SERVICE_START_PENDING:    state = "STARTING";    break;
            case SERVICE_STOP_PENDING:     state = "STOPPING";    break;
            default:                       state = "?";           break;
        }
        printf("%-40s %-12s %s\n",
               services[i].lpServiceName, state, services[i].lpDisplayName);
    }

    printf("--------------------------------------------------------------------------------\n");
    printf("Tong so service: %lu\n\n", servicesReturned);

    free(buffer);
    CloseServiceHandle(scm);
}

/* ==================================================================
 * PHAN 1B: START 1 SERVICE
 * ================================================================== */
void StartOneService(const char *name)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { InFormLoi("khong mo duoc SCM"); return; }

    SC_HANDLE svc = OpenServiceA(scm, name, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        InFormLoi("khong mo duoc service (kiem tra ten dung chua)");
        CloseServiceHandle(scm);
        return;
    }

    if (StartServiceA(svc, 0, NULL)) {
        printf("[OK] Da gui lenh START toi service '%s'.\n", name);
    } else {
        InFormLoi("khong start duoc service");
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ==================================================================
 * PHAN 1C: STOP 1 SERVICE
 * ================================================================== */
void StopOneService(const char *name)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { InFormLoi("khong mo duoc SCM"); return; }

    SC_HANDLE svc = OpenServiceA(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) {
        InFormLoi("khong mo duoc service");
        CloseServiceHandle(scm);
        return;
    }

    SERVICE_STATUS status;
    if (ControlService(svc, SERVICE_CONTROL_STOP, &status)) {
        printf("[OK] Da gui lenh STOP toi service '%s'.\n", name);
    } else {
        InFormLoi("khong stop duoc service");
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ==================================================================
 * PHAN 2A: CAI DAT CHINH MINH THANH SERVICE (CreateService)
 * ================================================================== */
void InstallService(void)
{
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    /* Duong dan chay service = "duong_dan_exe runservice"
       -> khi SCM khoi dong, no chay chinh file nay voi tham so "runservice" */
    char cmd[MAX_PATH + 32];
    snprintf(cmd, sizeof(cmd), "\"%s\" runservice", exePath);

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { InFormLoi("khong mo duoc SCM (can quyen Admin?)"); return; }

    SC_HANDLE svc = CreateServiceA(
        scm,
        SERVICE_NAME,
        SERVICE_DISPLAY,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,       /* khoi dong thu cong (co the doi thanh AUTO_START) */
        SERVICE_ERROR_NORMAL,
        cmd,
        NULL, NULL, NULL, NULL, NULL);

    if (!svc) {
        InFormLoi("khong tao duoc service (co the da ton tai, hoac thieu quyen Admin)");
        CloseServiceHandle(scm);
        return;
    }

    printf("[OK] Da cai dat service '%s'.\n", SERVICE_NAME);

    /* --- Cau hinh AUTO-RESTART neu bi kill --- */
    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART; actions[0].Delay = 5000;  /* restart sau 5s */
    actions[1].Type = SC_ACTION_RESTART; actions[1].Delay = 5000;
    actions[2].Type = SC_ACTION_RESTART; actions[2].Delay = 5000;

    SERVICE_FAILURE_ACTIONSA fa = {0};
    fa.dwResetPeriod = 86400;     /* reset bo dem loi sau 1 ngay */
    fa.lpRebootMsg   = NULL;
    fa.lpCommand     = NULL;
    fa.cActions      = 3;
    fa.lpsaActions   = actions;

    if (ChangeServiceConfig2A(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa)) {
        printf("[OK] Da cau hinh AUTO-RESTART (tu khoi dong lai sau 5s neu bi kill).\n");
    } else {
        InFormLoi("khong cau hinh duoc auto-restart");
    }

    printf("     De chay: service_controller.exe start %s\n", SERVICE_NAME);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ==================================================================
 * PHAN 2B: GO SERVICE (DeleteService)
 * ================================================================== */
void UninstallService(void)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { InFormLoi("khong mo duoc SCM"); return; }

    SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!svc) {
        InFormLoi("khong mo duoc service (co the chua cai)");
        CloseServiceHandle(scm);
        return;
    }

    /* Thu dung truoc khi xoa */
    SERVICE_STATUS status;
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    Sleep(1000);

    if (DeleteService(svc)) {
        printf("[OK] Da go service '%s'.\n", SERVICE_NAME);
    } else {
        InFormLoi("khong go duoc service");
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ==================================================================
 * PHAN 3A: XOAY LOG (xoa khi > 1MB hoac qua 5 ngay)
 * ================================================================== */
void RotateLogIfNeeded(void)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(LOG_FILE, GetFileExInfoStandard, &fad)) {
        return;   /* file chua ton tai -> khong can xoay */
    }

    /* 1) Kiem tra kich thuoc */
    ULONGLONG size = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    int needRotate = (size > LOG_MAX_BYTES);

    /* 2) Kiem tra tuoi file (theo thoi gian tao) */
    if (!needRotate) {
        FILETIME ftNow;
        GetSystemTimeAsFileTime(&ftNow);
        ULONGLONG now = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;
        ULONGLONG created = ((ULONGLONG)fad.ftCreationTime.dwHighDateTime << 32)
                            | fad.ftCreationTime.dwLowDateTime;
        /* FILETIME tinh theo don vi 100ns -> doi ra giay */
        ULONGLONG ageSec = (now - created) / 10000000ULL;
        if (ageSec > LOG_MAX_AGE_SEC) needRotate = 1;
    }

    if (needRotate) {
        /* Doi ten file cu thanh perf.old (ghi de neu da co), roi tao moi tinh */
        char oldName[] = LOG_DIR "\\perf.old";
        DeleteFileA(oldName);
        MoveFileA(LOG_FILE, oldName);
    }
}

/* ==================================================================
 * PHAN 3B: LAY CHI SO HIEU NANG (RAM, CPU, DISK) VA GHI LOG
 * ================================================================== */

/* Tinh % CPU toan he thong bang lay mau 2 lan (giong bai 2.2) */
static ULONGLONG FileTimeToULL(const FILETIME *ft) {
    return ((ULONGLONG)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
}

double GetCpuUsagePercent(void)
{
    FILETIME idle1, kernel1, user1, idle2, kernel2, user2;

    GetSystemTimes(&idle1, &kernel1, &user1);
    Sleep(500);   /* lay mau cach nhau 0.5s */
    GetSystemTimes(&idle2, &kernel2, &user2);

    ULONGLONG idle   = FileTimeToULL(&idle2)   - FileTimeToULL(&idle1);
    ULONGLONG kernel = FileTimeToULL(&kernel2) - FileTimeToULL(&kernel1);
    ULONGLONG user   = FileTimeToULL(&user2)   - FileTimeToULL(&user1);

    ULONGLONG total = kernel + user;   /* kernel da bao gom ca idle */
    if (total == 0) return 0.0;
    /* % ban = (total - idle) / total * 100 */
    return (double)(total - idle) * 100.0 / (double)total;
}

void WritePerfLogLine(void)
{
    /* --- RAM --- */
    MEMORYSTATUSEX mem = {0};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    DWORD ramPercent = mem.dwMemoryLoad;
    ULONGLONG ramUsedMB = (mem.ullTotalPhys - mem.ullAvailPhys) / (1024 * 1024);
    ULONGLONG ramTotalMB = mem.ullTotalPhys / (1024 * 1024);

    /* --- CPU --- */
    double cpu = GetCpuUsagePercent();

    /* --- DISK (dung luong con trong o C) --- */
    ULARGE_INTEGER freeBytes, totalBytes, totalFree;
    GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, &totalFree);
    ULONGLONG diskFreeGB = freeBytes.QuadPart / (1024ULL * 1024 * 1024);
    ULONGLONG diskTotalGB = totalBytes.QuadPart / (1024ULL * 1024 * 1024);

    /* --- Thoi gian hien tai --- */
    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    char timeStr[32];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", lt);

    /* --- Ghi vao file (append) --- */
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        fprintf(f, "[%s] RAM: %lu%% (%llu/%llu MB) | CPU: %.1f%% | DISK C: con %llu/%llu GB\n",
                timeStr, ramPercent, ramUsedMB, ramTotalMB,
                cpu, diskFreeGB, diskTotalGB);
        fclose(f);
    }
}

/* ==================================================================
 * PHAN 2C: HAM XU LY LENH DIEU KHIEN TU SCM
 * ================================================================== */
void WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    switch (ctrlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            /* SCM yeu cau dung -> bao "dang dung" va kich hoat event dung vong lap */
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            SetEvent(g_StopEvent);
            break;
        default:
            break;
    }
}

/* ==================================================================
 * PHAN 2D: HAM CHINH CUA SERVICE (SCM goi ham nay khi service chay)
 * ================================================================== */
void WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
    (void)argc; (void)argv;

    /* Dang ky ham xu ly lenh dieu khien */
    g_StatusHandle = RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    /* Khoi tao trang thai */
    g_ServiceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState            = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwWin32ExitCode           = 0;
    g_ServiceStatus.dwCheckPoint              = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    /* Tao event dung (thu cong reset, ban dau chua signaled) */
    g_StopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent) {
        g_ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    /* Tao thu muc log neu chua co */
    CreateDirectoryA(LOG_DIR, NULL);

    /* Bao SCM: service da chay OK */
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    /* Ghi 1 dong danh dau service vua khoi dong */
    FILE *f = fopen(LOG_FILE, "a");
    if (f) { fprintf(f, "===== SERVICE KHOI DONG =====\n"); fclose(f); }

    /* ===== VONG LAP CHINH: moi 60s ghi 1 dong log ===== */
    while (WaitForSingleObject(g_StopEvent, 0) != WAIT_OBJECT_0) {
        RotateLogIfNeeded();
        WritePerfLogLine();

        /* Cho 60s HOAC cho den khi co lenh dung (thoat som neu bi dung) */
        if (WaitForSingleObject(g_StopEvent, SAMPLE_INTERVAL_MS) == WAIT_OBJECT_0) {
            break;
        }
    }

    /* Ghi 1 dong danh dau service dung */
    f = fopen(LOG_FILE, "a");
    if (f) { fprintf(f, "===== SERVICE DUNG =====\n"); fclose(f); }

    /* Bao SCM: da dung han */
    CloseHandle(g_StopEvent);
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

/* ==================================================================
 * MAIN - phan biet CONTROLLER vs SERVICE qua tham so
 * ================================================================== */
int main(int argc, char *argv[])
{
    /* --- CHE DO SERVICE: SCM goi voi tham so "runservice" --- */
    if (argc >= 2 && strcmp(argv[1], "runservice") == 0) {
        SERVICE_TABLE_ENTRYA serviceTable[] = {
            { SERVICE_NAME, ServiceMain },
            { NULL, NULL }
        };
        /* Ket noi voi SCM va trao quyen dieu khien cho ServiceMain.
           Ham nay chi tra ve khi service dung han. */
        StartServiceCtrlDispatcherA(serviceTable);
        return 0;
    }

    /* --- CHE DO CONTROLLER: chay binh thuong tu command line --- */
    printf("========== SERVICE CONTROLLER (Bai 3.2) ==========\n\n");

    if (argc >= 2) {
        if (strcmp(argv[1], "list") == 0) {
            ListServices();
        } else if (strcmp(argv[1], "start") == 0 && argc >= 3) {
            StartOneService(argv[2]);
        } else if (strcmp(argv[1], "stop") == 0 && argc >= 3) {
            StopOneService(argv[2]);
        } else if (strcmp(argv[1], "install") == 0) {
            InstallService();
        } else if (strcmp(argv[1], "uninstall") == 0) {
            UninstallService();
        } else {
            printf("Tham so khong hop le.\n");
        }
        return 0;
    }

    /* --- Khong co tham so: hien menu tuong tac --- */
    int running = 1;
    while (running) {
        printf("\n1. Liet ke tat ca service\n");
        printf("2. Start 1 service\n");
        printf("3. Stop 1 service\n");
        printf("4. Cai dat PerfLoggerSvc (can Admin)\n");
        printf("5. Go PerfLoggerSvc (can Admin)\n");
        printf("6. Start PerfLoggerSvc\n");
        printf("7. Stop PerfLoggerSvc\n");
        printf("0. Thoat\n");
        printf("Chon: ");

        int choice;
        if (scanf("%d", &choice) != 1) { while (getchar() != '\n'); continue; }
        while (getchar() != '\n');
        printf("\n");

        char name[256];
        switch (choice) {
            case 1: ListServices(); break;
            case 2:
                printf("Nhap ten service can start: ");
                fgets(name, sizeof(name), stdin);
                name[strcspn(name, "\n")] = '\0';
                StartOneService(name);
                break;
            case 3:
                printf("Nhap ten service can stop: ");
                fgets(name, sizeof(name), stdin);
                name[strcspn(name, "\n")] = '\0';
                StopOneService(name);
                break;
            case 4: InstallService(); break;
            case 5: UninstallService(); break;
            case 6: StartOneService(SERVICE_NAME); break;
            case 7: StopOneService(SERVICE_NAME); break;
            case 0: running = 0; break;
            default: printf("Lua chon khong hop le.\n");
        }
    }

    printf("Ket thuc.\n");
    return 0;
}
