#define _CRT_SECURE_NO_WARNINGS
/*
 * client.c - Scan Client CLI 5.2
 * ===================================================================
 * Nang cap tu 5.1:
 *   [MOI] Reconnect trong 10s + gui RESUME de nhan tiep event da mat
 *   [MOI] Theo doi lastEventSeq de biet da nhan toi dau
 *   [MOI] Hien thi canh bao khi nhan FLOW_CONTROL (dang bi drop event)
 *   [MOI] Hien thi thong tin PE chi tiet tu MSG_PEINFO
 *   [MOI] Doc ma loi chuan hoa thay vi doan tu chuoi
 *
 * CLI:
 *   client.exe scan "D:\a.exe" --priority high
 *   client.exe query <jobId>
 *   client.exe cancel <jobId>
 *   client.exe scan "D:\a.exe" --verbose      (hien ca PROGRESS/PEINFO)
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "framing.h"

#define RECONNECT_WINDOW_MS  10000
#define RECONNECT_DELAY_MS   500

static int   g_sessionId = 0;
static DWORD g_lastSeq = 0;     /* seq event cuoi cung da nhan */
static int   g_verbose = 0;

/* ==================================================================
 * MO PIPE (thu vai lan neu server ban)
 * ================================================================== */
static HANDLE OpenPipe(void)
{
    HANDLE hPipe;
    int retry;

    for (retry = 0; retry < 10; retry++) {
        hPipe = CreateFileA(PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            /* Pipe ben service la BYTE mode - client cung phai BYTE mode.
             * Khong can SetNamedPipeHandleState vi mac dinh da la BYTE. */
            return hPipe;
        }
        if (GetLastError() != ERROR_PIPE_BUSY) return INVALID_HANDLE_VALUE;
        WaitNamedPipeA(PIPE_NAME, 2000);
    }
    return INVALID_HANDLE_VALUE;
}

/* ==================================================================
 * BAT TAY LAN DAU (HELLO -> WELCOME)
 * ================================================================== */
static HANDLE ConnectAndHandshake(FrameReader* fr)
{
    HANDLE hPipe;
    char hello[256], value[MAX_VALUE_SIZE + 1];
    char user[128] = "";
    DWORD n = sizeof(user);
    WORD type;
    DWORD seq, len;
    int rc;

    hPipe = OpenPipe();
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("Loi: khong ket noi duoc service. Service da chay chua?\n");
        printf("     Chay: service.exe console\n");
        return INVALID_HANDLE_VALUE;
    }

    FrameReaderInit(fr, hPipe, FALSE);

    /* Khai bao PID va USER THAT.
     * Service se doi chieu voi thong tin kernel cung cap - khai sai
     * la bi tu choi ngay (ERR_HANDSHAKE). */
    GetUserNameA(user, &n);
    sprintf(hello, "cli|%lu|%s|%d", GetCurrentProcessId(), user, PROTO_VERSION);

    rc = FrameSend(hPipe, FALSE, MSG_HELLO, 0, hello, (DWORD)strlen(hello), 5000);
    if (rc != ERR_NONE) {
        printf("Loi: gui HELLO that bai (%s)\n", FrameErrName(rc));
        CloseHandle(hPipe);
        return INVALID_HANDLE_VALUE;
    }

    rc = FrameRecv(fr, &type, &seq, value, MAX_VALUE_SIZE, &len, 10000);
    if (rc != ERR_NONE) {
        printf("Loi: khong nhan duoc phan hoi (%s)\n", FrameErrName(rc));
        CloseHandle(hPipe);
        return INVALID_HANDLE_VALUE;
    }
    value[len] = '\0';

    if (type == MSG_ERROR) {
        printf("Service tu choi: %s\n", value);
        CloseHandle(hPipe);
        return INVALID_HANDLE_VALUE;
    }
    if (type != MSG_WELCOME) {
        printf("Loi: mong doi WELCOME, nhan duoc 0x%04X\n", type);
        CloseHandle(hPipe);
        return INVALID_HANDLE_VALUE;
    }

    /* Lay sessionId de con RESUME neu mat ket noi */
    {
        char* p = strstr(value, "sessionId=");
        if (p) g_sessionId = atoi(p + 10);
    }

    printf("[Ket noi OK] %s\n\n", value);
    return hPipe;
}

/* ==================================================================
 * NOI LAI PHIEN SAU KHI MAT KET NOI
 * ------------------------------------------------------------------
 * Co che giong TCP sequence number:
 *   Client noi "toi nhan toi seq X roi", service gui tiep tu X+1.
 * Service giu session them 10 giay sau khi mat ket noi de cho viec nay.
 * ================================================================== */
static HANDLE ReconnectAndResume(FrameReader* fr)
{
    DWORD deadline = GetTickCount() + RECONNECT_WINDOW_MS;
    char req[128], value[MAX_VALUE_SIZE + 1];
    WORD type;
    DWORD seq, len;
    int attempt = 0;

    if (g_sessionId == 0) return INVALID_HANDLE_VALUE;

    printf("\n  [!] Mat ket noi. Dang thu noi lai (toi da %d giay)...\n",
        RECONNECT_WINDOW_MS / 1000);

    while (GetTickCount() < deadline) {
        HANDLE hPipe;
        int rc;

        attempt++;
        Sleep(RECONNECT_DELAY_MS);

        hPipe = OpenPipe();
        if (hPipe == INVALID_HANDLE_VALUE) continue;

        FrameReaderInit(fr, hPipe, FALSE);

        sprintf(req, "%d|%lu", g_sessionId, g_lastSeq);
        rc = FrameSend(hPipe, FALSE, MSG_RESUME, 0, req, (DWORD)strlen(req), 3000);
        if (rc != ERR_NONE) { CloseHandle(hPipe); continue; }

        rc = FrameRecv(fr, &type, &seq, value, MAX_VALUE_SIZE, &len, 5000);
        if (rc != ERR_NONE) { CloseHandle(hPipe); continue; }
        value[len] = '\0';

        if (type == MSG_RESUMED) {
            printf("  [OK] Noi lai thanh cong sau %d lan thu: %s\n", attempt, value);
            printf("       Nhan tiep event tu seq > %lu\n\n", g_lastSeq);
            return hPipe;
        }
        if (type == MSG_ERROR) {
            printf("  [X] Khong noi lai duoc: %s\n", value);
            CloseHandle(hPipe);
            return INVALID_HANDLE_VALUE;
        }
        CloseHandle(hPipe);
    }

    printf("  [X] Het thoi gian, khong noi lai duoc.\n");
    return INVALID_HANDLE_VALUE;
}

/* ==================================================================
 * IN MOT EVENT
 * ================================================================== */
static void PrintEvent(WORD type, DWORD seq, const char* value)
{
    switch (type) {
    case MSG_ACCEPTED:
        printf("  [ACCEPTED #%lu] %s\n", seq, value);
        break;

    case MSG_PROGRESS:
        if (g_verbose) printf("  [PROGRESS #%lu] %s\n", seq, value);
        break;

    case MSG_PEINFO:
        if (g_verbose) printf("  [PE INFO  #%lu] %s\n", seq, value);
        break;

    case MSG_DELAYED:
        printf("  [DELAYED  #%lu] %s\n", seq, value);
        printf("      -> may dang qua tai, job uu tien thap bi hoan\n");
        break;

    case MSG_FLOW_CONTROL:
        /* Day la diem quan trong: client BIET minh dang bi luoc bot
         * thong tin, thay vi tuong service da chet. */
        printf("  [FLOW CTL #%lu] %s\n", seq, value);
        printf("      -> service dang bo bot event tien do (khong anh huong ket qua)\n");
        break;

    case MSG_STATUS:
        printf("  [STATUS   #%lu] %s\n", seq, value);
        break;

    case MSG_ERROR: {
        int code = atoi(value);
        const char* msg = strchr(value, '|');
        printf("  [ERROR    #%lu] ma %d (%s): %s\n",
            seq, code, FrameErrName(code), msg ? msg + 1 : value);
        break;
    }

    case MSG_RESULT:
        printf("\n  =============== KET QUA ===============\n");
        {
            /* Tach chuoi "a=b|c=d|..." de in cho de doc */
            char copy[MAX_VALUE_SIZE + 1];
            char* tok;
            strncpy(copy, value, MAX_VALUE_SIZE);
            copy[MAX_VALUE_SIZE] = '\0';
            tok = strtok(copy, "|");
            while (tok) {
                char* eq = strchr(tok, '=');
                if (eq) {
                    *eq = '\0';
                    printf("  %-12s : %s\n", tok, eq + 1);
                }
                else {
                    printf("  %s\n", tok);
                }
                tok = strtok(NULL, "|");
            }
        }
        printf("  =======================================\n");
        break;

    default:
        printf("  [? 0x%04X #%lu] %s\n", type, seq, value);
        break;
    }
}

/* ==================================================================
 * LENH SCAN - vong lap nhan streaming, co reconnect
 * ================================================================== */
static void DoScan(const char* path, int priority)
{
    FrameReader fr;
    HANDLE hPipe;
    char req[MAX_PATH + 64], value[MAX_VALUE_SIZE + 1];
    WORD type;
    DWORD seq, len;
    BOOL done = FALSE;
    int rc;

    hPipe = ConnectAndHandshake(&fr);
    if (hPipe == INVALID_HANDLE_VALUE) return;

    sprintf(req, "%s|%d|30000", path, priority);
    rc = FrameSend(hPipe, FALSE, MSG_SCAN, 0, req, (DWORD)strlen(req), 5000);
    if (rc != ERR_NONE) {
        printf("Loi: gui yeu cau scan that bai (%s)\n", FrameErrName(rc));
        CloseHandle(hPipe);
        return;
    }
    printf("Da gui yeu cau quet: %s (priority=%d)\n\n", path, priority);

    /* --- VONG LAP NHAN STREAMING --- */
    while (!done) {
        rc = FrameRecv(&fr, &type, &seq, value, MAX_VALUE_SIZE, &len, 45000);

        if (rc == ERR_NONE) {
            value[len] = '\0';
            if (seq > g_lastSeq) g_lastSeq = seq;   /* ghi nho da nhan toi dau */
            PrintEvent(type, seq, value);
            if (type == MSG_RESULT) done = TRUE;
            if (type == MSG_ERROR) {
                int code = atoi(value);
                /* Loi ve chinh sach/handshake la loi cuoi cung */
                if (code == ERR_POLICY_DENIED || code == ERR_RATE_LIMITED ||
                    code == ERR_HANDSHAKE || code == ERR_ENGINE) done = TRUE;
            }
            continue;
        }

        if (rc == ERR_BAD_CHECKSUM) {
            /* Goi hong nhung dong byte van dong bo -> bo qua, doc tiep */
            printf("  [!] Mot goi bi hong (CRC sai), bo qua va doc tiep\n");
            continue;
        }

        if (rc == ERR_TIMEOUT) {
            printf("  [!] Khong nhan duoc gi trong 45 giay -> dung cho\n");
            break;
        }

        /* Mat ket noi -> thu RESUME */
        CloseHandle(hPipe);
        hPipe = ReconnectAndResume(&fr);
        if (hPipe == INVALID_HANDLE_VALUE) return;
    }

    FrameSend(hPipe, FALSE, MSG_BYE, 0, NULL, 0, 2000);
    CloseHandle(hPipe);
    printf("\nXong.\n");
}

/* ==================================================================
 * LENH QUERY / CANCEL
 * ================================================================== */
static void DoSimple(WORD msgType, int jobId, const char* label)
{
    FrameReader fr;
    HANDLE hPipe;
    char req[32], value[MAX_VALUE_SIZE + 1];
    WORD type;
    DWORD seq, len;
    int rc;

    hPipe = ConnectAndHandshake(&fr);
    if (hPipe == INVALID_HANDLE_VALUE) return;

    sprintf(req, "%d", jobId);
    FrameSend(hPipe, FALSE, msgType, 0, req, (DWORD)strlen(req), 5000);

    rc = FrameRecv(&fr, &type, &seq, value, MAX_VALUE_SIZE, &len, 10000);
    if (rc == ERR_NONE) {
        value[len] = '\0';
        printf("Ket qua %s job %d:\n", label, jobId);
        PrintEvent(type, seq, value);
    }
    else {
        printf("Loi: %s\n", FrameErrName(rc));
    }

    FrameSend(hPipe, FALSE, MSG_BYE, 0, NULL, 0, 2000);
    CloseHandle(hPipe);
}

/* ==================================================================
 * MAIN
 * ================================================================== */
static void Usage(void)
{
    printf("Cach dung:\n");
    printf("  client.exe scan \"D:\\a.exe\" [--priority high|normal|low] [--verbose] [--chunk N]\n");
    printf("  client.exe query <jobId>\n");
    printf("  client.exe cancel <jobId>\n\n");
    printf("  --verbose : hien PROGRESS, PE INFO va chi tiet khung tin [FRAME]/[FRAMING]\n");
    printf("  --chunk N : gioi han N byte moi lan ReadFile (mo phong truyen phan manh)\n");
    printf("              vd: --chunk 12  -> ep hien tuong partial read xuat hien\n");
}

int main(int argc, char* argv[])
{
    int i;

    printf("========== AV SCAN CLIENT 5.2 ==========\n\n");

    if (argc < 2) { Usage(); return 1; }

    /* Co --verbose / --chunk co the dat o bat ky dau.
     * LUU Y: vong lap nay PHAI co ngoac nhon vi than no gom nhieu nhanh. */
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;   /* hien PROGRESS + PE INFO */
            g_frameTrace = 1;   /* hien [FRAME] / [FRAMING] */
        }
        else if (strcmp(argv[i], "--chunk") == 0 && i + 1 < argc) {
            /* Mo phong duong truyen phan manh: gioi han so byte moi lan
             * ReadFile -> ep hien tuong PARTIAL READ xuat hien.
             * Vi buffer pipe la 64 KB va tin chi vai tram byte nen
             * partial read gan nhu khong bao gio xay ra tu nhien. */
            g_frameChunk = atoi(argv[i + 1]);
            g_frameTrace = 1;
            i++;            /* bo qua con so dang sau --chunk */
        }
    }

    if (strcmp(argv[1], "scan") == 0 && argc >= 3) {
        int priority = PRIORITY_NORMAL;
        for (i = 3; i < argc - 1; i++) {
            if (strcmp(argv[i], "--priority") == 0) {
                if (_stricmp(argv[i + 1], "high") == 0) priority = PRIORITY_HIGH;
                else if (_stricmp(argv[i + 1], "low") == 0) priority = PRIORITY_LOW;
                else                                          priority = PRIORITY_NORMAL;
            }
        }
        DoScan(argv[2], priority);

    }
    else if (strcmp(argv[1], "query") == 0 && argc >= 3) {
        DoSimple(MSG_QUERY, atoi(argv[2]), "query");

    }
    else if (strcmp(argv[1], "cancel") == 0 && argc >= 3) {
        DoSimple(MSG_CANCEL, atoi(argv[2]), "cancel");

    }
    else {
        printf("Tham so khong hop le.\n\n");
        Usage();
        return 1;
    }

    return 0;
}