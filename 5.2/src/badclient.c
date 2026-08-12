#define _CRT_SECURE_NO_WARNINGS
/*
 * badclient.c - Client GIA MAO de test cac lop phong thu
 *   badclient.exe crc   -> gui goi co checksum SAI
 *   badclient.exe magic -> gui goi co magic SAI
 *   badclient.exe ver   -> gui goi co version SAI
 *   badclient.exe pid   -> khai PID khong ton tai
 *   badclient.exe user  -> khai user khong dung
 *   badclient.exe ok    -> gui goi hop le (doi chung)
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "protocol.h"
#include "framing.h"

static void SendRaw(const char *mode)
{
    HANDLE h;
    BYTE pkt[512];
    FrameHeader hdr;
    char body[256];
    DWORD w = 0, r = 0;
    BYTE resp[512];

    h = CreateFileA(PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
                    0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Khong ket noi duoc service (loi %lu)\n", GetLastError());
        if (GetLastError() == ERROR_ACCESS_DENIED)
            printf("  -> ACL dang chan. Day la hanh vi DUNG.\n");
        return;
    }

    {
        char user[128] = "unknown";
        DWORD n = sizeof(user);
        GetUserNameA(user, &n);

        if (strcmp(mode, "pid") == 0)
            sprintf(body, "badclient|999999|%s|2", user);
        else if (strcmp(mode, "user") == 0)
            sprintf(body, "badclient|%lu|Administrator|2", GetCurrentProcessId());
        else
            sprintf(body, "badclient|%lu|%s|2", GetCurrentProcessId(), user);
    }

    hdr.magic   = FRAME_MAGIC;
    hdr.version = PROTO_VERSION;
    hdr.type    = MSG_HELLO;
    hdr.seq     = 0;
    hdr.length  = (DWORD)strlen(body);
    hdr.crc32   = Crc32(body, hdr.length);

    if (strcmp(mode, "crc") == 0)   hdr.crc32   = 0xDEADBEEF;
    if (strcmp(mode, "magic") == 0) hdr.magic   = 0x12345678;
    if (strcmp(mode, "ver") == 0)   hdr.version = 99;

    printf("Gui goi che do '%s':\n", mode);
    printf("  magic=0x%08lX  version=%u  crc=0x%08lX\n",
           hdr.magic, hdr.version, hdr.crc32);
    printf("  body=%s\n\n", body);

    memcpy(pkt, &hdr, FRAME_HEADER_SIZE);
    memcpy(pkt + FRAME_HEADER_SIZE, body, hdr.length);
    WriteFile(h, pkt, FRAME_HEADER_SIZE + hdr.length, &w, NULL);

    if (ReadFile(h, resp, sizeof(resp) - 1, &r, NULL) && r > FRAME_HEADER_SIZE) {
        FrameHeader *rh = (FrameHeader *)resp;
        resp[r] = 0;
        printf("Service tra ve: type=0x%04X\n", rh->type);
        printf("  noi dung = %s\n", (char *)(resp + FRAME_HEADER_SIZE));
    } else {
        printf("Service cat ket noi ngay, khong tra loi.\n");
    }

    CloseHandle(h);
}

int main(int argc, char *argv[])
{
    printf("===== BAD CLIENT (test phong thu) =====\n\n");
    if (argc < 2) {
        printf("Cach dung: badclient.exe [crc|magic|ver|pid|user|ok]\n");
        return 1;
    }
    SendRaw(argv[1]);
    return 0;
}