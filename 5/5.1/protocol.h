#ifndef PROTOCOL_H
#define PROTOCOL_H
/*
 * protocol.h - Giao thuc TLV dung chung cho Service va Client
 * ===================================================================
 * TLV = Type-Length-Value: dinh dang nhi phan chuan de dong goi tin.
 *
 *   [Type: 2 byte][Length: 4 byte][Value: Length byte]
 *
 * Ben nhan: doc 2 byte biet LOAI tin, doc 4 byte biet DO DAI,
 *           roi doc dung ngan ay byte la NOI DUNG.
 *
 * Ca service.c va client.c deu #include file nay de "noi cung ngon ngu".
 */

#include <windows.h>

/* Ten Named Pipe - ca 2 ben phai dung y het */
#define PIPE_NAME       "\\\\.\\pipe\\AvScanPipe"

/* Kich thuoc toi da 1 goi Value */
#define MAX_VALUE_SIZE  4096

/* ===== Cac loai tin (Type) ===== */
/* Client -> Service */
#define MSG_HELLO       0x0001   /* bat tay: {clientId, pid, user, version} */
#define MSG_SCAN        0x0002   /* yeu cau quet: {path, priority, timeoutMs} */
#define MSG_QUERY       0x0003   /* hoi trang thai job: {jobId} */
#define MSG_CANCEL      0x0004   /* huy job: {jobId} */
#define MSG_BYE         0x0005   /* client dong ket noi */

/* Service -> Client */
#define MSG_WELCOME     0x1001   /* tra loi bat tay: {sessionId, serverVersion, policy} */
#define MSG_ACCEPTED    0x1002   /* da nhan job: {jobId} */
#define MSG_PROGRESS    0x1003   /* tien do: {jobId, stage, percent} */
#define MSG_DELAYED     0x1004   /* job bi hoan do qua tai: {jobId, reason} */
#define MSG_RESULT      0x1005   /* ket qua cuoi: {jobId, verdict, severity, fromCache} */
#define MSG_STATUS      0x1006   /* tra loi QUERY: {jobId, state} */
#define MSG_ERROR       0x1007   /* loi: {message} */

/* ===== Cac muc uu tien ===== */
#define PRIORITY_LOW    0
#define PRIORITY_NORMAL 1
#define PRIORITY_HIGH   2

/* ===== Header TLV (dat #pragma pack de khong bi padding) ===== */
#pragma pack(push, 1)
typedef struct {
    WORD  type;      /* loai tin (MSG_xxx) */
    DWORD length;    /* do dai phan Value theo sau */
} TlvHeader;
#pragma pack(pop)

/* ==================================================================
 * Ham GUI 1 goi TLV qua pipe (dung chung ca 2 ben)
 * Tra ve TRUE neu gui thanh cong toan bo.
 * ================================================================== */
static BOOL TlvSend(HANDLE hPipe, WORD type, const void *value, DWORD length)
{
    TlvHeader hdr;
    DWORD written = 0;

    hdr.type   = type;
    hdr.length = length;

    /* Gui header truoc */
    if (!WriteFile(hPipe, &hdr, sizeof(hdr), &written, NULL) || written != sizeof(hdr))
        return FALSE;

    /* Gui value (neu co) */
    if (length > 0 && value != NULL) {
        if (!WriteFile(hPipe, value, length, &written, NULL) || written != length)
            return FALSE;
    }
    return TRUE;
}

/* ==================================================================
 * Ham NHAN 1 goi TLV tu pipe.
 * - outType : nhan loai tin
 * - buffer  : noi chua Value (nguoi goi cap phat san, kich thuoc bufSize)
 * - outLen  : nhan do dai Value that su
 * Tra ve TRUE neu nhan thanh cong 1 goi hoan chinh.
 * ================================================================== */
static BOOL TlvRecv(HANDLE hPipe, WORD *outType, void *buffer, DWORD bufSize, DWORD *outLen)
{
    TlvHeader hdr;
    DWORD read = 0;

    /* Doc header truoc */
    if (!ReadFile(hPipe, &hdr, sizeof(hdr), &read, NULL) || read != sizeof(hdr))
        return FALSE;

    if (hdr.length > bufSize) return FALSE;   /* value qua lon, tu choi */

    *outType = hdr.type;
    *outLen  = hdr.length;

    /* Doc value (neu co) */
    if (hdr.length > 0) {
        if (!ReadFile(hPipe, buffer, hdr.length, &read, NULL) || read != hdr.length)
            return FALSE;
    }
    return TRUE;
}

#endif /* PROTOCOL_H */
