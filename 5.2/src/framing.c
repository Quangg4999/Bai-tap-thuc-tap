#define _CRT_SECURE_NO_WARNINGS
/*
 * framing.c - Cai dat tang van chuyen AvScan 5.2
 */

#include <stdio.h>
#include <string.h>
#include "framing.h"

 /* ==================================================================
  * CO BAT CHE DO TRACE
  * ------------------------------------------------------------------
  * Khi = 1, cac ham trong file nay se in ra man hinh:
  *   [FRAME]   moi khung tin gui/nhan (magic, version, len, crc)
  *   [FRAMING] moi lan doc khong tron ven (partial read / sticky packet)
  * Client bat co nay khi co tham so --verbose.
  * Mac dinh TAT de khong lam ban output binh thuong.
  * Khai bao la "int" (khong phai static) de client.c thay duoc.
  * ================================================================== */
int g_frameTrace = 0;
int g_frameChunk = 0;

/* ==================================================================
 * CRC32 (chuan IEEE 802.3, da thuc 0xEDB88320)
 * ------------------------------------------------------------------
 * Nguyen ly: coi day byte nhu mot da thuc nhi phan khong lo, chia cho
 * mot da thuc sinh co dinh, lay PHAN DU lam checksum. Sai 1 bit thi
 * phan du chac chan doi.
 *
 * Cai dat bang BANG TRA 256 phan tu: thay vi xu ly tung bit (8 vong
 * lap moi byte), ta tinh truoc ket qua cho ca 256 gia tri byte ->
 * moi byte chi con 1 phep XOR + 1 phep dich. Nhanh gap ~8 lan.
 *
 * LUU Y QUAN TRONG VE GIOI HAN:
 * CRC32 chong LOI NGAU NHIEN (bit lat do phan cung, duong truyen).
 * No KHONG chong duoc ke tan cong co y - ho sua payload roi tinh lai
 * CRC moi la xong. Muon chong tan cong phai dung HMAC (co khoa bi mat).
 * De bai chi yeu cau checksum nen CRC32 la du.
 * ================================================================== */
static DWORD g_crcTable[256];
static BOOL  g_crcReady = FALSE;

static void Crc32BuildTable(void)
{
    DWORD i, j, c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++) {
            /* neu bit thap = 1 thi dich phai roi XOR da thuc sinh */
            c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
        }
        g_crcTable[i] = c;
    }
    g_crcReady = TRUE;
}

DWORD Crc32(const void* data, DWORD len)
{
    const BYTE* p = (const BYTE*)data;
    DWORD crc = 0xFFFFFFFFUL;   /* gia tri khoi tao chuan */
    DWORD i;

    if (!g_crcReady) Crc32BuildTable();
    if (!p || len == 0) return 0;

    for (i = 0; i < len; i++) {
        /* XOR byte hien tai voi 8 bit thap cua crc -> tra bang */
        crc = g_crcTable[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFUL;  /* dao bit cuoi theo chuan */
}

/* ==================================================================
 * TEN MA LOI - de log/hien thi cho nguoi doc
 * ================================================================== */
const char* FrameErrName(int err)
{
    switch (err) {
    case ERR_NONE:            return "OK";
    case ERR_BAD_MAGIC:       return "BAD_MAGIC";
    case ERR_BAD_VERSION:     return "BAD_VERSION";
    case ERR_BAD_CHECKSUM:    return "BAD_CHECKSUM";
    case ERR_TOO_LARGE:       return "TOO_LARGE";
    case ERR_TRUNCATED:       return "TRUNCATED";
    case ERR_HANDSHAKE:       return "HANDSHAKE_FAILED";
    case ERR_POLICY_DENIED:   return "POLICY_DENIED";
    case ERR_RATE_LIMITED:    return "RATE_LIMITED";
    case ERR_SESSION_UNKNOWN: return "SESSION_UNKNOWN";
    case ERR_TIMEOUT:         return "TIMEOUT";
    case ERR_PIPE:            return "PIPE_ERROR";
    case ERR_ENGINE:          return "ENGINE_ERROR";
    case ERR_BAD_REQUEST:     return "BAD_REQUEST";
    default:                  return "UNKNOWN";
    }
}

/* ==================================================================
 * GHI CO TIMEOUT (overlapped I/O)
 * ------------------------------------------------------------------
 * Day la bai hoc dat gia tu 5.1: WriteFile dong bo tren pipe PIPE_WAIT
 * se CHAN VO HAN khi buffer pipe day (client cham khong doc). Ca 4
 * worker treo cung -> he thong chet.
 *
 * Overlapped I/O: WriteFile tra ve NGAY LAP TUC voi ERROR_IO_PENDING,
 * ta tu cho tren event co gioi han thoi gian. Qua han -> CancelIo.
 * ================================================================== */
BOOL PipeWriteEx(HANDLE hPipe, BOOL overlapped, const void* data, DWORD size, DWORD timeoutMs)
{
    OVERLAPPED ov;
    HANDLE hEv;
    DWORD written = 0;
    BOOL ok;

    if (hPipe == INVALID_HANDLE_VALUE || hPipe == NULL) return FALSE;
    if (size == 0) return TRUE;

    /* Che do dong bo: ghi thang (dung cho client, it rui ro hon) */
    if (!overlapped) {
        return WriteFile(hPipe, data, size, &written, NULL) && written == size;
    }

    hEv = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!hEv) return FALSE;

    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = hEv;

    ok = WriteFile(hPipe, data, size, &written, &ov);
    if (!ok) {
        if (GetLastError() != ERROR_IO_PENDING) {
            CloseHandle(hEv);
            return FALSE;
        }
        /* Lenh dang cho -> doi toi da timeoutMs */
        if (WaitForSingleObject(hEv, timeoutMs) == WAIT_OBJECT_0) {
            ok = GetOverlappedResult(hPipe, &ov, &written, FALSE);
        }
        else {
            CancelIo(hPipe);   /* qua han -> huy lenh, di tiep */
            CloseHandle(hEv);
            return FALSE;
        }
    }

    CloseHandle(hEv);
    return ok && written == size;
}

/* ==================================================================
 * DOC CO TIMEOUT - tra ve so byte THUC SU doc duoc (co the < size)
 * Chinh cho nay sinh ra hien tuong partial read.
 * ================================================================== */
BOOL PipeReadEx(HANDLE hPipe, BOOL overlapped, void* buffer, DWORD size, DWORD* outRead, DWORD timeoutMs)
{
    OVERLAPPED ov;
    HANDLE hEv;
    DWORD read = 0;
    BOOL ok;

    if (outRead) *outRead = 0;
    if (hPipe == INVALID_HANDLE_VALUE || hPipe == NULL) return FALSE;
    if (size == 0) return TRUE;

    if (!overlapped) {
        ok = ReadFile(hPipe, buffer, size, &read, NULL);
        if (outRead) *outRead = read;
        return ok && read > 0;
    }

    hEv = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!hEv) return FALSE;

    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = hEv;

    ok = ReadFile(hPipe, buffer, size, &read, &ov);
    if (!ok) {
        if (GetLastError() != ERROR_IO_PENDING) {
            CloseHandle(hEv);
            return FALSE;
        }
        if (WaitForSingleObject(hEv, timeoutMs) == WAIT_OBJECT_0) {
            ok = GetOverlappedResult(hPipe, &ov, &read, FALSE);
        }
        else {
            CancelIo(hPipe);
            CloseHandle(hEv);
            return FALSE;
        }
    }

    CloseHandle(hEv);
    if (outRead) *outRead = read;
    return ok && read > 0;
}

/* ==================================================================
 * KHOI TAO / GIAI PHONG BO DOC
 * ================================================================== */
BOOL FrameReaderInit(FrameReader* fr, HANDLE hPipe, BOOL overlapped)
{
    if (!fr) return FALSE;
    ZeroMemory(fr, sizeof(FrameReader));
    fr->hPipe = hPipe;
    fr->overlapped = overlapped;
    fr->head = 0;
    fr->tail = 0;
    fr->lastError = ERR_NONE;
    return TRUE;
}

void FrameReaderFree(FrameReader* fr)
{
    if (!fr) return;
    fr->hPipe = INVALID_HANDLE_VALUE;
    fr->head = fr->tail = 0;
}

/* Gan handle moi sau khi reconnect. GIU NGUYEN du lieu con trong dem
 * la sai (du lieu cua ket noi cu) -> phai xoa sach. */
void FrameReaderAttach(FrameReader* fr, HANDLE hPipe)
{
    if (!fr) return;
    fr->hPipe = hPipe;
    fr->head = 0;
    fr->tail = 0;
    fr->lastError = ERR_NONE;
}

/* ==================================================================
 * DON DEP BO DEM
 * Doi phan chua tieu thu ve dau mang de lay lai khoang trong phia sau.
 * ================================================================== */
static void FrCompact(FrameReader* fr)
{
    DWORD avail = fr->tail - fr->head;
    if (fr->head == 0) return;
    if (avail > 0) memmove(fr->buf, fr->buf + fr->head, avail);
    fr->head = 0;
    fr->tail = avail;
}

/* ==================================================================
 * DAM BAO CO IT NHAT "need" BYTE TRONG DEM
 * ------------------------------------------------------------------
 * DAY LA HAM XU LY PARTIAL READ.
 * Vong lap doc them cho toi khi du, thay vi gia dinh 1 lan ReadFile
 * la du (loi thiet ke cua TlvRecv o 5.1).
 * ================================================================== */
static int FrEnsure(FrameReader* fr, DWORD need, DWORD timeoutMs)
{
    DWORD got;
    DWORD deadline = GetTickCount() + timeoutMs;

    if (need > FR_BUF_SIZE) return ERR_TOO_LARGE;

    while (fr->tail - fr->head < need) {
        DWORD space;
        DWORD remain;

        /* Khong con cho ghi -> don dep truoc */
        if (fr->tail >= FR_BUF_SIZE) FrCompact(fr);
        space = FR_BUF_SIZE - fr->tail;

        /* Mo phong duong truyen phan manh (chi khi bat --chunk N):
         * chi xin toi da N byte moi lan -> ep partial read xuat hien. */
        if (g_frameChunk > 0 && space > (DWORD)g_frameChunk)
            space = (DWORD)g_frameChunk;

        if (space == 0) {
            FrCompact(fr);
            space = FR_BUF_SIZE - fr->tail;
            if (space == 0) return ERR_TOO_LARGE;
        }

        /* Con bao nhieu thoi gian */
        {
            DWORD now = GetTickCount();
            if (now >= deadline) return ERR_TIMEOUT;
            remain = deadline - now;
        }

        got = 0;
        if (!PipeReadEx(fr->hPipe, fr->overlapped, fr->buf + fr->tail, space, &got, remain)) {
            /* Doc that bai: het gio hay dut ket noi */
            if (GetLastError() == ERROR_BROKEN_PIPE ||
                GetLastError() == ERROR_PIPE_NOT_CONNECTED ||
                GetLastError() == ERROR_NO_DATA) {
                return ERR_TRUNCATED;
            }
            return (got == 0) ? ERR_TIMEOUT : ERR_PIPE;
        }
        if (got == 0) return ERR_TRUNCATED;

        fr->tail += got;

        /* --- TRACE: chung minh xu ly PARTIAL READ (demo yeu cau 1.2) --- */
        if (g_frameTrace) {
            DWORD have = fr->tail - fr->head;
            if (have < need) {
                printf("[FRAMING] ReadFile tra ve %lu byte -> moi co %lu/%lu"
                    " -> DOC THEM (partial read)\n",
                    (unsigned long)got, (unsigned long)have, (unsigned long)need);
            }
            else {
                printf("[FRAMING] ReadFile tra ve %lu byte -> du %lu/%lu, di tiep\n",
                    (unsigned long)got, (unsigned long)have, (unsigned long)need);
            }
        }
    }
    return ERR_NONE;
}

/* ==================================================================
 * NHAN 1 KHUNG TIN HOAN CHINH
 * ------------------------------------------------------------------
 * Trinh tu 5 buoc, moi buoc la mot lop phong thu:
 *   1. Bao dam co du 20 byte header (xu ly partial)
 *   2. Kiem MAGIC   -> sai la lech pha / sai giao thuc
 *   3. Kiem VERSION -> sai la ban khac
 *   4. Kiem LENGTH  -> qua lon la tan cong tran bo dem (bai 1.2)
 *   5. Bao dam co du LENGTH byte value, roi kiem CRC32
 * Byte thua (sticky packet) duoc GIU LAI trong dem cho lan goi sau.
 * ================================================================== */
int FrameRecv(FrameReader* fr,
    WORD* outType, DWORD* outSeq,
    void* value, DWORD bufSize, DWORD* outLen,
    DWORD timeoutMs)
{
    FrameHeader hdr;
    int rc;
    DWORD crcCalc;

    if (!fr || !outType || !outLen) return ERR_BAD_REQUEST;
    *outLen = 0;
    if (outSeq) *outSeq = 0;

    /* --- Buoc 1: doc du header --- */
    rc = FrEnsure(fr, FRAME_HEADER_SIZE, timeoutMs);
    if (rc != ERR_NONE) { fr->lastError = rc; return rc; }

    memcpy(&hdr, fr->buf + fr->head, FRAME_HEADER_SIZE);

    /* --- Buoc 2: kiem MAGIC ---
     * Giong het viec validate magic o bai 1.3. Sai magic nghia la
     * dong byte da lech pha -> khong con cach nao dong bo lai,
     * phai cat ket noi. Doc tiep chi cang lech them. */
    if (hdr.magic != FRAME_MAGIC) {
        if (g_frameTrace) {
            printf("[FRAMING] MAGIC SAI: nhan 0x%08lX, mong doi 0x%08lX -> cat ket noi\n",
                (unsigned long)hdr.magic, (unsigned long)FRAME_MAGIC);
        }
        fr->lastError = ERR_BAD_MAGIC;
        return ERR_BAD_MAGIC;
    }

    /* --- Buoc 3: kiem VERSION --- */
    if (hdr.version != PROTO_VERSION) {
        if (g_frameTrace) {
            printf("[FRAMING] VERSION SAI: nhan %u, mong doi %u -> cat ket noi\n",
                (unsigned)hdr.version, (unsigned)PROTO_VERSION);
        }
        fr->lastError = ERR_BAD_VERSION;
        return ERR_BAD_VERSION;
    }

    /* --- Buoc 4: kiem LENGTH ---
     * Neu ke tan cong gui length = 1 ty, ta TU CHOI thay vi ghi tran
     * bo dem. Day chinh la lo hong bai 1.2 trong ngu canh mang. */
    if (hdr.length > MAX_VALUE_SIZE || hdr.length > bufSize) {
        if (g_frameTrace) {
            printf("[FRAMING] LENGTH QUA LON: %lu (toi da %lu) -> tu choi\n",
                (unsigned long)hdr.length, (unsigned long)MAX_VALUE_SIZE);
        }
        fr->lastError = ERR_TOO_LARGE;
        return ERR_TOO_LARGE;
    }

    /* --- Buoc 5: doc du phan value roi kiem CRC --- */
    rc = FrEnsure(fr, FRAME_HEADER_SIZE + hdr.length, timeoutMs);
    if (rc != ERR_NONE) { fr->lastError = rc; return rc; }

    if (hdr.length > 0) {
        memcpy(value, fr->buf + fr->head + FRAME_HEADER_SIZE, hdr.length);
        crcCalc = Crc32(value, hdr.length);
        if (crcCalc != hdr.crc32) {
            /* Van phai TIEU THU goi hong, neu khong se ket lai mai */
            fr->head += FRAME_HEADER_SIZE + hdr.length;
            if (fr->head == fr->tail) { fr->head = fr->tail = 0; }

            /* --- TRACE: chung minh phat hien CRC sai (demo yeu cau 1.4) --- */
            if (g_frameTrace) {
                printf("[FRAMING] CRC LECH: header ghi 0x%08lX, tinh lai 0x%08lX"
                    " -> bo goi hong, dong byte VAN DONG BO\n",
                    (unsigned long)hdr.crc32, (unsigned long)crcCalc);
            }

            fr->lastError = ERR_BAD_CHECKSUM;
            return ERR_BAD_CHECKSUM;
        }
    }

    /* Tieu thu goi vua doc. Phan con lai (sticky) o nguyen trong dem. */
    fr->head += FRAME_HEADER_SIZE + hdr.length;
    if (fr->head == fr->tail) { fr->head = fr->tail = 0; }  /* dem rong -> reset */

    /* --- TRACE: chung minh du 4 truong + xu ly STICKY PACKET --- */
    if (g_frameTrace) {
        DWORD remain = fr->tail - fr->head;
        printf("[FRAME]   nhan type=0x%04X seq=%lu len=%lu crc=0x%08lX  MAGIC=OK VER=%u\n",
            (unsigned)hdr.type, (unsigned long)hdr.seq,
            (unsigned long)hdr.length, (unsigned long)hdr.crc32,
            (unsigned)hdr.version);
        if (remain > 0) {
            printf("[FRAMING] Con %lu byte trong dem -> khung tiep theo da nam san"
                " (sticky packet)\n", (unsigned long)remain);
        }
    }

    *outType = hdr.type;
    *outLen = hdr.length;
    if (outSeq) *outSeq = hdr.seq;
    fr->lastError = ERR_NONE;
    return ERR_NONE;
}

/* ==================================================================
 * GUI 1 KHUNG TIN
 * ------------------------------------------------------------------
 * Ghep header + value vao MOT bo dem roi ghi MOT lan.
 * Ly do: hai lenh WriteFile rieng le co the bi xen ke boi luong khac
 * ghi cung pipe -> hong khung tin. Mot lenh duy nhat an toan hon.
 * ================================================================== */
int FrameSend(HANDLE hPipe, BOOL overlapped,
    WORD type, DWORD seq,
    const void* value, DWORD length,
    DWORD timeoutMs)
{
    BYTE packet[FRAME_HEADER_SIZE + MAX_VALUE_SIZE];
    FrameHeader hdr;

    if (hPipe == INVALID_HANDLE_VALUE || hPipe == NULL) return ERR_PIPE;
    if (length > MAX_VALUE_SIZE) return ERR_TOO_LARGE;

    hdr.magic = FRAME_MAGIC;
    hdr.version = PROTO_VERSION;
    hdr.type = type;
    hdr.seq = seq;
    hdr.length = length;
    hdr.crc32 = (length > 0 && value) ? Crc32(value, length) : 0;

    memcpy(packet, &hdr, FRAME_HEADER_SIZE);
    if (length > 0 && value) memcpy(packet + FRAME_HEADER_SIZE, value, length);

    /* --- TRACE: chung minh khung tin co du 4 truong (demo yeu cau 1.1) --- */
    if (g_frameTrace) {
        printf("[FRAME]   gui  type=0x%04X seq=%lu len=%lu crc=0x%08lX  magic=0x%08lX ver=%u\n",
            (unsigned)type, (unsigned long)seq, (unsigned long)length,
            (unsigned long)hdr.crc32, (unsigned long)hdr.magic,
            (unsigned)hdr.version);
    }

    if (!PipeWriteEx(hPipe, overlapped, packet, FRAME_HEADER_SIZE + length, timeoutMs))
        return ERR_TIMEOUT;

    return ERR_NONE;
}