#ifndef FRAMING_H
#define FRAMING_H
/*
 * framing.h - Tang van chuyen AvScan 5.2
 * ===================================================================
 * Giai quyet van de goc: PIPE LA DONG BYTE, KHONG PHAI DONG TIN NHAN.
 *
 * Khi ben gui goi WriteFile 3 lan gui 3 tin, kernel chi giu MOT DAY
 * BYTE LIEN TUC - khong co vach ngan. Ben nhan goi ReadFile co the:
 *
 *   - Partial read : nhan CHUA DU 1 tin (can 20 byte, tra ve 12)
 *   - Sticky packet: nhan NHIEU HON 1 tin (can 20 byte, tra ve 65)
 *
 * Code 5.1 gia dinh ReadFile luon tra dung sizeof(hdr) -> chay duoc
 * chi vi pipe dat PIPE_TYPE_MESSAGE (kernel giu ho ranh gioi).
 * 5.2 tu lam framing nen phai xu ly dung ca 2 truong hop.
 *
 * GIAI PHAP: FrameReader giu mot BO DEM TICH LUY.
 *   - Thieu byte  -> doc them vao dem (vong lap ReadExact)
 *   - Thua byte   -> giu lai trong dem cho lan goi sau
 */

#include <windows.h>
#include "protocol.h"

 /* ==================================================================
  * BO DOC CO DEM
  * head = vi tri da tieu thu toi dau
  * tail = vi tri da nap du lieu toi dau
  * So byte dang co san = tail - head
  * ================================================================== */
#define FR_BUF_SIZE  (MAX_VALUE_SIZE * 4 + FRAME_HEADER_SIZE * 4)

typedef struct {
    HANDLE hPipe;
    BYTE   buf[FR_BUF_SIZE];
    DWORD  head;
    DWORD  tail;
    HANDLE hEvent;        /* event cho overlapped I/O */
    BOOL   overlapped;    /* pipe co mo voi FILE_FLAG_OVERLAPPED khong */
    int    lastError;     /* ma loi ERR_xxx gan nhat */
} FrameReader;

/* ===== Vong doi bo doc ===== */
BOOL FrameReaderInit(FrameReader* fr, HANDLE hPipe, BOOL overlapped);
void FrameReaderFree(FrameReader* fr);
void FrameReaderAttach(FrameReader* fr, HANDLE hPipe);  /* dung khi reconnect */

/* ==================================================================
 * NHAN 1 KHUNG TIN HOAN CHINH
 * Tra ve ERR_NONE neu thanh cong, nguoc lai la ma ERR_xxx.
 * Tu dong xu ly partial + sticky + kiem CRC32.
 * ================================================================== */
int FrameRecv(FrameReader* fr,
    WORD* outType, DWORD* outSeq,
    void* value, DWORD bufSize, DWORD* outLen,
    DWORD timeoutMs);

/* ==================================================================
 * GUI 1 KHUNG TIN
 * Ghep header + value thanh MOT lenh WriteFile duy nhat de giam
 * kha nang bi cat giua chung.
 * ================================================================== */
int FrameSend(HANDLE hPipe, BOOL overlapped,
    WORD type, DWORD seq,
    const void* value, DWORD length,
    DWORD timeoutMs);

/* ===== Tien ich ===== */
DWORD       Crc32(const void* data, DWORD len);
const char* FrameErrName(int err);

/* Ghi/doc thuan tuy co timeout (dung chung trong service) */
BOOL PipeWriteEx(HANDLE hPipe, BOOL overlapped, const void* data, DWORD size, DWORD timeoutMs);
BOOL PipeReadEx(HANDLE hPipe, BOOL overlapped, void* buffer, DWORD size, DWORD* outRead, DWORD timeoutMs);

/* ==================================================================
 * CHE DO TRACE - phuc vu demo yeu cau 1.1 den 1.4 cua de bai
 * ------------------------------------------------------------------
 * g_frameTrace = 1 -> framing.c in ra man hinh:
 *     [FRAME]   moi khung tin gui/nhan (magic, version, len, crc)
 *     [FRAMING] moi lan doc khong tron ven (partial / sticky)
 *               va moi lan mot lop phong thu bat duoc loi
 *
 * g_frameChunk > 0 -> gioi han so byte moi lan ReadFile.
 *     Dung de MO PHONG duong truyen phan manh, ep hien tuong
 *     PARTIAL READ xuat hien. Vi buffer pipe la 64 KB va tin chi
 *     vai tram byte nen partial read gan nhu khong xay ra tu nhien.
 *     Co che xu ly la co che THAT, chi co dieu kien la mo phong.
 *
 * Ca hai mac dinh = 0 (tat). Client bat qua --verbose / --chunk N.
 * ================================================================== */
extern int g_frameTrace;
extern int g_frameChunk;

#endif /* FRAMING_H */