#ifndef PROTOCOL_H
#define PROTOCOL_H
/*
 * protocol.h - Hang so giao thuc AvScan 5.2
 * ===================================================================
 * KHAC 5.1: file nay CHI con hang so + struct.
 * Toan bo ham da chuyen sang framing.c/.h.
 *
 * Ly do: o 5.1 hai ham TlvSend/TlvRecv khai bao "static" trong header
 * -> moi file .c include se co MOT BAN SAO RIENG cua ham (code bi nhan
 * doi). O 5.2 phan framing dai gap ~10 lan nen bat buoc phai tach ra
 * file .c rieng, khai bao prototype trong .h.
 *
 * KHUNG TIN (FRAME) MOI - 20 byte header:
 *
 *   [MAGIC 4]["AVSF"]   <- chu ky nhan dien, giong magic bai 1.3
 *   [VERSION 2]         <- phien ban giao thuc
 *   [TYPE 2]            <- loai tin (MSG_xxx)
 *   [SEQ 4]             <- so thu tu event, phuc vu RESUME
 *   [LENGTH 4]          <- do dai phan Value
 *   [CRC32 4]           <- checksum cua phan Value
 *   [VALUE ... LENGTH byte]
 *
 * So voi 5.1 (chi co Type 2 + Length 4 = 6 byte):
 *   + MAGIC   -> phat hien lech pha / sai giao thuc ngay lap tuc
 *   + VERSION -> tuong lai doi dinh dang van nhan ra duoc
 *   + SEQ     -> biet da nhan toi dau, resume duoc
 *   + CRC32   -> phat hien du lieu hong
 */

#include <windows.h>

/* ===== Ten pipe (doi ten so voi 5.1 vi giao thuc khong tuong thich) ===== */
#define PIPE_NAME           "\\\\.\\pipe\\AvScanPipe52"

/* ===== Hang so khung tin ===== */
#define FRAME_MAGIC         0x46535641UL   /* 'A','V','S','F' doc kieu little-endian */
#define PROTO_VERSION       2
#define FRAME_HEADER_SIZE   20
#define MAX_VALUE_SIZE      8192           /* do dai toi da phan Value */

/* ===== Loai tin: Client -> Service ===== */
#define MSG_HELLO           0x0001   /* bat tay: clientId|pid|user|version */
#define MSG_SCAN            0x0002   /* yeu cau quet: path|priority|timeoutMs */
#define MSG_QUERY           0x0003   /* hoi trang thai job: jobId */
#define MSG_CANCEL          0x0004   /* huy job: jobId */
#define MSG_BYE             0x0005   /* dong ket noi tu te */
#define MSG_RESUME          0x0006   /* noi lai phien: sessionId|lastEventSeq */

/* ===== Loai tin: Service -> Client ===== */
#define MSG_WELCOME         0x1001   /* tra loi bat tay: sessionId|serverVersion|policy */
#define MSG_ACCEPTED        0x1002   /* da nhan job: jobId */
#define MSG_PROGRESS        0x1003   /* tien do: jobId|stage|percent  (VERBOSE) */
#define MSG_DELAYED         0x1004   /* job bi hoan do qua tai */
#define MSG_RESULT          0x1005   /* ket qua cuoi cung */
#define MSG_STATUS          0x1006   /* tra loi QUERY */
#define MSG_ERROR           0x1007   /* loi chuan hoa: code|message */
#define MSG_FLOW_CONTROL    0x1008   /* bao dang drop bot event verbose */
#define MSG_RESUMED         0x1009   /* xac nhan resume thanh cong */
#define MSG_PEINFO          0x100A   /* thong tin PE chi tiet (VERBOSE) */

/* ===== Ma loi CHUAN HOA =====
 * Moi tin MSG_ERROR gui ve dang "code|mo ta".
 * Client chi can doc code, khong phai doan tu chuoi tieng Anh. */
#define ERR_NONE            0
#define ERR_BAD_MAGIC       1001   /* 4 byte dau khong phai "AVSF" */
#define ERR_BAD_VERSION     1002   /* version giao thuc khong khop */
#define ERR_BAD_CHECKSUM    1003   /* CRC32 khong khop -> du lieu hong */
#define ERR_TOO_LARGE       1004   /* length vuot MAX_VALUE_SIZE */
#define ERR_TRUNCATED       1005   /* doc dang do thi mat ket noi */
#define ERR_HANDSHAKE       1006   /* HELLO sai / pid khong ton tai / user khong khop */
#define ERR_POLICY_DENIED   1007   /* path nam trong deny-list */
#define ERR_RATE_LIMITED    1008   /* client gui qua nhanh */
#define ERR_SESSION_UNKNOWN 1009   /* RESUME voi sessionId khong ton tai/het han */
#define ERR_TIMEOUT         1010   /* I/O qua han */
#define ERR_PIPE            1011   /* loi pipe cap he thong */
#define ERR_ENGINE          1012   /* engine tra ve loi */
#define ERR_BAD_REQUEST     1013   /* tham so sai dinh dang */

/* ===== Muc uu tien job ===== */
#define PRIORITY_LOW        0
#define PRIORITY_NORMAL     1
#define PRIORITY_HIGH       2

/* ===== Phan loai event (phuc vu backpressure) =====
 * Khi hang doi gui bi day:
 *   VERBOSE  -> duoc phep bo bot (mat vai dong tien do khong sao)
 *   CRITICAL -> TUYET DOI khong bo (mat la client treo mai) */
#define EVCLASS_CRITICAL    0
#define EVCLASS_VERBOSE     1

/* ===== Ket qua verdict ===== */
#define VERDICT_ERROR       (-1)
#define VERDICT_SAFE        0
#define VERDICT_SUSPICIOUS  1
#define VERDICT_MALICIOUS   2

/* ===== Cac stage engine bao qua callback ===== */
#define STAGE_OPEN          1
#define STAGE_PARSE         2   /* moi o 5.2: dang parse cau truc PE */
#define STAGE_ANALYZE       3
#define STAGE_SIGNATURE     4   /* moi o 5.2: dang verify chu ky */
#define STAGE_REPORT        5

/* ===== Header khung tin =====
 * #pragma pack(1) BAT BUOC: mac dinh compiler chen padding sau
 * "version" va "type" de can chinh 4 byte -> struct thanh 24 byte
 * thay vi 20. Hai ben doc lech nhau -> giao thuc vo hoan toan.
 * Day chinh la ky thuat da hoc o bai 1.3. */
#pragma pack(push, 1)
typedef struct {
    DWORD magic;      /* offset 0  - FRAME_MAGIC */
    WORD  version;    /* offset 4  - PROTO_VERSION */
    WORD  type;       /* offset 6  - MSG_xxx */
    DWORD seq;        /* offset 8  - so thu tu event */
    DWORD length;     /* offset 12 - do dai Value */
    DWORD crc32;      /* offset 16 - checksum cua Value */
} FrameHeader;        /* tong: 20 byte */
#pragma pack(pop)

#endif /* PROTOCOL_H */
