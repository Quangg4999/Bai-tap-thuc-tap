#define _CRT_SECURE_NO_WARNINGS
/*
 * pereader.c - Cai dat module doc PE thuan tay (bai 5.2)
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "pereader.h"

/* ==================================================================
 * BIEN CUC BO CUA MOT LAN PARSE
 * Bo dem chua toan bo file (hoac PE_MAX_READ byte dau).
 * Duoc giai phong ngay truoc khi PeRead tra ve -> nguoi goi khong
 * phai nho don dep.
 * ================================================================== */
typedef struct {
    BYTE      *img;      /* bo dem file */
    DWORD      size;     /* so byte thuc su doc duoc */
    ULONGLONG  fileSize; /* kich thuoc that cua file */
} PeBuf;

/* Kiem tra [off, off+len) co nam gon trong bo dem khong.
 * Dung ULONGLONG de phep cong KHONG BI TRAN - neu dung DWORD thi
 * off = 0xFFFFFFF0 + len = 0x20 se quay vong ve 0x10 va "lot" kiem tra.
 * Day chinh la bay tran so hoc trong bai 1.2. */
static BOOL InBuf(const PeBuf *b, ULONGLONG off, ULONGLONG len)
{
    if (!b || !b->img) return FALSE;
    return (off + len) <= (ULONGLONG)b->size && (off + len) >= off;
}

/* Lay con tro toi offset neu hop le, nguoc lai NULL */
static const BYTE *At(const PeBuf *b, ULONGLONG off, ULONGLONG len)
{
    if (!InBuf(b, off, len)) return NULL;
    return b->img + off;
}

/* ==================================================================
 * ENTROPY SHANNON THAT
 * ------------------------------------------------------------------
 * Khac 5.1 (chi dem so byte khac nhau - gia lap tho).
 *
 *   H = - SUM p(i) * log2(p(i))     voi p(i) = freq[i] / tong
 *
 * Ket qua 0..8 (vi byte co 8 bit).
 *   - Van ban thuan  : ~4.5
 *   - .text binh thuong: ~6.2
 *   - Da nen / ma hoa : > 7.4   <- nguong de bai dung
 * ================================================================== */
double PeEntropy(const BYTE *buf, DWORD len)
{
    DWORD freq[256];
    DWORD i;
    double h = 0.0, p;

    if (!buf || len == 0) return 0.0;
    memset(freq, 0, sizeof(freq));

    for (i = 0; i < len; i++) freq[buf[i]]++;

    for (i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        p = (double)freq[i] / (double)len;
        h -= p * (log(p) / log(2.0));   /* log2(p) = ln(p)/ln(2) */
    }
    return h;
}

/* ==================================================================
 * QUY DOI RVA -> FILE OFFSET
 * ------------------------------------------------------------------
 * Duyet tung section, tim section chua RVA, roi:
 *     offset = rva - VirtualAddress + PointerToRawData
 *
 * Truong hop dac biet: RVA nam trong vung header (truoc section dau
 * tien) thi offset = rva (header khong bi gian).
 * ================================================================== */
DWORD RvaToFileOffset(const PeInfo *info, DWORD rva)
{
    int i;
    if (!info) return 0;

    /* RVA nam trong vung header */
    if (info->sizeOfHeaders > 0 && rva < info->sizeOfHeaders) return rva;

    for (i = 0; i < (int)info->sectionCount; i++) {
        const PeSection *s = &info->sections[i];
        DWORD vsize = s->virtualSize ? s->virtualSize : s->sizeOfRawData;

        if (rva >= s->virtualAddress && rva < s->virtualAddress + vsize) {
            DWORD delta = rva - s->virtualAddress;
            /* Neu vuot qua phan raw tren dia -> vung khong co du lieu that
             * (BSS chang han). Coi nhu khong doc duoc. */
            if (delta >= s->sizeOfRawData) return 0;
            return s->pointerToRawData + delta;
        }
    }
    return 0;   /* out of range */
}

/* ==================================================================
 * TEN GOI DE HIEN THI
 * ================================================================== */
const char *PeStatusName(int status)
{
    switch (status) {
        case PE_OK:             return "OK";
        case PE_ERR_IO:         return "IO_ERROR";
        case PE_MALFORMED_PE:   return "MALFORMED_PE";
        case PE_STRUCT_CORRUPT: return "STRUCT_CORRUPT";
        default:                return "UNKNOWN";
    }
}

const char *PeMachineName(WORD m)
{
    switch (m) {
        case 0x014C: return "x86";
        case 0x8664: return "x64";
        case 0x01C0: return "ARM";
        case 0xAA64: return "ARM64";
        case 0x0200: return "IA64";
        default:     return "OTHER";
    }
}

const char *PeSubsystemName(WORD s)
{
    switch (s) {
        case 1:  return "NATIVE(driver)";
        case 2:  return "WINDOWS_GUI";
        case 3:  return "WINDOWS_CUI";
        case 9:  return "WINDOWS_CE";
        case 10: return "EFI_APP";
        default: return "OTHER";
    }
}

const char *PeSignStateName(int st)
{
    switch (st) {
        case SIGN_UNSIGNED: return "UNSIGNED";
        case SIGN_VALID:    return "SIGNED_VALID";
        case SIGN_INVALID:  return "SIGNED_INVALID";
        default:            return "SIGN_UNKNOWN";
    }
}

const char *PeRiskGroupName(int g)
{
    switch (g) {
        case RISK_PROCESS: return "Process/Thread";
        case RISK_PERSIST: return "Persistence";
        case RISK_NETWORK: return "Network";
        case RISK_CRYPTO:  return "Crypto";
        default:           return "?";
    }
}

/* ==================================================================
 * DANH SACH API RUI RO (nhom C)
 * So khop bang tien to, khong phan biet hoa thuong, de bat ca ban
 * ...A va ...W (vi du OpenProcess / CreateFileW).
 * ================================================================== */
static const char *g_riskProcess[] = {
    "CreateRemoteThread", "OpenProcess", "WriteProcessMemory", "ReadProcessMemory",
    "VirtualAllocEx", "VirtualProtectEx", "NtUnmapViewOfSection", "SetThreadContext",
    "GetThreadContext", "QueueUserAPC", "ResumeThread", "SuspendThread",
    "CreateToolhelp32Snapshot", "Process32", "NtCreateThreadEx", "RtlCreateUserThread",
    "AdjustTokenPrivileges", "OpenProcessToken", NULL
};
static const char *g_riskPersist[] = {
    "RegSetValue", "RegCreateKey", "RegOpenKey", "RegDeleteKey",
    "CreateService", "OpenSCManager", "StartService", "ChangeServiceConfig",
    "SetWindowsHookEx", "CreateProcess", "ShellExecute", "WinExec",
    "SHGetFolderPath", "CopyFile", "MoveFileEx", NULL
};
static const char *g_riskNetwork[] = {
    "WinHttp", "InternetOpen", "InternetConnect", "InternetReadFile",
    "HttpSendRequest", "HttpOpenRequest", "URLDownloadToFile",
    "WSAStartup", "WSASocket", "WSAConnect", "socket", "connect",
    "send", "recv", "gethostbyname", "getaddrinfo", "bind", "listen", NULL
};
static const char *g_riskCrypto[] = {
    "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
    "CryptDeriveKey", "CryptHashData", "CryptStringToBinary",
    "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
    "BCryptGenerateSymmetricKey", "CryptProtectData", "CryptUnprotectData", NULL
};

static const char **g_riskTable[RISK_GROUPS] = {
    g_riskProcess, g_riskPersist, g_riskNetwork, g_riskCrypto
};

/* Phan loai 1 ten API vao nhom rui ro; tra ve -1 neu khong thuoc nhom nao */
static int ClassifyApi(const char *api)
{
    int g, i;
    if (!api || !api[0]) return -1;

    for (g = 0; g < RISK_GROUPS; g++) {
        const char **list = g_riskTable[g];
        for (i = 0; list[i]; i++) {
            size_t n = strlen(list[i]);
            if (_strnicmp(api, list[i], n) == 0) return g;
        }
    }
    return -1;
}

/* ==================================================================
 * KIEM TRA TEN SECTION CO "KY" KHONG
 * Ten binh thuong: .text .rdata .data .rsrc .reloc .pdata .idata ...
 * Bat thuong: rong, chua ky tu khong in duoc, khong bat dau bang '.'
 * ================================================================== */
static BOOL SectionNameWeird(const char *name)
{
    int i, len = 0;
    BOOL hasNonPrintable = FALSE;

    for (i = 0; i < 8 && name[i]; i++) {
        BYTE c = (BYTE)name[i];
        len++;
        if (c < 0x20 || c > 0x7E) hasNonPrintable = TRUE;
    }
    if (len == 0) return TRUE;              /* ten rong */
    if (hasNonPrintable) return TRUE;       /* ky tu la */
    if (name[0] != '.' && _strnicmp(name, "UPX", 3) != 0) {
        /* Khong bat dau bang '.' -> dang ngo (packer thuong dat ten la) */
        return TRUE;
    }
    return FALSE;
}

/* ==================================================================
 * KIEM TRA POWER OF TWO
 * n & (n-1) == 0 chi dung voi luy thua cua 2.
 *   8 = 1000, 7 = 0111 -> AND = 0     (dung)
 *   6 = 0110, 5 = 0101 -> AND = 0100  (sai)
 * ================================================================== */
static BOOL IsPowerOfTwo(DWORD n)
{
    return n != 0 && (n & (n - 1)) == 0;
}

/* ==================================================================
 * DOC TOAN BO FILE VAO BO DEM
 * ================================================================== */
static int LoadFile(const char *path, PeBuf *b)
{
    HANDLE hFile;
    LARGE_INTEGER li;
    DWORD toRead, got = 0, total = 0;

    b->img = NULL; b->size = 0; b->fileSize = 0;

    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return PE_ERR_IO;

    if (!GetFileSizeEx(hFile, &li)) { CloseHandle(hFile); return PE_ERR_IO; }
    b->fileSize = (ULONGLONG)li.QuadPart;

    if (b->fileSize == 0) { CloseHandle(hFile); return PE_MALFORMED_PE; }

    toRead = (b->fileSize > PE_MAX_READ) ? PE_MAX_READ : (DWORD)b->fileSize;

    b->img = (BYTE *)malloc(toRead);
    if (!b->img) { CloseHandle(hFile); return PE_ERR_IO; }

    /* Vong lap doc: ReadFile co the tra ve it hon yeu cau */
    while (total < toRead) {
        if (!ReadFile(hFile, b->img + total, toRead - total, &got, NULL) || got == 0) break;
        total += got;
    }
    CloseHandle(hFile);

    b->size = total;
    if (total < 64) { free(b->img); b->img = NULL; return PE_MALFORMED_PE; }
    return PE_OK;
}

/* ==================================================================
 * PARSE IMPORT TABLE  (DataDirectory[1])
 * ------------------------------------------------------------------
 * Cau truc:
 *   IMAGE_IMPORT_DESCRIPTOR[]  <- mang, ket thuc bang phan tu toan 0
 *     .Name                    -> RVA toi ten DLL
 *     .OriginalFirstThunk      -> RVA toi mang ILT (ten ham)
 *     .FirstThunk              -> RVA toi mang IAT
 *
 *   Moi thunk:
 *     - Bit cao nhat = 1  -> import theo ORDINAL (khong co ten)
 *     - Bit cao nhat = 0  -> la RVA toi IMAGE_IMPORT_BY_NAME
 *                            {WORD Hint; char Name[];}
 * ================================================================== */
static void ParseImports(const PeBuf *b, PeInfo *pe)
{
    DWORD impRva = pe->dirRva[IMAGE_DIRECTORY_ENTRY_IMPORT];
    DWORD off, i;

    if (impRva == 0) return;
    off = RvaToFileOffset(pe, impRva);
    if (off == 0) return;

    for (i = 0; i < 256; i++) {   /* gioi han 256 DLL de tranh vong lap vo tan */
        const IMAGE_IMPORT_DESCRIPTOR *desc;
        DWORD thunkRva, thunkOff, k;
        const char *dllName;

        desc = (const IMAGE_IMPORT_DESCRIPTOR *)At(b, off + i * sizeof(IMAGE_IMPORT_DESCRIPTOR),
                                                   sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (!desc) break;

        /* Phan tu toan 0 = het bang */
        if (desc->Name == 0 && desc->FirstThunk == 0) break;

        /* Ten DLL (chi de dem, khong bat buoc dung) */
        {
            DWORD nameOff = RvaToFileOffset(pe, desc->Name);
            dllName = (const char *)At(b, nameOff, 1);
            if (dllName) pe->importDllCount++;
        }

        /* Uu tien OriginalFirstThunk (ILT) vi no giu nguyen ten ham.
         * FirstThunk (IAT) sau khi nap se bi ghi de bang dia chi that. */
        thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        if (thunkRva == 0) continue;
        thunkOff = RvaToFileOffset(pe, thunkRva);
        if (thunkOff == 0) continue;

        for (k = 0; k < 4096; k++) {   /* gioi han 4096 ham moi DLL */
            ULONGLONG entry = 0;
            DWORD nameRva, nameOff;
            const char *api;
            int grp;

            if (pe->isPE32Plus) {
                const ULONGLONG *p = (const ULONGLONG *)At(b, thunkOff + k * 8, 8);
                if (!p) break;
                entry = *p;
                if (entry == 0) break;
                if (entry & 0x8000000000000000ULL) continue;   /* import theo ordinal */
                nameRva = (DWORD)(entry & 0x7FFFFFFF);
            } else {
                const DWORD *p = (const DWORD *)At(b, thunkOff + k * 4, 4);
                if (!p) break;
                entry = *p;
                if (entry == 0) break;
                if (entry & 0x80000000UL) continue;            /* import theo ordinal */
                nameRva = (DWORD)(entry & 0x7FFFFFFF);
            }

            /* +2 de bo qua truong Hint (WORD) trong IMAGE_IMPORT_BY_NAME */
            nameOff = RvaToFileOffset(pe, nameRva);
            if (nameOff == 0) continue;
            api = (const char *)At(b, nameOff + 2, 1);
            if (!api) continue;

            pe->importApiCount++;

            grp = ClassifyApi(api);
            if (grp >= 0) {
                pe->riskHit[grp]++;
                if (pe->riskyApiCount < PE_MAX_RISKY) {
                    strncpy(pe->riskyApis[pe->riskyApiCount], api, 47);
                    pe->riskyApis[pe->riskyApiCount][47] = '\0';
                    pe->riskyApiCount++;
                }
            }
        }
    }
}

/* ==================================================================
 * PARSE EXPORT TABLE  (DataDirectory[0])
 * ================================================================== */
static void ParseExports(const PeBuf *b, PeInfo *pe)
{
    DWORD expRva = pe->dirRva[IMAGE_DIRECTORY_ENTRY_EXPORT];
    DWORD off, namesOff, i;
    const IMAGE_EXPORT_DIRECTORY *ed;

    if (expRva == 0) return;
    off = RvaToFileOffset(pe, expRva);
    if (off == 0) return;

    ed = (const IMAGE_EXPORT_DIRECTORY *)At(b, off, sizeof(IMAGE_EXPORT_DIRECTORY));
    if (!ed) return;

    pe->hasExport   = TRUE;
    pe->exportCount = ed->NumberOfNames;

    if (ed->AddressOfNames == 0 || ed->NumberOfNames == 0) return;
    namesOff = RvaToFileOffset(pe, ed->AddressOfNames);
    if (namesOff == 0) return;

    /* Kiem tra vai ten dau xem co "la" khong */
    for (i = 0; i < ed->NumberOfNames && i < 32; i++) {
        const DWORD *pRva = (const DWORD *)At(b, namesOff + i * 4, 4);
        DWORD nOff;
        const char *nm;
        int j;

        if (!pRva) break;
        nOff = RvaToFileOffset(pe, *pRva);
        if (nOff == 0) continue;
        nm = (const char *)At(b, nOff, 1);
        if (!nm) continue;

        for (j = 0; j < 32 && nm[j]; j++) {
            BYTE c = (BYTE)nm[j];
            if (c < 0x20 || c > 0x7E) { pe->exportNameWeird = TRUE; break; }
        }
        if (j == 0) pe->exportNameWeird = TRUE;   /* ten rong */
    }
}

/* ==================================================================
 * PARSE TLS DIRECTORY  (DataDirectory[9])
 * ------------------------------------------------------------------
 * TLS callback CHAY TRUOC entry point. Malware dung de thuc thi code
 * truoc khi debugger kip dat breakpoint o EP -> rat dang ngo (+2).
 *
 * BAY: truong AddressOfCallBacks la VA TUYET DOI (da cong ImageBase),
 * khong phai RVA. Phai tru ImageBase truoc khi quy doi.
 * ================================================================== */
static void ParseTls(const PeBuf *b, PeInfo *pe)
{
    DWORD tlsRva = pe->dirRva[IMAGE_DIRECTORY_ENTRY_TLS];
    DWORD off, cbOff, i;
    ULONGLONG cbVa = 0;

    if (tlsRva == 0) return;
    off = RvaToFileOffset(pe, tlsRva);
    if (off == 0) return;

    pe->hasTls = TRUE;

    if (pe->isPE32Plus) {
        const IMAGE_TLS_DIRECTORY64 *t =
            (const IMAGE_TLS_DIRECTORY64 *)At(b, off, sizeof(IMAGE_TLS_DIRECTORY64));
        if (!t) return;
        cbVa = t->AddressOfCallBacks;
    } else {
        const IMAGE_TLS_DIRECTORY32 *t =
            (const IMAGE_TLS_DIRECTORY32 *)At(b, off, sizeof(IMAGE_TLS_DIRECTORY32));
        if (!t) return;
        cbVa = t->AddressOfCallBacks;
    }

    if (cbVa == 0 || cbVa <= pe->imageBase) return;

    /* VA -> RVA -> file offset */
    cbOff = RvaToFileOffset(pe, (DWORD)(cbVa - pe->imageBase));
    if (cbOff == 0) return;

    /* Mang con tro callback, ket thuc bang phan tu 0 */
    for (i = 0; i < 64; i++) {
        if (pe->isPE32Plus) {
            const ULONGLONG *p = (const ULONGLONG *)At(b, cbOff + i * 8, 8);
            if (!p || *p == 0) break;
        } else {
            const DWORD *p = (const DWORD *)At(b, cbOff + i * 4, 4);
            if (!p || *p == 0) break;
        }
        pe->tlsCallbackCount++;
    }
}

/* ==================================================================
 * PARSE RESOURCE DIRECTORY  (DataDirectory[2])
 * ------------------------------------------------------------------
 * Resource la CAY 3 TANG: Type -> Name/ID -> Language -> DataEntry
 * Ta chi can duyet tang 1 (Type) de biet co VersionInfo/Icon/Manifest,
 * va di sau vao RCDATA de do kich thuoc + entropy.
 *
 * Trong IMAGE_RESOURCE_DIRECTORY_ENTRY:
 *   OffsetToData bit 31 = 1 -> tro toi thu muc con (offset tuong doi
 *                              so voi DAU vung resource)
 *   bit 31 = 0 -> tro toi IMAGE_RESOURCE_DATA_ENTRY
 * ================================================================== */
static void ParseResources(const PeBuf *b, PeInfo *pe)
{
    DWORD resRva = pe->dirRva[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    DWORD base, i;
    const IMAGE_RESOURCE_DIRECTORY *root;
    WORD total;

    if (resRva == 0) return;
    base = RvaToFileOffset(pe, resRva);
    if (base == 0) return;

    root = (const IMAGE_RESOURCE_DIRECTORY *)At(b, base, sizeof(IMAGE_RESOURCE_DIRECTORY));
    if (!root) return;

    total = (WORD)(root->NumberOfNamedEntries + root->NumberOfIdEntries);
    if (total > 64) total = 64;

    for (i = 0; i < total; i++) {
        const IMAGE_RESOURCE_DIRECTORY_ENTRY *e;
        DWORD typeId;

        e = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)
            At(b, base + sizeof(IMAGE_RESOURCE_DIRECTORY)
                  + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY),
               sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
        if (!e) break;

        if (e->NameIsString) continue;   /* type dat ten bang chuoi - bo qua */
        typeId = e->Id;

        if (typeId == 16) pe->hasVersionInfo = TRUE;   /* RT_VERSION */
        if (typeId == 3 || typeId == 14) pe->hasIcon = TRUE; /* RT_ICON / RT_GROUP_ICON */
        if (typeId == 24) pe->hasManifest = TRUE;      /* RT_MANIFEST */

        /* RT_RCDATA = 10: di sau 2 tang de lay du lieu that */
        if (typeId == 10 && e->DataIsDirectory) {
            const IMAGE_RESOURCE_DIRECTORY *lvl2;
            const IMAGE_RESOURCE_DIRECTORY_ENTRY *e2;
            DWORD off2 = base + e->OffsetToDirectory;

            lvl2 = (const IMAGE_RESOURCE_DIRECTORY *)At(b, off2, sizeof(IMAGE_RESOURCE_DIRECTORY));
            if (!lvl2) continue;

            e2 = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)
                 At(b, off2 + sizeof(IMAGE_RESOURCE_DIRECTORY),
                    sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
            if (!e2 || !e2->DataIsDirectory) continue;

            {
                DWORD off3 = base + e2->OffsetToDirectory;
                const IMAGE_RESOURCE_DIRECTORY_ENTRY *e3 =
                    (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)
                    At(b, off3 + sizeof(IMAGE_RESOURCE_DIRECTORY),
                       sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
                const IMAGE_RESOURCE_DATA_ENTRY *de;
                DWORD dataOff;

                if (!e3 || e3->DataIsDirectory) continue;

                de = (const IMAGE_RESOURCE_DATA_ENTRY *)
                     At(b, base + e3->OffsetToData, sizeof(IMAGE_RESOURCE_DATA_ENTRY));
                if (!de) continue;

                if (de->Size > pe->biggestRcData) pe->biggestRcData = de->Size;

                /* OffsetToData trong DATA_ENTRY la RVA (khac 2 tang tren!) */
                dataOff = RvaToFileOffset(pe, de->OffsetToData);
                if (dataOff != 0 && de->Size > 0) {
                    DWORD n = de->Size > 65536 ? 65536 : de->Size;
                    const BYTE *d = At(b, dataOff, n);
                    if (d) {
                        double h = PeEntropy(d, n);
                        if (h > pe->rcDataEntropy) pe->rcDataEntropy = h;
                    }
                }
            }
        }
    }
}

/* ==================================================================
 * TIM RICH HEADER
 * ------------------------------------------------------------------
 * Rich header la vung khong chinh thuc do linker Microsoft chen giua
 * DOS stub va NT headers, chua dau chi cong cu build. File that cua
 * Microsoft gan nhu luon co. Thieu no o mot file "trong giong" san
 * pham thuong mai la mot dau hieu (file duoc dung lai/che bien).
 *
 * Nhan dien: chuoi "Rich" nam truoc e_lfanew.
 * ================================================================== */
static BOOL FindRichHeader(const PeBuf *b, DWORD lfanew)
{
    DWORD i;
    DWORD limit = (lfanew < b->size) ? lfanew : b->size;

    if (limit < 0x80) return FALSE;
    for (i = 0x80; i + 4 <= limit; i += 4) {
        if (memcmp(b->img + i, "Rich", 4) == 0) return TRUE;
    }
    return FALSE;
}

/* ==================================================================
 * HAM CHINH - PeRead
 * ================================================================== */
int PeRead(const char *path, PeInfo *pe)
{
    PeBuf b;
    int rc;
    DWORD lfanew, optOff, secOff, i;
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_FILE_HEADER *fh;
    WORD optMagic, sizeOfOpt;
    ULONGLONG maxSecEnd = 0;

    if (!pe || !path) return PE_ERR_IO;
    memset(pe, 0, sizeof(PeInfo));
    pe->status    = PE_ERR_IO;
    pe->signState = SIGN_UNSIGNED;

    /* ---------- Doc file ---------- */
    rc = LoadFile(path, &b);
    if (rc != PE_OK) {
        pe->status = rc;
        strcpy(pe->errMsg, (rc == PE_ERR_IO) ? "Khong mo/doc duoc file"
                                             : "File qua ngan de la PE");
        return rc;
    }
    pe->fileSize = b.fileSize;

    /* Entropy tong the (1MB dau) */
    {
        DWORD n = b.size > (1024 * 1024) ? (1024 * 1024) : b.size;
        pe->fileEntropy = PeEntropy(b.img, n);
    }

    /* ---------- BUOC 1: DOS HEADER ----------
     * Kiem 'MZ' o offset 0. Day chinh la validate magic bai 1.3. */
    dos = (const IMAGE_DOS_HEADER *)At(&b, 0, sizeof(IMAGE_DOS_HEADER));
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        pe->status = PE_MALFORMED_PE;
        strcpy(pe->errMsg, "Thieu chu ky 'MZ' o dau file");
        free(b.img);
        return PE_MALFORMED_PE;
    }

    /* e_lfanew tai offset 0x3C tro toi NT headers.
     * Phai kiem tra ky: gia tri am/qua lon la dau hieu file bi che bien. */
    lfanew = (DWORD)dos->e_lfanew;
    if (lfanew < sizeof(IMAGE_DOS_HEADER) || lfanew + 4 + sizeof(IMAGE_FILE_HEADER) > b.size) {
        pe->status = PE_MALFORMED_PE;
        strcpy(pe->errMsg, "e_lfanew tro ra ngoai file");
        free(b.img);
        return PE_MALFORMED_PE;
    }

    /* ---------- BUOC 2: CHU KY 'PE\0\0' ---------- */
    {
        const DWORD *sig = (const DWORD *)At(&b, lfanew, 4);
        if (!sig || *sig != IMAGE_NT_SIGNATURE) {
            pe->status = PE_MALFORMED_PE;
            strcpy(pe->errMsg, "Thieu chu ky 'PE\\0\\0'");
            free(b.img);
            return PE_MALFORMED_PE;
        }
    }

    pe->hasRichHeader = FindRichHeader(&b, lfanew);

    /* ---------- BUOC 3: FILE HEADER (20 byte) ---------- */
    fh = (const IMAGE_FILE_HEADER *)At(&b, lfanew + 4, sizeof(IMAGE_FILE_HEADER));
    if (!fh) {
        pe->status = PE_MALFORMED_PE;
        strcpy(pe->errMsg, "File header bi cat");
        free(b.img);
        return PE_MALFORMED_PE;
    }

    pe->machine         = fh->Machine;
    pe->sectionCount    = fh->NumberOfSections;
    pe->timeDateStamp   = fh->TimeDateStamp;
    pe->characteristics = fh->Characteristics;
    pe->isDll           = (fh->Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;
    sizeOfOpt           = fh->SizeOfOptionalHeader;

    if (pe->sectionCount == 0 || pe->sectionCount > PE_MAX_SECTIONS) {
        pe->status = PE_STRUCT_CORRUPT;
        sprintf(pe->errMsg, "So section vo ly: %u", pe->sectionCount);
        free(b.img);
        return PE_STRUCT_CORRUPT;
    }

    /* ---------- BUOC 4: OPTIONAL HEADER ----------
     * Magic quyet dinh bo cuc:
     *   0x10B = PE32  -> ImageBase la 4 byte
     *   0x20B = PE32+ -> ImageBase la 8 byte
     * Vi ImageBase nam GIUA struct, moi truong SAU no bi lech 4 byte
     * giua hai loai. Khong phan nhanh dung -> doc sai toan bo phan sau. */
    optOff = lfanew + 4 + sizeof(IMAGE_FILE_HEADER);
    {
        const WORD *pMagic = (const WORD *)At(&b, optOff, 2);
        if (!pMagic) {
            pe->status = PE_MALFORMED_PE;
            strcpy(pe->errMsg, "Optional header bi cat");
            free(b.img);
            return PE_MALFORMED_PE;
        }
        optMagic = *pMagic;
    }

    if (optMagic == 0x20B) {
        const IMAGE_OPTIONAL_HEADER64 *oh =
            (const IMAGE_OPTIONAL_HEADER64 *)At(&b, optOff, sizeof(IMAGE_OPTIONAL_HEADER64));
        if (!oh) {
            pe->status = PE_MALFORMED_PE;
            strcpy(pe->errMsg, "Optional header PE32+ bi cat");
            free(b.img);
            return PE_MALFORMED_PE;
        }
        pe->isPE32Plus          = TRUE;
        pe->entryPointRva       = oh->AddressOfEntryPoint;
        pe->imageBase           = oh->ImageBase;
        pe->sectionAlignment    = oh->SectionAlignment;
        pe->fileAlignment       = oh->FileAlignment;
        pe->subsystem           = oh->Subsystem;
        pe->numberOfRvaAndSizes = oh->NumberOfRvaAndSizes;
        pe->sizeOfImage         = oh->SizeOfImage;
        pe->sizeOfHeaders       = oh->SizeOfHeaders;
        pe->dllCharacteristics  = oh->DllCharacteristics;

        for (i = 0; i < 16; i++) {
            if (i < oh->NumberOfRvaAndSizes) {
                pe->dirRva[i]  = oh->DataDirectory[i].VirtualAddress;
                pe->dirSize[i] = oh->DataDirectory[i].Size;
            }
        }
    } else if (optMagic == 0x10B) {
        const IMAGE_OPTIONAL_HEADER32 *oh =
            (const IMAGE_OPTIONAL_HEADER32 *)At(&b, optOff, sizeof(IMAGE_OPTIONAL_HEADER32));
        if (!oh) {
            pe->status = PE_MALFORMED_PE;
            strcpy(pe->errMsg, "Optional header PE32 bi cat");
            free(b.img);
            return PE_MALFORMED_PE;
        }
        pe->isPE32Plus          = FALSE;
        pe->entryPointRva       = oh->AddressOfEntryPoint;
        pe->imageBase           = oh->ImageBase;
        pe->sectionAlignment    = oh->SectionAlignment;
        pe->fileAlignment       = oh->FileAlignment;
        pe->subsystem           = oh->Subsystem;
        pe->numberOfRvaAndSizes = oh->NumberOfRvaAndSizes;
        pe->sizeOfImage         = oh->SizeOfImage;
        pe->sizeOfHeaders       = oh->SizeOfHeaders;
        pe->dllCharacteristics  = oh->DllCharacteristics;

        for (i = 0; i < 16; i++) {
            if (i < oh->NumberOfRvaAndSizes) {
                pe->dirRva[i]  = oh->DataDirectory[i].VirtualAddress;
                pe->dirSize[i] = oh->DataDirectory[i].Size;
            }
        }
    } else {
        pe->status = PE_MALFORMED_PE;
        sprintf(pe->errMsg, "Optional magic la 0x%X, khong phai PE32/PE32+", optMagic);
        free(b.img);
        return PE_MALFORMED_PE;
    }

    /* Driver: subsystem NATIVE (1) va thuong co duoi .sys */
    pe->isDriver  = (pe->subsystem == 1) ? TRUE : FALSE;
    /* .NET: co COM Descriptor directory (index 14) */
    pe->isManaged = (pe->dirRva[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] != 0) ? TRUE : FALSE;
    pe->hasDebug  = (pe->dirRva[IMAGE_DIRECTORY_ENTRY_DEBUG] != 0) ? TRUE : FALSE;

    /* Security Directory: BAY LON NHAT CUA PE.
     * Truong "VirtualAddress" cua muc [4] thuc chat la FILE OFFSET,
     * KHONG phai RVA. Khong duoc goi RvaToFileOffset cho no. */
    pe->securityDirOffset = pe->dirRva[IMAGE_DIRECTORY_ENTRY_SECURITY];
    pe->securityDirSize   = pe->dirSize[IMAGE_DIRECTORY_ENTRY_SECURITY];
    pe->isSigned          = (pe->securityDirOffset != 0 && pe->securityDirSize != 0);

    /* ---------- BUOC 5: SECTION TABLE ----------
     * Nam ngay sau Optional Header. 40 byte moi section. */
    secOff = optOff + sizeOfOpt;
    if (secOff + (ULONGLONG)pe->sectionCount * sizeof(IMAGE_SECTION_HEADER) > b.size) {
        pe->status = PE_STRUCT_CORRUPT;
        strcpy(pe->errMsg, "Section table vuot qua kich thuoc file");
        free(b.img);
        return PE_STRUCT_CORRUPT;
    }

    for (i = 0; i < pe->sectionCount; i++) {
        const IMAGE_SECTION_HEADER *sh =
            (const IMAGE_SECTION_HEADER *)At(&b, secOff + i * sizeof(IMAGE_SECTION_HEADER),
                                             sizeof(IMAGE_SECTION_HEADER));
        PeSection *s = &pe->sections[i];
        if (!sh) {
            pe->status = PE_STRUCT_CORRUPT;
            strcpy(pe->errMsg, "Section header bi cat");
            free(b.img);
            return PE_STRUCT_CORRUPT;
        }

        memcpy(s->name, sh->Name, 8);
        s->name[8] = '\0';
        s->virtualAddress   = sh->VirtualAddress;
        s->virtualSize      = sh->Misc.VirtualSize;
        s->sizeOfRawData    = sh->SizeOfRawData;
        s->pointerToRawData = sh->PointerToRawData;
        s->characteristics  = sh->Characteristics;
        s->isExec  = (sh->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? TRUE : FALSE;
        s->isWrite = (sh->Characteristics & IMAGE_SCN_MEM_WRITE)   ? TRUE : FALSE;
        s->isRead  = (sh->Characteristics & IMAGE_SCN_MEM_READ)    ? TRUE : FALSE;
        s->nameWeird = SectionNameWeird(s->name);

        /* Section tro ra ngoai file -> STRUCT_CORRUPT */
        if (s->sizeOfRawData > 0) {
            ULONGLONG end = (ULONGLONG)s->pointerToRawData + s->sizeOfRawData;
            if (end > b.fileSize) {
                pe->status = PE_STRUCT_CORRUPT;
                sprintf(pe->errMsg, "Section '%s' vuot kich thuoc file", s->name);
                free(b.img);
                return PE_STRUCT_CORRUPT;
            }
            if (end > maxSecEnd) maxSecEnd = end;

            /* Entropy that cua section (toi da 1MB de khong qua cham) */
            {
                DWORD n = s->sizeOfRawData > (1024 * 1024) ? (1024 * 1024) : s->sizeOfRawData;
                const BYTE *d = At(&b, s->pointerToRawData, n);
                if (d) s->entropy = PeEntropy(d, n);
            }
        }
    }

    /* ---------- BUOC 6: kiem tra DataDirectory tro ra ngoai file ---------- */
    for (i = 0; i < 16; i++) {
        if (pe->dirRva[i] == 0) continue;
        if (i == IMAGE_DIRECTORY_ENTRY_SECURITY) {
            /* muc [4] la file offset -> so sanh truc tiep voi fileSize */
            if ((ULONGLONG)pe->dirRva[i] + pe->dirSize[i] > b.fileSize) pe->dirOutOfFile = TRUE;
            continue;
        }
        if (pe->dirRva[i] >= pe->sizeOfImage) { pe->dirOutOfFile = TRUE; continue; }
        if (RvaToFileOffset(pe, pe->dirRva[i]) == 0) pe->dirOutOfFile = TRUE;
    }

    /* ---------- BUOC 7: OVERLAY ----------
     * Du lieu nam sau diem ket thuc cua section cuoi cung.
     * Khong thuoc section nao -> khong duoc nap vao RAM khi chay.
     * Malware hay giau payload o day. */
    if (b.fileSize > maxSecEnd && maxSecEnd > 0) {
        pe->overlayOffset = maxSecEnd;
        pe->overlaySize   = b.fileSize - maxSecEnd;
    }

    /* ---------- BUOC 8: cac bang phu ---------- */
    pe->hasDelayImport = (pe->dirRva[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] != 0) ? TRUE : FALSE;

    ParseImports(&b, pe);
    ParseExports(&b, pe);
    ParseTls(&b, pe);
    ParseResources(&b, pe);

    free(b.img);
    pe->status = PE_OK;
    strcpy(pe->errMsg, "OK");
    return PE_OK;
}
