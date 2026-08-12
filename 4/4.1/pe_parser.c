#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE
#undef _UNICODE
/*
 * Bai 4.1 - PE File Parser (Windows API + Dialog)
 * ===================================================================
 * Giao dien: cua so chinh chia 2 phan
 *   - Ben trai : TreeView liet ke cac Header / Directory
 *   - Ben phai : ListView hien thi chi tiet (Truong / Gia tri / Y nghia)
 *
 * Parse day du:
 *   DOS Header, NT Headers, File Header, Optional Header,
 *   Data Directories, Section Headers,
 *   Export / Import / Resource / Relocation Directory
 *
 * Ho tro ca PE32 (32-bit) va PE32+ (64-bit).
 *
 * Build tren Windows (x64), Visual Studio:
 *   cl /Od pe_parser.c user32.lib gdi32.lib comctl32.lib comdlg32.lib
 *   (Trong Visual Studio: Properties -> Linker -> System -> SubSystem = Windows)
 */

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

/* ================= ID cac thanh phan ================= */
#define ID_TREE   1001
#define ID_LIST   1002
#define IDM_OPEN  2001
#define IDM_EXIT  2002

/* Ma dinh danh tung nut tren TreeView (luu vao lParam) */
enum {
    NODE_NONE = 0,
    NODE_DOS, NODE_NT, NODE_FILEHDR, NODE_OPTHDR, NODE_DATADIR,
    NODE_SECTIONS, NODE_EXPORT, NODE_IMPORT, NODE_RESOURCE, NODE_RELOC
};

/* ================= Bien toan cuc ================= */
static HWND  g_hMain, g_hTree, g_hList;
static BYTE *g_pFile     = NULL;    /* toan bo file nam trong RAM */
static DWORD g_fileSize  = 0;
static PIMAGE_DOS_HEADER      g_pDos   = NULL;
static PIMAGE_NT_HEADERS32    g_pNt32  = NULL;
static PIMAGE_NT_HEADERS64    g_pNt64  = NULL;
static PIMAGE_SECTION_HEADER  g_pSec   = NULL;
static WORD  g_numSec = 0;
static BOOL  g_is64   = FALSE;
static char  g_filePath[MAX_PATH] = "";

/* ==================================================================
 * TIEN ICH CHUNG
 * ================================================================== */

/* Kiem tra con tro co nam trong vung file da nap khong (chong crash
   khi doc file PE bi hong hoac co so lieu gia mao) */
static BOOL InFile(const void *p, DWORD size)
{
    const BYTE *b = (const BYTE *)p;
    if (!g_pFile || !b) return FALSE;
    if (b < g_pFile) return FALSE;
    if (b + size > g_pFile + g_fileSize) return FALSE;
    return TRUE;
}

/* Doi RVA (dia chi ao khi da nap vao RAM) -> offset that trong file.
   Day la ham QUAN TRONG NHAT cua ca bai: moi Directory deu luu dia chi
   theo RVA, nhung ta dang doc FILE tren dia nen phai quy doi. */
static DWORD RvaToOffset(DWORD rva)
{
    WORD i;
    if (!g_pSec || rva == 0) return 0;
    for (i = 0; i < g_numSec; i++) {
        DWORD va = g_pSec[i].VirtualAddress;
        DWORD vs = g_pSec[i].Misc.VirtualSize;
        if (vs == 0) vs = g_pSec[i].SizeOfRawData;
        if (rva >= va && rva < va + vs) {
            return g_pSec[i].PointerToRawData + (rva - va);
        }
    }
    return 0;
}

/* Lay 1 muc trong bang Data Directory (xu ly ca PE32 va PE32+) */
static PIMAGE_DATA_DIRECTORY GetDataDir(int index)
{
    if (index < 0 || index >= 16) return NULL;
    if (g_is64) {
        if (!g_pNt64) return NULL;
        if ((DWORD)index >= g_pNt64->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        return &g_pNt64->OptionalHeader.DataDirectory[index];
    } else {
        if (!g_pNt32) return NULL;
        if ((DWORD)index >= g_pNt32->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        return &g_pNt32->OptionalHeader.DataDirectory[index];
    }
}

static const char *MachineName(WORD m)
{
    switch (m) {
        case 0x014c: return "Intel x86 (32-bit)";
        case 0x8664: return "AMD64 / x64 (64-bit)";
        case 0x01c0: return "ARM";
        case 0xaa64: return "ARM64";
        case 0x0200: return "Intel Itanium";
        default:     return "(khong xac dinh)";
    }
}

static const char *SubsystemName(WORD s)
{
    switch (s) {
        case 1:  return "Native (driver)";
        case 2:  return "Windows GUI";
        case 3:  return "Windows Console";
        case 7:  return "POSIX Console";
        case 9:  return "Windows CE GUI";
        case 10: return "EFI Application";
        default: return "(khac)";
    }
}

static const char *DataDirName(int i)
{
    static const char *names[16] = {
        "Export", "Import", "Resource", "Exception",
        "Security", "Base Relocation", "Debug", "Architecture",
        "Global Ptr", "TLS", "Load Config", "Bound Import",
        "IAT", "Delay Import", "COM Descriptor", "(Reserved)"
    };
    return (i >= 0 && i < 16) ? names[i] : "?";
}

static const char *ResTypeName(DWORD id)
{
    switch (id) {
        case 1:  return "CURSOR";
        case 2:  return "BITMAP";
        case 3:  return "ICON";
        case 4:  return "MENU";
        case 5:  return "DIALOG";
        case 6:  return "STRING";
        case 7:  return "FONTDIR";
        case 8:  return "FONT";
        case 9:  return "ACCELERATOR";
        case 10: return "RCDATA";
        case 11: return "MESSAGETABLE";
        case 12: return "GROUP_CURSOR";
        case 14: return "GROUP_ICON";
        case 16: return "VERSION";
        case 24: return "MANIFEST";
        default: return "(tuy chinh)";
    }
}

/* ==================================================================
 * TIEN ICH LISTVIEW
 * ================================================================== */
static void ListClear(void)
{
    ListView_DeleteAllItems(g_hList);
}

static void ListAdd(const char *field, const char *value, const char *desc)
{
    LVITEMA it;
    int idx = ListView_GetItemCount(g_hList);
    ZeroMemory(&it, sizeof(it));
    it.mask     = LVIF_TEXT;
    it.iItem    = idx;
    it.iSubItem = 0;
    it.pszText  = (LPSTR)field;
    ListView_InsertItem(g_hList, &it);
    ListView_SetItemText(g_hList, idx, 1, (LPSTR)(value ? value : ""));
    ListView_SetItemText(g_hList, idx, 2, (LPSTR)(desc  ? desc  : ""));
}

static void AddHex32(const char *field, DWORD v, const char *desc)
{
    char buf[64];
    sprintf(buf, "0x%08X", v);
    ListAdd(field, buf, desc);
}

static void AddHex16(const char *field, WORD v, const char *desc)
{
    char buf[64];
    sprintf(buf, "0x%04X", v);
    ListAdd(field, buf, desc);
}

static void AddDec(const char *field, DWORD v, const char *desc)
{
    char buf[64];
    sprintf(buf, "%lu", (unsigned long)v);
    ListAdd(field, buf, desc);
}

static void AddHex64(const char *field, ULONGLONG v, const char *desc)
{
    char buf[64];
    sprintf(buf, "0x%016llX", (unsigned long long)v);
    ListAdd(field, buf, desc);
}

/* ==================================================================
 * HIEN THI: DOS HEADER
 * ================================================================== */
static void ShowDosHeader(void)
{
    char buf[64];
    if (!g_pDos) return;

    sprintf(buf, "0x%04X (\"MZ\")", g_pDos->e_magic);
    ListAdd("e_magic", buf, "Chu ky DOS, luon la 'MZ'");
    AddHex16("e_cblp",     g_pDos->e_cblp,     "So byte tren trang cuoi");
    AddHex16("e_cp",       g_pDos->e_cp,       "So trang trong file");
    AddHex16("e_crlc",     g_pDos->e_crlc,     "So muc relocation (DOS)");
    AddHex16("e_cparhdr",  g_pDos->e_cparhdr,  "Kich thuoc header (paragraph)");
    AddHex16("e_minalloc", g_pDos->e_minalloc, "Bo nho toi thieu can them");
    AddHex16("e_maxalloc", g_pDos->e_maxalloc, "Bo nho toi da can them");
    AddHex16("e_ss",       g_pDos->e_ss,       "Gia tri thanh ghi SS ban dau");
    AddHex16("e_sp",       g_pDos->e_sp,       "Gia tri thanh ghi SP ban dau");
    AddHex16("e_csum",     g_pDos->e_csum,     "Checksum");
    AddHex16("e_ip",       g_pDos->e_ip,       "Gia tri IP ban dau");
    AddHex16("e_cs",       g_pDos->e_cs,       "Gia tri CS ban dau");
    AddHex16("e_lfarlc",   g_pDos->e_lfarlc,   "Offset bang relocation");
    AddHex16("e_ovno",     g_pDos->e_ovno,     "So hieu overlay");
    AddHex32("e_lfanew",   (DWORD)g_pDos->e_lfanew,
             "QUAN TRONG: offset toi NT Headers");
}

/* ==================================================================
 * HIEN THI: NT HEADERS (tong quan)
 * ================================================================== */
static void ShowNtHeaders(void)
{
    char buf[64];
    DWORD sig = g_is64 ? g_pNt64->Signature : g_pNt32->Signature;

    sprintf(buf, "0x%08X (\"PE\\0\\0\")", sig);
    ListAdd("Signature", buf, "Chu ky PE, xac nhan day la file PE");
    ListAdd("Kieu file", g_is64 ? "PE32+ (64-bit)" : "PE32 (32-bit)",
            "Xac dinh qua Optional Header Magic");
    AddHex32("Offset NT Headers", (DWORD)g_pDos->e_lfanew,
             "Vi tri bat dau trong file");
    ListAdd("", "", "");
    ListAdd("Ghi chu", "NT Headers gom 3 phan",
            "Signature + File Header + Optional Header");
}

/* ==================================================================
 * HIEN THI: FILE HEADER
 * ================================================================== */
static void ShowFileHeader(void)
{
    char buf[128];
    PIMAGE_FILE_HEADER fh = g_is64 ? &g_pNt64->FileHeader : &g_pNt32->FileHeader;
    time_t t;
    struct tm *lt;
    WORD c;

    sprintf(buf, "0x%04X", fh->Machine);
    ListAdd("Machine", buf, MachineName(fh->Machine));
    AddDec("NumberOfSections", fh->NumberOfSections, "So luong section trong file");

    t  = (time_t)fh->TimeDateStamp;
    lt = localtime(&t);
    if (lt) strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", lt);
    else    strcpy(buf, "(khong doc duoc)");
    ListAdd("TimeDateStamp", buf, "Thoi diem file duoc bien dich");

    AddHex32("PointerToSymbolTable", fh->PointerToSymbolTable, "Bang symbol (thuong = 0)");
    AddDec ("NumberOfSymbols",       fh->NumberOfSymbols,      "So symbol (thuong = 0)");
    AddDec ("SizeOfOptionalHeader",  fh->SizeOfOptionalHeader, "Kich thuoc Optional Header (byte)");

    c = fh->Characteristics;
    sprintf(buf, "0x%04X", c);
    ListAdd("Characteristics", buf, "Co mo ta thuoc tinh file");

    if (c & IMAGE_FILE_EXECUTABLE_IMAGE) ListAdd("  -> EXECUTABLE_IMAGE", "1", "File chay duoc");
    if (c & IMAGE_FILE_DLL)              ListAdd("  -> DLL",              "1", "Day la thu vien DLL");
    if (c & IMAGE_FILE_32BIT_MACHINE)    ListAdd("  -> 32BIT_MACHINE",    "1", "Danh cho may 32-bit");
    if (c & IMAGE_FILE_LARGE_ADDRESS_AWARE) ListAdd("  -> LARGE_ADDRESS_AWARE", "1", "Dung duoc dia chi > 2GB");
    if (c & IMAGE_FILE_SYSTEM)           ListAdd("  -> SYSTEM",           "1", "File he thong");
    if (c & IMAGE_FILE_RELOCS_STRIPPED)  ListAdd("  -> RELOCS_STRIPPED",  "1", "Da go bo thong tin relocation");
}

/* ==================================================================
 * HIEN THI: OPTIONAL HEADER
 * ================================================================== */
static void ShowOptionalHeader(void)
{
    char buf[128];

    if (g_is64) {
        PIMAGE_OPTIONAL_HEADER64 oh = &g_pNt64->OptionalHeader;
        sprintf(buf, "0x%04X", oh->Magic);
        ListAdd("Magic", buf, "0x20B = PE32+ (64-bit)");
        sprintf(buf, "%u.%u", oh->MajorLinkerVersion, oh->MinorLinkerVersion);
        ListAdd("LinkerVersion", buf, "Phien ban trinh linker");
        AddHex32("SizeOfCode",              oh->SizeOfCode,              "Tong kich thuoc vung code");
        AddHex32("SizeOfInitializedData",   oh->SizeOfInitializedData,   "Du lieu da khoi tao (.data)");
        AddHex32("SizeOfUninitializedData", oh->SizeOfUninitializedData, "Du lieu chua khoi tao (.bss)");
        AddHex32("AddressOfEntryPoint",     oh->AddressOfEntryPoint,     "RVA noi chuong trinh bat dau chay");
        AddHex32("BaseOfCode",              oh->BaseOfCode,              "RVA bat dau vung code");
        AddHex64("ImageBase",               oh->ImageBase,               "Dia chi mong muon khi nap vao RAM");
        AddHex32("SectionAlignment",        oh->SectionAlignment,        "Can le section trong RAM");
        AddHex32("FileAlignment",           oh->FileAlignment,           "Can le section trong FILE");
        sprintf(buf, "%u.%u", oh->MajorOperatingSystemVersion, oh->MinorOperatingSystemVersion);
        ListAdd("OS Version", buf, "Phien ban Windows toi thieu");
        sprintf(buf, "%u.%u", oh->MajorSubsystemVersion, oh->MinorSubsystemVersion);
        ListAdd("Subsystem Version", buf, "Phien ban subsystem");
        AddHex32("SizeOfImage",   oh->SizeOfImage,   "Tong kich thuoc khi nap vao RAM");
        AddHex32("SizeOfHeaders", oh->SizeOfHeaders, "Tong kich thuoc toan bo header");
        AddHex32("CheckSum",      oh->CheckSum,      "Checksum (driver bat buoc co)");
        sprintf(buf, "%u", oh->Subsystem);
        ListAdd("Subsystem", buf, SubsystemName(oh->Subsystem));
        AddHex16("DllCharacteristics", oh->DllCharacteristics, "Co bao mat (ASLR, DEP...)");
        AddHex64("SizeOfStackReserve", oh->SizeOfStackReserve, "Stack dat truoc");
        AddHex64("SizeOfStackCommit",  oh->SizeOfStackCommit,  "Stack cap ngay");
        AddHex64("SizeOfHeapReserve",  oh->SizeOfHeapReserve,  "Heap dat truoc");
        AddHex64("SizeOfHeapCommit",   oh->SizeOfHeapCommit,   "Heap cap ngay");
        AddDec ("NumberOfRvaAndSizes", oh->NumberOfRvaAndSizes, "So muc Data Directory (thuong 16)");
    } else {
        PIMAGE_OPTIONAL_HEADER32 oh = &g_pNt32->OptionalHeader;
        sprintf(buf, "0x%04X", oh->Magic);
        ListAdd("Magic", buf, "0x10B = PE32 (32-bit)");
        sprintf(buf, "%u.%u", oh->MajorLinkerVersion, oh->MinorLinkerVersion);
        ListAdd("LinkerVersion", buf, "Phien ban trinh linker");
        AddHex32("SizeOfCode",              oh->SizeOfCode,              "Tong kich thuoc vung code");
        AddHex32("SizeOfInitializedData",   oh->SizeOfInitializedData,   "Du lieu da khoi tao (.data)");
        AddHex32("SizeOfUninitializedData", oh->SizeOfUninitializedData, "Du lieu chua khoi tao (.bss)");
        AddHex32("AddressOfEntryPoint",     oh->AddressOfEntryPoint,     "RVA noi chuong trinh bat dau chay");
        AddHex32("BaseOfCode",              oh->BaseOfCode,              "RVA bat dau vung code");
        AddHex32("BaseOfData",              oh->BaseOfData,              "RVA bat dau vung du lieu");
        AddHex32("ImageBase",               oh->ImageBase,               "Dia chi mong muon khi nap vao RAM");
        AddHex32("SectionAlignment",        oh->SectionAlignment,        "Can le section trong RAM");
        AddHex32("FileAlignment",           oh->FileAlignment,           "Can le section trong FILE");
        sprintf(buf, "%u.%u", oh->MajorOperatingSystemVersion, oh->MinorOperatingSystemVersion);
        ListAdd("OS Version", buf, "Phien ban Windows toi thieu");
        sprintf(buf, "%u.%u", oh->MajorSubsystemVersion, oh->MinorSubsystemVersion);
        ListAdd("Subsystem Version", buf, "Phien ban subsystem");
        AddHex32("SizeOfImage",   oh->SizeOfImage,   "Tong kich thuoc khi nap vao RAM");
        AddHex32("SizeOfHeaders", oh->SizeOfHeaders, "Tong kich thuoc toan bo header");
        AddHex32("CheckSum",      oh->CheckSum,      "Checksum");
        sprintf(buf, "%u", oh->Subsystem);
        ListAdd("Subsystem", buf, SubsystemName(oh->Subsystem));
        AddHex16("DllCharacteristics", oh->DllCharacteristics, "Co bao mat (ASLR, DEP...)");
        AddHex32("SizeOfStackReserve", oh->SizeOfStackReserve, "Stack dat truoc");
        AddHex32("SizeOfStackCommit",  oh->SizeOfStackCommit,  "Stack cap ngay");
        AddHex32("SizeOfHeapReserve",  oh->SizeOfHeapReserve,  "Heap dat truoc");
        AddHex32("SizeOfHeapCommit",   oh->SizeOfHeapCommit,   "Heap cap ngay");
        AddDec ("NumberOfRvaAndSizes", oh->NumberOfRvaAndSizes, "So muc Data Directory (thuong 16)");
    }
}

/* ==================================================================
 * HIEN THI: DATA DIRECTORIES (16 muc)
 * ================================================================== */
static void ShowDataDirectories(void)
{
    int i;
    char field[64], value[128];

    for (i = 0; i < 16; i++) {
        PIMAGE_DATA_DIRECTORY d = GetDataDir(i);
        sprintf(field, "[%2d] %s", i, DataDirName(i));
        if (!d) {
            ListAdd(field, "(khong co)", "");
            continue;
        }
        sprintf(value, "RVA=0x%08X  Size=0x%08X", d->VirtualAddress, d->Size);
        if (d->VirtualAddress == 0) {
            ListAdd(field, value, "Khong su dung");
        } else {
            char desc[64];
            sprintf(desc, "Offset trong file = 0x%08X", RvaToOffset(d->VirtualAddress));
            ListAdd(field, value, desc);
        }
    }
}

/* ==================================================================
 * HIEN THI: SECTION HEADERS
 * ================================================================== */
static void ShowSections(void)
{
    WORD i;
    char name[16], field[64], value[160], desc[160];

    for (i = 0; i < g_numSec; i++) {
        PIMAGE_SECTION_HEADER s = &g_pSec[i];
        DWORD c = s->Characteristics;

        memset(name, 0, sizeof(name));
        memcpy(name, s->Name, 8);

        sprintf(field, "[%u] %s", i, name);
        sprintf(value, "VA=0x%08X  VSize=0x%08X", s->VirtualAddress, s->Misc.VirtualSize);
        sprintf(desc,  "Raw=0x%08X  RawSize=0x%08X", s->PointerToRawData, s->SizeOfRawData);
        ListAdd(field, value, desc);

        strcpy(value, "");
        if (c & IMAGE_SCN_MEM_READ)    strcat(value, "READ ");
        if (c & IMAGE_SCN_MEM_WRITE)   strcat(value, "WRITE ");
        if (c & IMAGE_SCN_MEM_EXECUTE) strcat(value, "EXEC ");
        if (c & IMAGE_SCN_CNT_CODE)              strcat(value, "| CODE ");
        if (c & IMAGE_SCN_CNT_INITIALIZED_DATA)  strcat(value, "| INIT_DATA ");
        if (c & IMAGE_SCN_CNT_UNINITIALIZED_DATA)strcat(value, "| UNINIT_DATA ");
        sprintf(desc, "Characteristics = 0x%08X", c);
        ListAdd("      Quyen truy cap", value, desc);
    }

    if (g_numSec == 0) ListAdd("(khong co section)", "", "");
}

/* ==================================================================
 * HIEN THI: EXPORT DIRECTORY
 * ================================================================== */
static void ShowExport(void)
{
    PIMAGE_DATA_DIRECTORY dir = GetDataDir(IMAGE_DIRECTORY_ENTRY_EXPORT);
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD off, i, *pNames, *pFuncs;
    WORD *pOrds;
    char field[64], value[256], desc[128];

    if (!dir || dir->VirtualAddress == 0) {
        ListAdd("(khong co Export Directory)", "",
                "File nay khong xuat ham nao (thuong la .exe)");
        return;
    }

    off = RvaToOffset(dir->VirtualAddress);
    exp = (PIMAGE_EXPORT_DIRECTORY)(g_pFile + off);
    if (!InFile(exp, sizeof(IMAGE_EXPORT_DIRECTORY))) {
        ListAdd("(loi)", "", "Export Directory nam ngoai vung file");
        return;
    }

    off = RvaToOffset(exp->Name);
    if (off && InFile(g_pFile + off, 1))
        ListAdd("Ten module", (char *)(g_pFile + off), "Ten DLL goc luc bien dich");

    AddHex32("Characteristics", exp->Characteristics, "Thuong = 0");
    AddDec ("Base",             exp->Base,            "So thu tu (ordinal) bat dau");
    AddDec ("NumberOfFunctions",exp->NumberOfFunctions,"Tong so ham xuat ra");
    AddDec ("NumberOfNames",    exp->NumberOfNames,   "So ham xuat theo TEN");
    AddHex32("AddressOfFunctions",    exp->AddressOfFunctions,    "RVA bang dia chi ham");
    AddHex32("AddressOfNames",        exp->AddressOfNames,        "RVA bang ten ham");
    AddHex32("AddressOfNameOrdinals", exp->AddressOfNameOrdinals, "RVA bang ordinal");
    ListAdd("", "", "");
    ListAdd("--- DANH SACH HAM XUAT ---", "", "");

    pNames = (DWORD *)(g_pFile + RvaToOffset(exp->AddressOfNames));
    pOrds  = (WORD  *)(g_pFile + RvaToOffset(exp->AddressOfNameOrdinals));
    pFuncs = (DWORD *)(g_pFile + RvaToOffset(exp->AddressOfFunctions));

    if (!InFile(pNames, 4) || !InFile(pOrds, 2) || !InFile(pFuncs, 4)) {
        ListAdd("(loi)", "", "Bang export nam ngoai vung file");
        return;
    }

    for (i = 0; i < exp->NumberOfNames && i < 3000; i++) {
        DWORD nameOff = RvaToOffset(pNames[i]);
        const char *fname = "(?)";
        WORD ord;
        DWORD funcRva = 0;

        if (nameOff && InFile(g_pFile + nameOff, 1))
            fname = (const char *)(g_pFile + nameOff);

        ord = pOrds[i];
        if (ord < exp->NumberOfFunctions) funcRva = pFuncs[ord];

        sprintf(field, "  [%lu]", (unsigned long)i);
        sprintf(value, "%.200s", fname);
        sprintf(desc,  "Ordinal=%u  RVA=0x%08X",
                (unsigned)(ord + exp->Base), funcRva);
        ListAdd(field, value, desc);
    }
}

/* ==================================================================
 * HIEN THI: IMPORT DIRECTORY
 * ================================================================== */
static void ShowImport(void)
{
    PIMAGE_DATA_DIRECTORY dir = GetDataDir(IMAGE_DIRECTORY_ENTRY_IMPORT);
    PIMAGE_IMPORT_DESCRIPTOR imp;
    DWORD off, total = 0;
    char field[64], value[256], desc[128];

    if (!dir || dir->VirtualAddress == 0) {
        ListAdd("(khong co Import Directory)", "", "File khong goi ham tu DLL nao");
        return;
    }

    off = RvaToOffset(dir->VirtualAddress);
    imp = (PIMAGE_IMPORT_DESCRIPTOR)(g_pFile + off);

    while (InFile(imp, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && imp->Name != 0 && total < 5000) {
        DWORD dllOff = RvaToOffset(imp->Name);
        const char *dllName = "(?)";
        DWORD thunkRva, thunkOff, k;

        if (dllOff && InFile(g_pFile + dllOff, 1))
            dllName = (const char *)(g_pFile + dllOff);

        sprintf(desc, "OriginalFirstThunk=0x%08X  FirstThunk=0x%08X",
                imp->OriginalFirstThunk, imp->FirstThunk);
        ListAdd("=== DLL ===", dllName, desc);

        thunkRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        thunkOff = RvaToOffset(thunkRva);

        if (thunkOff == 0) { imp++; continue; }

        if (g_is64) {
            ULONGLONG *t = (ULONGLONG *)(g_pFile + thunkOff);
            for (k = 0; InFile(t + k, 8) && t[k] != 0 && total < 5000; k++, total++) {
                if (t[k] & 0x8000000000000000ULL) {
                    sprintf(field, "  (ordinal)");
                    sprintf(value, "#%llu", (unsigned long long)(t[k] & 0xFFFF));
                    ListAdd(field, value, "Import theo so thu tu");
                } else {
                    DWORD nOff = RvaToOffset((DWORD)t[k]);
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(g_pFile + nOff);
                    if (nOff && InFile(ibn, sizeof(WORD) + 1)) {
                        sprintf(desc, "Hint=%u", ibn->Hint);
                        ListAdd("  ->", (const char *)ibn->Name, desc);
                    }
                }
            }
        } else {
            DWORD *t = (DWORD *)(g_pFile + thunkOff);
            for (k = 0; InFile(t + k, 4) && t[k] != 0 && total < 5000; k++, total++) {
                if (t[k] & 0x80000000) {
                    sprintf(field, "  (ordinal)");
                    sprintf(value, "#%lu", (unsigned long)(t[k] & 0xFFFF));
                    ListAdd(field, value, "Import theo so thu tu");
                } else {
                    DWORD nOff = RvaToOffset(t[k]);
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(g_pFile + nOff);
                    if (nOff && InFile(ibn, sizeof(WORD) + 1)) {
                        sprintf(desc, "Hint=%u", ibn->Hint);
                        ListAdd("  ->", (const char *)ibn->Name, desc);
                    }
                }
            }
        }
        imp++;
    }
}

/* ==================================================================
 * HIEN THI: RESOURCE DIRECTORY (duyet 2 cap dau)
 * ================================================================== */
static void ShowResource(void)
{
    PIMAGE_DATA_DIRECTORY dir = GetDataDir(IMAGE_DIRECTORY_ENTRY_RESOURCE);
    PIMAGE_RESOURCE_DIRECTORY root;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY entry;
    DWORD off;
    int i, count;
    char field[64], value[128], desc[128];

    if (!dir || dir->VirtualAddress == 0) {
        ListAdd("(khong co Resource Directory)", "", "File khong chua icon/menu/dialog...");
        return;
    }

    off  = RvaToOffset(dir->VirtualAddress);
    root = (PIMAGE_RESOURCE_DIRECTORY)(g_pFile + off);
    if (!InFile(root, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
        ListAdd("(loi)", "", "Resource Directory nam ngoai vung file");
        return;
    }

    AddHex32("Characteristics", root->Characteristics, "Thuong = 0");
    AddHex32("TimeDateStamp",   root->TimeDateStamp,   "Thoi diem tao resource");
    AddDec ("NumberOfNamedEntries", root->NumberOfNamedEntries, "So muc dat theo TEN");
    AddDec ("NumberOfIdEntries",    root->NumberOfIdEntries,    "So muc dat theo ID");
    ListAdd("", "", "");
    ListAdd("--- CAC LOAI RESOURCE (cap 1) ---", "", "");

    count = root->NumberOfNamedEntries + root->NumberOfIdEntries;
    entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(root + 1);

    for (i = 0; i < count && i < 200; i++) {
        if (!InFile(&entry[i], sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) break;

        if (entry[i].NameIsString) {
            sprintf(field, "  [%d] (ten chuoi)", i);
            sprintf(value, "NameOffset=0x%08X", entry[i].NameOffset);
            strcpy(desc, "Resource dat ten bang chuoi");
        } else {
            sprintf(field, "  [%d] ID=%lu", i, (unsigned long)entry[i].Id);
            strcpy(value, ResTypeName(entry[i].Id));
            strcpy(desc, "");
        }

        if (entry[i].DataIsDirectory) {
            PIMAGE_RESOURCE_DIRECTORY sub =
                (PIMAGE_RESOURCE_DIRECTORY)((BYTE *)root + entry[i].OffsetToDirectory);
            if (InFile(sub, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
                sprintf(desc, "Chua %u muc con",
                        (unsigned)(sub->NumberOfNamedEntries + sub->NumberOfIdEntries));
            }
        } else {
            strcpy(desc, "Tro thang toi du lieu");
        }
        ListAdd(field, value, desc);
    }
}

/* ==================================================================
 * HIEN THI: RELOCATION DIRECTORY
 * ================================================================== */
static void ShowRelocation(void)
{
    PIMAGE_DATA_DIRECTORY dir = GetDataDir(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    PIMAGE_BASE_RELOCATION reloc;
    DWORD off, parsed = 0, totalEntries = 0;
    int blockIdx = 0;
    char field[64], value[128], desc[128];

    if (!dir || dir->VirtualAddress == 0) {
        ListAdd("(khong co Relocation Directory)", "",
                "File khong ho tro nap lai o dia chi khac");
        return;
    }

    off   = RvaToOffset(dir->VirtualAddress);
    reloc = (PIMAGE_BASE_RELOCATION)(g_pFile + off);

    sprintf(value, "RVA=0x%08X  Size=0x%08X", dir->VirtualAddress, dir->Size);
    ListAdd("Vi tri bang reloc", value, "Lay tu Data Directory [5]");
    ListAdd("", "", "");
    ListAdd("--- CAC BLOCK RELOCATION ---", "", "");

    while (InFile(reloc, sizeof(IMAGE_BASE_RELOCATION)) &&
           reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION) &&
           parsed < dir->Size && blockIdx < 500) {

        DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        totalEntries += numEntries;

        sprintf(field, "  Block [%d]", blockIdx);
        sprintf(value, "PageRVA=0x%08X", reloc->VirtualAddress);
        sprintf(desc,  "SizeOfBlock=%lu  So muc=%lu",
                (unsigned long)reloc->SizeOfBlock, (unsigned long)numEntries);
        ListAdd(field, value, desc);

        parsed += reloc->SizeOfBlock;
        reloc = (PIMAGE_BASE_RELOCATION)((BYTE *)reloc + reloc->SizeOfBlock);
        blockIdx++;
    }

    ListAdd("", "", "");
    sprintf(value, "%d", blockIdx);
    ListAdd("Tong so block", value, "Moi block quan ly 1 trang 4KB");
    sprintf(value, "%lu", (unsigned long)totalEntries);
    ListAdd("Tong so muc can sua", value, "So dia chi phai chinh khi doi ImageBase");
}

/* ==================================================================
 * XAY DUNG CAY TREEVIEW
 * ================================================================== */
static HTREEITEM AddTreeItem(HTREEITEM parent, const char *text, LPARAM data)
{
    TVINSERTSTRUCTA tvi;
    ZeroMemory(&tvi, sizeof(tvi));
    tvi.hParent      = parent ? parent : TVI_ROOT;
    tvi.hInsertAfter = TVI_LAST;
    tvi.item.mask    = TVIF_TEXT | TVIF_PARAM;
    tvi.item.pszText = (LPSTR)text;
    tvi.item.lParam  = data;
    return (HTREEITEM)SendMessageA(g_hTree, TVM_INSERTITEMA, 0, (LPARAM)&tvi);
}

static void BuildTree(void)
{
    HTREEITEM hNt, hOpt;

    SendMessageA(g_hTree, TVM_DELETEITEM, 0, (LPARAM)TVI_ROOT);

    AddTreeItem(NULL, "DOS Header", NODE_DOS);
    hNt  = AddTreeItem(NULL, "NT Headers", NODE_NT);
    AddTreeItem(hNt, "File Header", NODE_FILEHDR);
    hOpt = AddTreeItem(hNt, "Optional Header", NODE_OPTHDR);
    AddTreeItem(hOpt, "Data Directories", NODE_DATADIR);
    AddTreeItem(NULL, "Section Headers",       NODE_SECTIONS);
    AddTreeItem(NULL, "Export Directory",      NODE_EXPORT);
    AddTreeItem(NULL, "Import Directory",      NODE_IMPORT);
    AddTreeItem(NULL, "Resource Directory",    NODE_RESOURCE);
    AddTreeItem(NULL, "Relocation Directory",  NODE_RELOC);

    SendMessageA(g_hTree, TVM_EXPAND, TVE_EXPAND, (LPARAM)hNt);
    SendMessageA(g_hTree, TVM_EXPAND, TVE_EXPAND, (LPARAM)hOpt);
}

/* ==================================================================
 * NAP FILE PE VAO BO NHO VA KIEM TRA HOP LE
 * ================================================================== */
static BOOL LoadPeFile(const char *path)
{
    HANDLE hFile;
    DWORD read = 0;
    WORD magic;

    if (g_pFile) { free(g_pFile); g_pFile = NULL; }
    g_pDos = NULL; g_pNt32 = NULL; g_pNt64 = NULL; g_pSec = NULL;
    g_numSec = 0; g_fileSize = 0;

    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        MessageBoxA(g_hMain, "Khong mo duoc file.", "Loi", MB_ICONERROR);
        return FALSE;
    }

    g_fileSize = GetFileSize(hFile, NULL);
    if (g_fileSize == INVALID_FILE_SIZE || g_fileSize < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile);
        MessageBoxA(g_hMain, "File qua nho, khong phai file PE.", "Loi", MB_ICONERROR);
        return FALSE;
    }

    g_pFile = (BYTE *)malloc(g_fileSize);
    if (!g_pFile) {
        CloseHandle(hFile);
        MessageBoxA(g_hMain, "Khong du bo nho.", "Loi", MB_ICONERROR);
        return FALSE;
    }

    if (!ReadFile(hFile, g_pFile, g_fileSize, &read, NULL) || read != g_fileSize) {
        CloseHandle(hFile);
        free(g_pFile); g_pFile = NULL;
        MessageBoxA(g_hMain, "Doc file that bai.", "Loi", MB_ICONERROR);
        return FALSE;
    }
    CloseHandle(hFile);

    /* --- Kiem tra chu ky DOS "MZ" --- */
    g_pDos = (PIMAGE_DOS_HEADER)g_pFile;
    if (g_pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        free(g_pFile); g_pFile = NULL;
        MessageBoxA(g_hMain, "Thieu chu ky 'MZ' - khong phai file PE.", "Loi", MB_ICONERROR);
        return FALSE;
    }

    /* --- Nhay toi NT Headers qua e_lfanew --- */
    if ((DWORD)g_pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > g_fileSize) {
        free(g_pFile); g_pFile = NULL;
        MessageBoxA(g_hMain, "e_lfanew khong hop le.", "Loi", MB_ICONERROR);
        return FALSE;
    }

    g_pNt32 = (PIMAGE_NT_HEADERS32)(g_pFile + g_pDos->e_lfanew);
    if (g_pNt32->Signature != IMAGE_NT_SIGNATURE) {
        free(g_pFile); g_pFile = NULL;
        MessageBoxA(g_hMain, "Thieu chu ky 'PE' - khong phai file PE.", "Loi", MB_ICONERROR);
        return FALSE;
    }

    /* --- Phan biet PE32 va PE32+ qua Optional Header Magic --- */
    magic = g_pNt32->OptionalHeader.Magic;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        g_is64  = TRUE;
        g_pNt64 = (PIMAGE_NT_HEADERS64)g_pNt32;
        g_pNt32 = NULL;
        g_numSec = g_pNt64->FileHeader.NumberOfSections;
        g_pSec   = IMAGE_FIRST_SECTION(g_pNt64);
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        g_is64  = FALSE;
        g_numSec = g_pNt32->FileHeader.NumberOfSections;
        g_pSec   = IMAGE_FIRST_SECTION(g_pNt32);
    } else {
        free(g_pFile); g_pFile = NULL;
        MessageBoxA(g_hMain, "Optional Header Magic khong hop le.", "Loi", MB_ICONERROR);
        return FALSE;
    }

    strcpy(g_filePath, path);
    return TRUE;
}

/* ==================================================================
 * HOP THOAI CHON FILE
 * ================================================================== */
static void DoOpenFile(void)
{
    OPENFILENAMEA ofn;
    char path[MAX_PATH] = "";
    char title[MAX_PATH + 64];

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = g_hMain;
    ofn.lpstrFilter  = "File PE (*.exe;*.dll;*.sys;*.ocx)\0*.exe;*.dll;*.sys;*.ocx\0"
                       "Tat ca file (*.*)\0*.*\0";
    ofn.lpstrFile    = path;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrTitle   = "Chon file PE de phan tich";
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (!GetOpenFileNameA(&ofn)) return;

    if (LoadPeFile(path)) {
        BuildTree();
        ListClear();
        sprintf(title, "PE Parser - %s  [%s]", path, g_is64 ? "PE32+ 64-bit" : "PE32 32-bit");
        SetWindowTextA(g_hMain, title);
        ListAdd("Da nap file thanh cong", path, "Chon 1 muc ben trai de xem chi tiet");
    }
}

/* ==================================================================
 * XU LY KHI NGUOI DUNG CHON 1 NUT TREN CAY
 * ================================================================== */
static void OnTreeSelect(LPARAM nodeId)
{
    if (!g_pFile) {
        ListClear();
        ListAdd("(chua mo file)", "", "Dung menu File -> Mo file PE");
        return;
    }

    ListClear();
    switch (nodeId) {
        case NODE_DOS:      ShowDosHeader();       break;
        case NODE_NT:       ShowNtHeaders();       break;
        case NODE_FILEHDR:  ShowFileHeader();      break;
        case NODE_OPTHDR:   ShowOptionalHeader();  break;
        case NODE_DATADIR:  ShowDataDirectories(); break;
        case NODE_SECTIONS: ShowSections();        break;
        case NODE_EXPORT:   ShowExport();          break;
        case NODE_IMPORT:   ShowImport();          break;
        case NODE_RESOURCE: ShowResource();        break;
        case NODE_RELOC:    ShowRelocation();      break;
        default: break;
    }
}

/* ==================================================================
 * WINDOW PROCEDURE
 * ================================================================== */
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {

    case WM_CREATE: {
        HMENU hMenu, hFile;
        LVCOLUMNA col;
        HFONT hFont;

        /* --- Tao menu --- */
        hMenu = CreateMenu();
        hFile = CreatePopupMenu();
        AppendMenuA(hFile, MF_STRING, IDM_OPEN, "&Mo file PE...\tCtrl+O");
        AppendMenuA(hFile, MF_SEPARATOR, 0, NULL);
        AppendMenuA(hFile, MF_STRING, IDM_EXIT, "&Thoat");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hFile, "&File");
        SetMenu(hWnd, hMenu);

        /* --- TreeView ben trai --- */
        g_hTree = CreateWindowExA(WS_EX_CLIENTEDGE, WC_TREEVIEWA, "",
            WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_HASBUTTONS |
            TVS_LINESATROOT | TVS_SHOWSELALWAYS,
            0, 0, 240, 400, hWnd, (HMENU)ID_TREE, NULL, NULL);

        /* --- ListView ben phai --- */
        g_hList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            240, 0, 500, 400, hWnd, (HMENU)ID_LIST, NULL, NULL);

        ListView_SetExtendedListViewStyle(g_hList,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        SendMessageA(g_hTree, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(g_hList, WM_SETFONT, (WPARAM)hFont, TRUE);

        ZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = "Truong";   col.cx = 220; ListView_InsertColumn(g_hList, 0, &col);
        col.pszText = "Gia tri";  col.cx = 260; ListView_InsertColumn(g_hList, 1, &col);
        col.pszText = "Y nghia";  col.cx = 340; ListView_InsertColumn(g_hList, 2, &col);

        BuildTree();
        ListAdd("(chua mo file)", "", "Dung menu File -> Mo file PE");
        return 0;
    }

    case WM_SIZE: {
        int w = LOWORD(lParam), h = HIWORD(lParam);
        int treeW = 240;
        MoveWindow(g_hTree, 0, 0, treeW, h, TRUE);
        MoveWindow(g_hList, treeW, 0, w - treeW, h, TRUE);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
            case IDM_OPEN: DoOpenFile(); return 0;
            case IDM_EXIT: DestroyWindow(hWnd); return 0;
        }
        break;

    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lParam;
        if (nh->idFrom == ID_TREE && nh->code == TVN_SELCHANGEDA) {
            LPNMTREEVIEWA tv = (LPNMTREEVIEWA)lParam;
            OnTreeSelect(tv->itemNew.lParam);
            return 0;
        }
        break;
    }

    case WM_DESTROY:
        if (g_pFile) { free(g_pFile); g_pFile = NULL; }
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

    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_TREEVIEW_CLASSES | ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "PeParserWndClass";
    if (!RegisterClassA(&wc)) return 1;

    g_hMain = CreateWindowExA(0, "PeParserWndClass",
        "PE Parser (Bai 4.1) - File -> Mo file PE de bat dau",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1100, 650,
        NULL, NULL, hInst, NULL);
    if (!g_hMain) return 1;

    ShowWindow(g_hMain, nShow);
    UpdateWindow(g_hMain);

    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}
