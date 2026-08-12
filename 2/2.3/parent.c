#define _CRT_SECURE_NO_WARNINGS
/*
 * Bai 2.3 - PARENT PROCESS - Create Process & Inject Parameter
 * -------------------------------------------------------------------
 * Tu tao mot process con (child.exe) bang CreateProcessW, truyen tham so
 * tu CHA sang CON qua command line. Mo rong:
 *  - Log lai thoi gian chay va exit code cua process con
 *  - Redirect STDOUT cua process con ve process cha, doc qua Pipe
 *
 * QUAN TRONG:
 *  - child.exe PHAI nam CUNG THU MUC voi parent.exe (chuong trinh nay
 *    tu tim child.exe trong chinh thu muc chua no dang chay).
 *  - Chi build duoc tren Windows (Windows API).
 * 
 * Build tren Windows (x64), Visual Studio:
 *   cl /Od /std:c11 parent.c
 */

#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

void InFormLoi(const char *hanhDong)
{
    DWORD err = GetLastError();
    fprintf(stderr, "Loi: %s (ma loi Windows: %lu)\n", hanhDong, err);
}

int main(void)
{
    printf("========== PARENT PROCESS: TAO CHILD & TRUYEN THAM SO ==========\n\n");

    /* ---------------------------------------------------------------
     * BUOC 1: Tim duong dan day du toi child.exe (gia dinh nam CUNG
     * thu muc voi chinh file .exe dang chay nay)
     * --------------------------------------------------------------- */
    wchar_t exeDir[MAX_PATH];
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);   /* lay duong dan cua CHINH parent.exe */

    wchar_t *lastSlash = wcsrchr(exeDir, L'\\');
    if (lastSlash != NULL) {
        *(lastSlash + 1) = L'\0';   /* cat bo ten file, chi giu lai thu muc */
    }

    wchar_t childPath[MAX_PATH];
    swprintf_s(childPath, MAX_PATH, L"%schild.exe", exeDir);

    /* ---------------------------------------------------------------
     * BUOC 2: Hoi nguoi dung muon truyen tham so gi cho child
     * --------------------------------------------------------------- */
    char paramsNarrow[256] = "";
    printf("Nhap tham so muon truyen cho child , de trong neu khong co\n");
    printf("(go 'fail' de test truong hop child tra ve loi): ");
    fgets(paramsNarrow, sizeof(paramsNarrow), stdin);

    size_t len = strlen(paramsNarrow);
    if (len > 0 && paramsNarrow[len - 1] == '\n') {
        paramsNarrow[len - 1] = '\0';   /* bo ky tu xuong dong do fgets giu lai */
    }

    wchar_t paramsWide[256];
    MultiByteToWideChar(CP_ACP, 0, paramsNarrow, -1, paramsWide, 256);

    /* Ghep thanh dong lenh day du: "duong_dan\child.exe" tham_so...
       Dau ngoac kep quanh duong dan de xu ly truong hop duong dan co dau cach */
    wchar_t cmdLine[1024];
    swprintf_s(cmdLine, 1024, L"\"%s\" %s", childPath, paramsWide);

    wprintf(L"\n[PARENT] Se chay: %s\n", cmdLine);

    /* ---------------------------------------------------------------
     * BUOC 3: Tao Pipe de redirect STDOUT cua con ve cha
     * --------------------------------------------------------------- */
    SECURITY_ATTRIBUTES saPipe;
    saPipe.nLength = sizeof(SECURITY_ATTRIBUTES);
    saPipe.lpSecurityDescriptor = NULL;
    saPipe.bInheritHandle = TRUE;   /* BAT BUOC TRUE de child ke thua duoc dau ghi cua pipe */

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &saPipe, 0)) {
        InFormLoi("khong tao duoc pipe");
        return 1;
    }

    /* Dau DOC (hReadPipe) chi CHA dung, KHONG duoc de con ke thua no,
       neu khong pipe se khong bao gio "dong" dung luc (ganh 2 nguoi giu ban ghi) */
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    /* ---------------------------------------------------------------
     * BUOC 4: Cau hinh STARTUPINFO de "gan" STDOUT cua con vao pipe
     * --------------------------------------------------------------- */
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;   /* STDOUT cua con se di thang vao pipe */
    si.hStdError  = hWritePipe;   /* gom luon STDERR chung 1 pipe cho don gian */
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    /* ---------------------------------------------------------------
     * BUOC 5: Tao process con - day la lenh trung tam cua ca bai
     * --------------------------------------------------------------- */
    ULONGLONG tBatDau = GetTickCount64();

    BOOL ok = CreateProcessW(
        NULL,        /* lpApplicationName: NULL vi duong dan da nam trong cmdLine */
        cmdLine,     /* lpCommandLine: BAT BUOC la buffer CO THE SUA (khong dung string literal) */
        NULL,        /* lpProcessAttributes: mac dinh */
        NULL,        /* lpThreadAttributes: mac dinh */
        TRUE,        /* bInheritHandles: TRUE de con ke thua duoc pipe write-end */
        0,           /* dwCreationFlags */
        NULL,        /* lpEnvironment: ke thua moi truong tu cha */
        NULL,        /* lpCurrentDirectory: ke thua thu muc lam viec tu cha */
        &si,
        &pi
    );

    if (!ok) {
        InFormLoi("khong tao duoc process con (kiem tra child.exe co ton tai dung cho khong)");
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return 1;
    }

    /* QUAN TRONG: dong dau GHI trong CHA ngay sau khi tao process xong.
       Neu khong dong, ReadFile ben duoi se KHONG BAO GIO tra ve "het du lieu",
       vi Windows nghi con vẫn co the con ghi them (vi cha van giu 1 tay cam ghi) */
    CloseHandle(hWritePipe);

    /* ---------------------------------------------------------------
     * BUOC 6: Doc STDOUT cua con qua pipe, cho den khi con dong (thoat)
     * --------------------------------------------------------------- */
    printf("\n===== OUTPUT TU CHILD (da duoc redirect ve CHA qua STDOUT) =====\n");
    char readBuf[256];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, readBuf, sizeof(readBuf) - 1, &bytesRead, NULL) && bytesRead > 0) {
        readBuf[bytesRead] = '\0';
        printf("%s", readBuf);
    }
    printf("===== HET OUTPUT TU CHILD =====\n\n");

    CloseHandle(hReadPipe);

    /* ---------------------------------------------------------------
     * BUOC 7: Cho process con ket thuc han va lay Exit Code
     * --------------------------------------------------------------- */
    WaitForSingleObject(pi.hProcess, INFINITE);

    ULONGLONG tKetThuc = GetTickCount64();

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    printf("========== LOG KET QUA ==========\n");
    printf("Thoi gian chay: %llu ms\n", (unsigned long long)(tKetThuc - tBatDau));
    printf("Exit code     : %lu   (%s)\n",
           exitCode, exitCode == 0 ? "THANH CONG" : "CO LOI / KHAC 0");

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
