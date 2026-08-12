#define _CRT_SECURE_NO_WARNINGS
/*
 * Bai 2.3 - CHILD PROCESS
 * -------------------------------------------------------------------
 * Chuong trinh CON, don gian, dung de:
 *  - Nhan tham so dong lenh tu process CHA (qua argv)
 *  - In ra man hinh (STDOUT) mot vai dong, mo phong "dang lam viec"
 *  - Tra ve exit code khac nhau tuy tham so nhan duoc (0 = thanh cong,
 *    1 = loi, dung de kiem tra process CHA co doc dung exit code khong)
 *
 * Build tren Windows (x64), Visual Studio:
 *   cl /Od /std:c11 child.c
 *   => tao ra child.exe, PHAI nam CUNG THU MUC voi parent.exe
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>   /* can cho ham Sleep() */

int main(int argc, char *argv[])
{
    printf("[CHILD] Da khoi dong. PID cua tien trinh nay: %lu\n", GetCurrentProcessId());
    printf("[CHILD] So tham so nhan duoc tu process CHA (khong tinh ten chuong trinh): %d\n",
           argc - 1);

    int failMode = 0;
    for (int i = 1; i < argc; i++) {
        printf("[CHILD]   argv[%d] = \"%s\"\n", i, argv[i]);
        if (strcmp(argv[i], "fail") == 0) {
            failMode = 1;
        }
    }

    printf("[CHILD] Dang gia lap cong viec...\n");
    for (int step = 1; step <= 3; step++) {
        printf("[CHILD] Buoc %d/3 dang xu ly...\n", step);
        fflush(stdout);   /* QUAN TRONG: khi STDOUT bi redirect qua pipe (khong phai console
                              that), du lieu co the bi giu trong buffer thay vi gui ngay.
                              fflush() ep gui ngay lap tuc de process CHA doc duoc kip thoi. */
        Sleep(400);        /* gia lap cong viec ton thoi gian, de CHA co gi do de "cho" */
    }

    if (failMode) {
        printf("[CHILD] Phat hien tham so \"fail\" -> ket thuc voi loi (exit code = 1).\n");
        fflush(stdout);
        return 1;
    }

    printf("[CHILD] Hoan thanh cong viec, thoat binh thuong (exit code = 0).\n");
    fflush(stdout);
    return 0;
}
