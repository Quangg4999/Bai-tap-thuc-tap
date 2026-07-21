#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE
#undef _UNICODE
/*
 * Bai 3.1 - Registry Editor CLI
 * -------------------------------------------------------------------
 * Cong cu them/sua/xoa key va value trong Windows Registry.
 * Dung API: RegOpenKeyExA, RegCreateKeyExA, RegSetValueExA,
 *           RegDeleteValueA, RegDeleteKeyA, RegEnumValueA (liet ke).
 *
 * AN TOAN: chuong trinh CO DINH lam viec trong vung:
 *   HKEY_CURRENT_USER\Software\MyTestApp
 * Day la vung an toan, chi anh huong tai khoan hien tai, khong dung
 * cham toi HKEY_LOCAL_MACHINE hay bat ky vung he thong nao.
 *
 * Build tren Windows (x64), Visual Studio:
 *   cl /Od /std:c11 registry_editor.c
 *   (Advapi32.lib thuong da duoc link san mac dinh tren MSVC)
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define BASE_ROOT   HKEY_CURRENT_USER
#define BASE_SUBKEY "Software\\MyTestApp"

void InFormLoi(const char *hanhDong, LONG errCode)
{
    fprintf(stderr, "Loi: %s (ma loi: %ld)\n", hanhDong, errCode);
}

/* ==================================================================
 * Mo (hoac tao moi neu chua co) key trong vung an toan
 * ================================================================== */
HKEY OpenOrCreateBaseKey(void)
{
    HKEY hKey;
    LONG result;

    /* Thu MO key truoc bang RegOpenKeyExA (dung theo yeu cau de bai) */
    result = RegOpenKeyExA(BASE_ROOT, BASE_SUBKEY, 0, KEY_ALL_ACCESS, &hKey);

    if (result == ERROR_SUCCESS) {
        return hKey;   /* key da ton tai, mo thanh cong */
    }

    if (result == ERROR_FILE_NOT_FOUND) {
        /* Key chua ton tai -> tao moi bang RegCreateKeyExA */
        DWORD disposition;
        result = RegCreateKeyExA(BASE_ROOT, BASE_SUBKEY, 0, NULL,
                                   REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                                   NULL, &hKey, &disposition);
        if (result == ERROR_SUCCESS) {
            printf("[INFO] Key '%s' chua ton tai, da TU DONG TAO MOI.\n", BASE_SUBKEY);
            return hKey;
        }
    }

    InFormLoi("khong mo/tao duoc key goc", result);
    return NULL;
}

/* ==================================================================
 * Them / sua 1 value kieu chuoi (REG_SZ)
 * ================================================================== */
void SetStringValue(HKEY hKey, const char *valueName, const char *data)
{
    LONG result = RegSetValueExA(hKey, valueName, 0, REG_SZ,
                                   (const BYTE *)data, (DWORD)(strlen(data) + 1));
    if (result == ERROR_SUCCESS) {
        printf("[OK] Da ghi value '%s' = \"%s\" (REG_SZ)\n", valueName, data);
    } else {
        InFormLoi("khong ghi duoc value chuoi", result);
    }
}

/* ==================================================================
 * Them / sua 1 value kieu so nguyen (REG_DWORD)
 * ================================================================== */
void SetDwordValue(HKEY hKey, const char *valueName, DWORD data)
{
    LONG result = RegSetValueExA(hKey, valueName, 0, REG_DWORD,
                                   (const BYTE *)&data, sizeof(DWORD));
    if (result == ERROR_SUCCESS) {
        printf("[OK] Da ghi value '%s' = %lu (REG_DWORD)\n", valueName, data);
    } else {
        InFormLoi("khong ghi duoc value so nguyen", result);
    }
}

/* ==================================================================
 * Xoa 1 value theo ten
 * ================================================================== */
void DeleteValueByName(HKEY hKey, const char *valueName)
{
    LONG result = RegDeleteValueA(hKey, valueName);
    if (result == ERROR_SUCCESS) {
        printf("[OK] Da XOA value '%s'\n", valueName);
    } else if (result == ERROR_FILE_NOT_FOUND) {
        printf("[CANH BAO] Value '%s' khong ton tai, khong co gi de xoa.\n", valueName);
    } else {
        InFormLoi("khong xoa duoc value", result);
    }
}

/* ==================================================================
 * Liet ke toan bo value hien co trong key (de nguoi dung xem truoc/sau)
 * ================================================================== */
void ListAllValues(HKEY hKey)
{
    char valueName[256];
    BYTE data[1024];
    DWORD index = 0;

    printf("\n--- Danh sach value hien co trong '%s' ---\n", BASE_SUBKEY);

    for (;;) {
        DWORD nameSize = sizeof(valueName);
        DWORD dataSize = sizeof(data);
        DWORD type;

        LONG result = RegEnumValueA(hKey, index, valueName, &nameSize,
                                      NULL, &type, data, &dataSize);

        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) {
            InFormLoi("loi khi liet ke value", result);
            break;
        }

        if (type == REG_SZ) {
            printf("  [%lu] %-20s REG_SZ     = \"%s\"\n", index, valueName, (char *)data);
        } else if (type == REG_DWORD) {
            DWORD val;
            memcpy(&val, data, sizeof(DWORD));
            printf("  [%lu] %-20s REG_DWORD  = %lu\n", index, valueName, val);
        } else {
            printf("  [%lu] %-20s (kieu khac, type=%lu)\n", index, valueName, type);
        }

        index++;
    }

    if (index == 0) {
        printf("  (rong - chua co value nao)\n");
    }
    printf("--------------------------------------------------\n\n");
}

/* ==================================================================
 * Xoa toan bo key goc (chi xoa duoc khi key RONG, khong co value/subkey con)
 * ================================================================== */
void DeleteBaseKey(void)
{
    LONG result = RegDeleteKeyA(HKEY_CURRENT_USER, BASE_SUBKEY);
    if (result == ERROR_SUCCESS) {
        printf("[OK] Da XOA hoan toan key '%s'.\n", BASE_SUBKEY);
    } else {
        InFormLoi("khong xoa duoc key (co the do key khong rong)", result);
        printf("     Goi y: hay xoa het value ben trong truoc (chuc nang 3).\n");
    }
}

/* ==================================================================
 * MAIN - menu dieu khien
 * ================================================================== */
int main(void)
{
    printf("========== REGISTRY EDITOR CLI ==========\n");
    printf("Vung lam viec CO DINH (an toan): HKEY_CURRENT_USER\\%s\n\n", BASE_SUBKEY);

    HKEY hKey = OpenOrCreateBaseKey();
    if (hKey == NULL) {
        printf("Khong the tiep tuc, thoat chuong trinh.\n");
        return 1;
    }

    int running = 1;
    while (running) {
        printf("1. Them/Sua value kieu CHUOI (REG_SZ)\n");
        printf("2. Them/Sua value kieu SO NGUYEN (REG_DWORD)\n");
        printf("3. Xoa 1 value theo ten\n");
        printf("4. Liet ke toan bo value hien co\n");
        printf("5. Xoa toan bo key (chi khi key da rong)\n");
        printf("0. Thoat\n");
        printf("Chon: ");

        int choice;
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }
        while (getchar() != '\n');   /* don ky tu xuong dong con sot lai */

        printf("\n");
        char nameBuf[256], dataBuf[512];

        switch (choice) {
            case 1:
                printf("Nhap ten value: ");
                fgets(nameBuf, sizeof(nameBuf), stdin);
                nameBuf[strcspn(nameBuf, "\n")] = '\0';
                printf("Nhap noi dung chuoi: ");
                fgets(dataBuf, sizeof(dataBuf), stdin);
                dataBuf[strcspn(dataBuf, "\n")] = '\0';
                SetStringValue(hKey, nameBuf, dataBuf);
                break;

            case 2: {
                printf("Nhap ten value: ");
                fgets(nameBuf, sizeof(nameBuf), stdin);
                nameBuf[strcspn(nameBuf, "\n")] = '\0';
                printf("Nhap gia tri so nguyen: ");
                DWORD val;
                scanf("%lu", &val);
                while (getchar() != '\n');
                SetDwordValue(hKey, nameBuf, val);
                break;
            }

            case 3:
                printf("Nhap ten value can xoa: ");
                fgets(nameBuf, sizeof(nameBuf), stdin);
                nameBuf[strcspn(nameBuf, "\n")] = '\0';
                DeleteValueByName(hKey, nameBuf);
                break;

            case 4:
                ListAllValues(hKey);
                break;

            case 5:
                RegCloseKey(hKey);
                DeleteBaseKey();
                hKey = OpenOrCreateBaseKey();   /* tao lai rong de tiep tuc dung menu */
                break;

            case 0:
                running = 0;
                break;

            default:
                printf("Lua chon khong hop le.\n");
        }
        printf("\n");
    }

    RegCloseKey(hKey);
    printf("Da dong key, ket thuc chuong trinh.\n");
    return 0;
}
