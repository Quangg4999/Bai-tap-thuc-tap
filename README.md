# Bài tập thực tập

Repo lưu bài tập thực tập về **lập trình hệ thống trên Windows** bằng C/C++.

Nội dung đi từ nền tảng C/C++ (bố cục bộ nhớ, thao tác con trỏ, file nhị phân) đến Windows API (tiến trình, luồng, Registry, Service) và kết thúc bằng việc phân tích cấu trúc file PE.

## Cấu trúc thư mục

```
Bai-tap-thuc-tap/
├── 1.1/            Memory Layout Explorer
├── 1.2/            Unsafe vs Safe Copy
├── 1.3/            Binary File Parser
├── 2.1/            Process Explorer mini
├── 2.2/            Thread Monitor
├── 2.3/            Create Process & Inject Parameter
├── 3.1/            Registry Editor CLI
├── 3.2/            Service Controller
├── 4.1/            PE File Parser
├── .gitignore
└── README.md
```

## Nội dung các phần

### A — C/C++ Core

| Thư mục | Bài tập | Mô tả ngắn |
|---|---|---|
| `1.1` | Memory Layout Explorer | In địa chỉ (hex) của biến local, static, global và vùng cấp phát động; so sánh khoảng cách giữa các vùng nhớ. Build x64, không dùng STL. |
| `1.2` | Unsafe vs Safe Copy | Cài đặt `UnsafeCopy` và `SafeCopy`, demo buffer overflow và quan sát vùng nhớ bị ghi đè bằng Debugger của Visual Studio. |
| `1.3` | Binary File Parser | Định nghĩa struct `FILE_HDR`, ghi ra file nhị phân, đọc lại và kiểm tra chữ ký `magic`. |

### B — Process & Thread

| Thư mục | Bài tập | Mô tả ngắn |
|---|---|---|
| `2.1` | Process Explorer mini | Liệt kê tiến trình bằng `CreateToolhelp32Snapshot` / `Process32First-Next`: PID, tên, đường dẫn, RAM. Hỗ trợ lọc theo tên và kết thúc tiến trình. |
| `2.2` | Thread Monitor | Liệt kê thread của một tiến trình bằng `Thread32First-Next`: TID, trạng thái, mức sử dụng CPU. |
| `2.3` | Create Process & Inject Parameter | Tạo tiến trình con bằng `CreateProcessW`, truyền tham số từ cha sang con, ghi log thời gian chạy và exit code, redirect STDOUT. |

### C — Registry & Service

| Thư mục | Bài tập | Mô tả ngắn |
|---|---|---|
| `3.1` | Registry Editor CLI | Công cụ dòng lệnh thêm/sửa/xóa key và value trong Registry (`RegOpenKeyEx`, `RegSetValueEx`, `RegDeleteValue`). |
| `3.2` | Service Controller | Liệt kê Windows Services (`OpenSCManager`, `EnumServicesStatusEx`), start/stop service. Mở rộng: tự tạo service ghi log RAM/CPU/Disk mỗi phút, tự khởi động lại khi bị kill, xoay vòng log theo dung lượng và thời gian. |

### D — PE Format

| Thư mục | Bài tập | Mô tả ngắn |
|---|---|---|
| `4.1` | PE File Parser | Phân tích file PE và hiển thị DOS Header, NT Header, File Header, Optional Header (kèm Data Directories), Section Headers, cùng các bảng Export, Import, Resource và Relocation. |

## Môi trường

- Windows 10/11, kiến trúc **x64**
- Visual Studio (MSVC), C/C++
- Windows SDK — Win32 API

Một số bài (thao tác Registry, điều khiển Service, kết thúc tiến trình) cần chạy với quyền **Administrator**.

## Cách build

Mở solution/project trong thư mục tương ứng bằng Visual Studio, chọn cấu hình `Debug | x64`, rồi build và chạy.
