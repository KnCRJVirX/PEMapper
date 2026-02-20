#ifndef PEMAPPER_H
#define PEMAPPER_H

#include <cstdint>
#include <string>
#include <source_location>
#include <iostream>
#include <vector>
#include <format>
#include <map>
#include <algorithm>

#include <Windows.h>
#include <TlHelp32.h>

#include "Utils.h"

namespace PEMapper {

static inline std::string FromUtf16(const std::wstring& utf16Str) {
    LPCWSTR pUtf16Str = (LPCWSTR)utf16Str.c_str();
    int len = WideCharToMultiByte(CP_UTF8, 0, pUtf16Str, -1, nullptr, 0, nullptr, nullptr);
    std::string utf8;
    utf8.resize(len);
    WideCharToMultiByte(CP_UTF8, 0, pUtf16Str, -1, utf8.data(), len, nullptr, nullptr);
    while (utf8.size() && utf8.back() == 0) utf8.pop_back();
    return utf8;
}

static inline std::string FromANSI(const std::string& ansiStr) {
    LPCSTR pAnsiStr = ansiStr.c_str();
    int len = MultiByteToWideChar(CP_ACP, 0, pAnsiStr, ansiStr.length(), nullptr, 0);
    std::wstring utf16;
    utf16.resize(len);
    MultiByteToWideChar(CP_ACP, 0, pAnsiStr, ansiStr.length(), (LPWSTR)utf16.data(), len);
    while (utf16.size() && utf16.back() == 0) utf16.pop_back();
    return FromUtf16(utf16);
}

static inline std::wstring ToUtf16(const std::string& utf8Str) {
    LPCSTR pUtf8Str = utf8Str.c_str();
    int len = MultiByteToWideChar(CP_UTF8, 0, pUtf8Str, utf8Str.length(), nullptr, 0);
    std::wstring utf16;
    utf16.resize(len);
    MultiByteToWideChar(CP_UTF8, 0, pUtf8Str, utf8Str.length(), (LPWSTR)utf16.data(), len);
    while (utf16.size() && utf16.back() == 0) utf16.pop_back();
    return utf16;
}

static inline std::string ToANSI(const std::string& utf8Str) {
    std::wstring utf16Str = ToUtf16(utf8Str);
    LPCWSTR pUtf16Str = utf16Str.c_str();
    int len = WideCharToMultiByte(CP_ACP, 0, pUtf16Str, utf16Str.length(), nullptr, 0, nullptr, nullptr);
    std::string ansi;
    ansi.resize(len);
    WideCharToMultiByte(CP_ACP, 0, pUtf16Str, utf16Str.length(), (LPSTR)ansi.data(), len, nullptr, nullptr);
    while (ansi.size() && ansi.back() == 0) ansi.pop_back();
    return ansi;
}

static inline void UnicodeInit() {
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
}

template <typename T>
static inline T _min(T a, T b) {
    return (a < b) ? a : b;
}

struct Log {
protected:
    static constexpr const char* RED    = "\033[31m";
    static constexpr const char* GREEN  = "\033[32m";
    static constexpr const char* YELLOW = "\033[33m";
    static constexpr const char* BLUE   = "\033[34m";
    static constexpr const char* RESET  = "\033[0m";
public:
    enum class Level {
        Debug, Info, Warning, Error
    };

    static inline Level level = Level::Info;

    static void Error(const std::string_view message, const std::source_location& loc = std::source_location::current()) {
        if (level <= Level::Error) {
            std::cerr << RED    << "[PEMapper][Error]   " << RESET << loc.function_name() << " : " << message << '\n';
        }
    }
    static void Warning(const std::string_view message) {
        if (level <= Level::Warning) {
            std::cout << YELLOW << "[PEMapper][Warning] " << RESET << message << std::endl;
        }
    }
    static void Info(const std::string_view message) {
        if (level <= Level::Info) {
            std::cout           << "[PEMapper][Info]    " << message << std::endl;
        }
    }
    static void Debug(const std::string_view message) {
        if (level <= Level::Debug) {    
            std::cout << BLUE   << "[PEMapper][Debug]   " << RESET << message << std::endl;
        }
    }
    static void Success(const std::string_view message) {
        std::cout << GREEN      << "[PEMapper][Success] " << RESET << message << std::endl;
    }
};

struct CompareStringIgnoreCase {
    bool operator()(const std::string& a, const std::string& b) const {
        size_t n = _min(a.size(), b.size());

        for (size_t i = 0; i < n; ++i) {
            auto ca = std::tolower((unsigned char)a[i]);
            auto cb = std::tolower((unsigned char)b[i]);
            if (ca < cb) return true;
            if (ca > cb) return false;
        }
        return a.size() < b.size();
    }
};
    
class Loader {
protected:
    std::string path;
    HANDLE hFile;
    bool inited = false;

    PIMAGE_DOS_HEADER dosHeader = nullptr;
    PIMAGE_NT_HEADERS ntHeader = nullptr;
    std::vector<IMAGE_SECTION_HEADER> sectionTable;
public:
    Loader(const std::string& filePath): path(filePath) {
        hFile = CreateFileW(ToUtf16(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            inited = true;
        }
    }
    ~Loader() {
        if (inited) {
            CloseHandle(hFile);
            if (dosHeader) delete dosHeader;
            if (ntHeader) delete ntHeader;
        }
        
    }

    template <typename T>
    T* read(T* buffer, size_t bytesToRead, int64_t readPos = -1) {
        if (!inited) {
            return nullptr;
        }

        if (readPos != -1) {
            LARGE_INTEGER off;
            off.QuadPart = readPos;
            SetFilePointerEx(hFile, off, NULL, FILE_BEGIN);
        }
        
        ReadFile(hFile, buffer, bytesToRead, NULL, NULL);
        return buffer;
    }

    PIMAGE_DOS_HEADER getDosHeader() {
        if (!inited) {
            return nullptr;
        }

        if (!dosHeader) {
            dosHeader = new IMAGE_DOS_HEADER;
            read(dosHeader, sizeof(IMAGE_DOS_HEADER), 0);

            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                inited = false;
                Log::Error("Not PE File!");
                return nullptr;
            }
        }
        
        return dosHeader;
    }
    PIMAGE_NT_HEADERS64 getNtHeader() {
        if (!inited) {
            return nullptr;
        }

        if (!ntHeader) {
            PIMAGE_DOS_HEADER pDosHeader = getDosHeader();
            if (!pDosHeader) {
                return nullptr;
            }

            ntHeader = new IMAGE_NT_HEADERS;
            read(ntHeader, sizeof(IMAGE_NT_HEADERS), pDosHeader->e_lfanew);

            if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
                inited = false;
                Log::Error("Not NT PE File!");
            }
            
        }
        
        return ntHeader;
    }
    std::vector<IMAGE_SECTION_HEADER> getSectionTable() {
        if (!inited) {
            return {};
        }

        if (sectionTable.size() == 0) {
            PIMAGE_NT_HEADERS pNtHeader = getNtHeader();
            PIMAGE_DOS_HEADER pDosHeader = getDosHeader();
            if (!pNtHeader) {
                return {};
            }
            
            WORD sectionCount = pNtHeader->FileHeader.NumberOfSections;
            sectionTable.resize(sectionCount);
            // 节表跟在NT Header后
            read(sectionTable.data(), sectionCount * sizeof(IMAGE_SECTION_HEADER), pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
        }
        
        return sectionTable;
    }
    bool isInited() const {
        return inited;
    }
    HANDLE getFileHandle() const {
        if (!inited) {
            return INVALID_HANDLE_VALUE;
        }
        return hFile;
    }
};

class ThreadWindows {
protected:
    DWORD threadId;
    std::vector<HWND> allWindows;
    bool isHasWindow = false;
    
    static BOOL CALLBACK GetAllWndProc(HWND hwnd, LPARAM lParam) {
        ThreadWindows* pThis = (ThreadWindows*)lParam;
        pThis->allWindows.push_back(hwnd);
        pThis->isHasWindow = true;
        return TRUE;
    }
    static BOOL CALLBACK IsThHasWndProc(HWND hwnd, LPARAM lParam) {
        if (hwnd) {
            ThreadWindows* pThis = (ThreadWindows*)lParam;
            pThis->isHasWindow = true;
            return FALSE;
        }
        return TRUE;
    }
public:
    ThreadWindows(DWORD _ThreadId): threadId(_ThreadId) {}
    bool hasWindow() {
        isHasWindow = false;
        EnumThreadWindows(threadId, IsThHasWndProc, (LPARAM)this);
        return isHasWindow;
    }
    std::vector<HWND> all() {
        isHasWindow = false;
        allWindows.clear();
        EnumThreadWindows(threadId, GetAllWndProc, (LPARAM)this);
        return allWindows;
    }
};

class Stub {
public:
    enum class Type {
        ReturnBack,     // 通过CreateRemoteThread执行，执行后返回
        JumpBack,       // 通过劫持上下文执行，执行后跳转回原RIP
        LoadDll,        // 通过劫持上下文执行，调用LoadLibraryW，执行后跳转原Rip
    };
protected:
    std::vector<uint8_t> byteCodes;
    Type stubType;

    // 各占位符在 byteCodes 中的偏移（8字节 imm64 的起始位置）
    size_t offDllMain      = 0;
    size_t offHInstance    = 0;
    size_t offOriginRip    = 0; // JumpBack / LoadDll
    size_t offDllPath      = 0; // 仅 LoadDll：远程进程中宽字符路径的指针
    size_t offLoadLibraryW = 0; // 仅 LoadDll：LoadLibraryW 地址
    size_t offFlag         = 0; // 仅 JumpBack：call-once 标志地址（远程 DWORD*）

    // 往 byteCodes 追加任意字节序列
    void emit(std::initializer_list<uint8_t> bytes) {
        for (auto b : bytes) byteCodes.push_back(b);
    }
    // 追加 8 字节小端 imm64，返回其在 byteCodes 中的偏移
    size_t emitImm64(uint64_t val = 0) {
        size_t off = byteCodes.size();
        for (int i = 0; i < 8; i++)
            byteCodes.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
        return off;
    }
    // 在指定偏移处写入 8 字节 imm64
    void patchImm64(size_t off, uint64_t val) {
        for (int i = 0; i < 8; i++)
            byteCodes[off + i] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
    }
public:
    /*
     * ReturnBack 字节码模板（x86_64）：
     *   sub  rsp, 0x28          ; shadow space + 对齐
     *   ; call-once CAS 门卫
     *   xor  eax, eax           ; expected = 0         (33 C0)
     *   mov  ecx, 1             ; new = 1              (B9 01 00 00 00)
     *   mov  rdx, <flag_addr>   ; 48 BA [8字节]  ← offFlag
     *   lock cmpxchg [rdx], ecx ; 原子 CAS             (F0 0F B1 0A)
     *   jne  skip               ; ZF=0 → 已被抓占，跳过 DllMain (75 1E)
     *   ; DllMain 调用（仅抢到 CAS 的线程执行，共 30 字节）
     *   mov  rcx, <hInstDll>    ; 48 B9 [8字节]
     *   mov  edx, 1             ; BA 01 00 00 00
     *   xor  r8d, r8d           ; 45 33 C0
     *   mov  rax, <dllMain>     ; 48 B8 [8字节]
     *   call rax                ; FF D0
     * skip:
     *   add  rsp, 0x28          ; 48 83 C4 28
     *   ret                     ; C3
     *
     * JumpBack 字节码模板（x86_64，劫持上下文版，含 call-once CAS 门卫）：
     *   push rax/rcx/rdx/r8~r11 ; 保存 7 个易失寄存器（11字节）
     *   push rbp                ; 记录对齐前 RSP 基准
     *   mov  rbp, rsp
     *   and  rsp, -16           ; 强制 16 字节对齐
     *   sub  rsp, 0x20          ; shadow space
     *   ; call-once CAS 门卫
     *   xor  eax, eax           ; expected = 0         (33 C0)
     *   mov  ecx, 1             ; new = 1              (B9 01 00 00 00)
     *   mov  rdx, <flag_addr>   ; 48 BA [8字节]  ← offFlag
     *   lock cmpxchg [rdx], ecx ; 原子 CAS             (F0 0F B1 0A)
     *   jne  skip               ; ZF=0 → 已被抢占，跳过 DllMain (75 1E)
     *   ; DllMain 调用（仅抢到 CAS 的线程执行）
     *   mov  rcx, <hInstDll>    ; 48 B9 [8字节]
     *   mov  edx, 1
     *   xor  r8d, r8d
     *   mov  rax, <dllMain>     ; 48 B8 [8字节]
     *   call rax                ; 共 30 字节，恰好是 jne 的偏移 0x1E
     * skip:
     *   mov  rsp, rbp           ; 恢复对齐前 RSP
     *   pop  rbp
     *   pop  r11/r10/r9/r8/rdx/rcx ; 逆序恢复 6 个寄存器（rax 留在栈上）
     *   mov  rax, <originRip>   ; 48 B8 [8字节]
     *   xchg rax, [rsp]         ; [rsp]=originRip, rax=原始rax（完整恢复）
     *   ret                     ; 弹出 originRip 到 RIP
     *
     * LoadDll 字节码模板（x86_64，劫持上下文版）：
     *   push rax/rcx/rdx/r8~r11 ; 保存 7 个易失寄存器（11字节）
     *   push rbp                ; 记录对齐前 RSP 基准
     *   mov  rbp, rsp
     *   and  rsp, -16           ; 强制 16 字节对齐（劫持点 RSP 不保证对齐）
     *   sub  rsp, 0x20          ; shadow space
     *   mov  rcx, <lpDllPathW>  ; 48 B9 [8字节] — 远程进程中宽字符路径地址
     *   mov  rax, <LoadLibraryW>; 48 B8 [8字节]
     *   call rax
     *   mov  rsp, rbp           ; 恢复对齐前 RSP
     *   pop  rbp
     *   pop  r11/r10/r9/r8/rdx/rcx ; 逆序恢复 6 个寄存器（rax 留在栈上）
     *   mov  rax, <originRip>   ; 48 B8 [8字节]
     *   xchg rax, [rsp]         ; [rsp]=originRip, rax=原始rax（完整恢复）
     *   ret                     ; 弹出 originRip 到 RIP
     */
    Stub(Type type) : stubType(type) {
        if (type == Type::ReturnBack) {
            // sub rsp, 0x28
            emit({0x48, 0x83, 0xEC, 0x28});
            // call-once CAS 门卫
            // xor eax, eax  (expected = 0)
            emit({0x33, 0xC0});
            // mov ecx, 1   (new = 1)
            emit({0xB9, 0x01, 0x00, 0x00, 0x00});
            // mov rdx, <flag_addr>   ; 48 BA [8字节]
            emit({0x48, 0xBA});
            offFlag = emitImm64();
            // lock cmpxchg [rdx], ecx  ; F0 0F B1 0A
            emit({0xF0, 0x0F, 0xB1, 0x0A});
            // jne skip (+0x1E = 30字节，跳过 DllMain 调用块)
            emit({0x75, 0x1E});
            // DllMain 调用块（共 30 字节）
            // mov rcx, <hInstDll>    ; 10字节
            emit({0x48, 0xB9});
            offHInstance = emitImm64();
            // mov edx, 1             ;  5字节
            emit({0xBA, 0x01, 0x00, 0x00, 0x00});
            // xor r8d, r8d           ;  3字节
            emit({0x45, 0x33, 0xC0});
            // mov rax, <dllMain>     ; 10字节
            emit({0x48, 0xB8});
            offDllMain = emitImm64();
            // call rax               ;  2字节
            emit({0xFF, 0xD0});
            // skip: 
            // add rsp, 0x28
            emit({0x48, 0x83, 0xC4, 0x28});
            // ret
            emit({0xC3});
        } else if (type == Type::JumpBack) {
            // 所有线程：保存寄存器 + 对齐
            // push rax, rcx, rdx, r8, r9, r10, r11
            emit({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});
            // push rbp
            emit({0x55});
            // mov rbp, rsp
            emit({0x48, 0x89, 0xE5});
            // and rsp, -16
            emit({0x48, 0x83, 0xE4, 0xF0});
            // sub rsp, 0x20
            emit({0x48, 0x83, 0xEC, 0x20});

            // call-once CAS 门卫
            // xor eax, eax  (expected = 0)
            emit({0x33, 0xC0});
            // mov ecx, 1   (new = 1)
            emit({0xB9, 0x01, 0x00, 0x00, 0x00});
            // mov rdx, <flag_addr>   ; 48 BA [8字节]
            emit({0x48, 0xBA});
            offFlag = emitImm64();
            // lock cmpxchg [rdx], ecx  ; F0 0F B1 0A
            emit({0xF0, 0x0F, 0xB1, 0x0A});
            // jne skip (+0x1E = 30字节，跳过 DllMain 调用块)
            emit({0x75, 0x1E});

            // DllMain 调用块（仅 CAS 胜出的线程执行，共 30 字节）
            // mov rcx, <hInstDll>    ; 10字节
            emit({0x48, 0xB9});
            offHInstance = emitImm64();
            // mov edx, 1             ;  5字节
            emit({0xBA, 0x01, 0x00, 0x00, 0x00});
            // xor r8d, r8d           ;  3字节
            emit({0x45, 0x33, 0xC0});
            // mov rax, <dllMain>     ; 10字节
            emit({0x48, 0xB8});
            offDllMain = emitImm64();
            // call rax               ;  2字节
            emit({0xFF, 0xD0});
            // skip:
            
            // 所有线程：恢复寄存器，跳回原 RIP
            // mov rsp, rbp
            emit({0x48, 0x89, 0xEC});
            // pop rbp
            emit({0x5D});
            // pop r11, r10, r9, r8, rdx, rcx  (逆序，rax 留在栈上)
            emit({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59});
            // mov rax, <originRip>
            emit({0x48, 0xB8});
            offOriginRip = emitImm64();
            // xchg rax, [rsp]  — 将 originRip 写入栈槽，同时将原始 rax 放回 rax
            emit({0x48, 0x87, 0x04, 0x24});
            // ret  — 弹出 originRip 到 RIP，rsp 恢复为劫持前的原始值
            emit({0xC3});
        } else if (type == Type::LoadDll) {
            // push rax, rcx, rdx, r8, r9, r10, r11
            emit({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});
            // push rbp
            emit({0x55});
            // mov rbp, rsp
            emit({0x48, 0x89, 0xE5});
            // and rsp, -16
            emit({0x48, 0x83, 0xE4, 0xF0});
            // sub rsp, 0x20
            emit({0x48, 0x83, 0xEC, 0x20});
            // mov rcx, <lpDllPathW>
            emit({0x48, 0xB9});
            offDllPath = emitImm64();
            // mov rax, <LoadLibraryW>
            emit({0x48, 0xB8});
            offLoadLibraryW = emitImm64(
                reinterpret_cast<uint64_t>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"))
            );
            // call rax
            emit({0xFF, 0xD0});
            // mov rsp, rbp
            emit({0x48, 0x89, 0xEC});
            // pop rbp
            emit({0x5D});
            // pop r11, r10, r9, r8, rdx, rcx  (逆序，rax 留在栈上)
            emit({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59});
            // mov rax, <originRip>
            emit({0x48, 0xB8});
            offOriginRip = emitImm64();
            // xchg rax, [rsp]  — 将 originRip 写入栈槽，同时将原始 rax 放回 rax
            emit({0x48, 0x87, 0x04, 0x24});
            // ret  — 弹出 originRip 到 RIP，rsp 恢复为劫持前的原始值
            emit({0xC3});
        }
    }

    Type getType() const { return stubType; }

    Stub& setDllMain(PVOID dllMainAddress) {
        patchImm64(offDllMain, reinterpret_cast<uint64_t>(dllMainAddress));
        return *this;
    }
    Stub& setOriginRip(uint64_t originRip) {
        if (stubType == Type::JumpBack || stubType == Type::LoadDll)
            patchImm64(offOriginRip, originRip);
        return *this;
    }
    Stub& setHInstance(HINSTANCE hInstDll) {
        patchImm64(offHInstance, reinterpret_cast<uint64_t>(hInstDll));
        return *this;
    }
    Stub& setLpDllPathW(LPCWSTR remoteDllPathW) {
        if (stubType == Type::LoadDll)
            patchImm64(offDllPath, reinterpret_cast<uint64_t>(remoteDllPathW));
        return *this;
    }
    Stub& setFlagAddr(PVOID remoteFlagAddr) {
        if (stubType == Type::JumpBack || stubType == Type::ReturnBack)
            patchImm64(offFlag, reinterpret_cast<uint64_t>(remoteFlagAddr));
        return *this;
    }

    std::vector<uint8_t> toBytes() const {
        return byteCodes;
    }
};

class RemoteProcess {
protected:
    HANDLE hProcess = NULL;
public:
    RemoteProcess(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    RemoteProcess(const RemoteProcess& rhs) {
        DuplicateHandle(GetCurrentProcess(),
                        rhs.hProcess,
                        GetCurrentProcess(),
                        &hProcess,
                        0,
                        FALSE,
                        DUPLICATE_SAME_ACCESS);
    }
    ~RemoteProcess() {
        if (hProcess) {
            CloseHandle(hProcess);
        }
    }

    RemoteProcess& operator=(const RemoteProcess& rhs) {
        if (hProcess) {
            CloseHandle(hProcess);
            hProcess = NULL;
        }
        DuplicateHandle(GetCurrentProcess(),
                        rhs.hProcess,
                        GetCurrentProcess(),
                        &hProcess,
                        0,
                        FALSE,
                        DUPLICATE_SAME_ACCESS);
        return *this;
    }

    HANDLE getHandle() const {
        return hProcess;
    }

    BOOL writeMemory(LPVOID remoteBaseAddress, LPCVOID buffer, SIZE_T bytesToWrite) const {
        return WriteProcessMemory(hProcess, remoteBaseAddress, buffer, bytesToWrite, nullptr);
    }
    BOOL readMemory(LPCVOID remoteBaseAddress, LPVOID buffer, SIZE_T bytesToRead) const {
        return ReadProcessMemory(hProcess, remoteBaseAddress, buffer, bytesToRead, nullptr);
    }
    PVOID alloc(SIZE_T allocSize, DWORD protect = PAGE_READWRITE) const {
        return VirtualAllocEx(hProcess, nullptr, allocSize, MEM_COMMIT, protect);
    }
    BOOL free(PVOID baseAddress, SIZE_T allocSize) const {
        return VirtualFreeEx(hProcess, baseAddress, allocSize, MEM_FREE);
    }
    BOOL setProtect(PVOID baseAddress, SIZE_T setSize, DWORD protect) const {
        DWORD oldProtect = 0;
        // lpflOldProtect 不能为 nullptr，否则 VirtualProtectEx 静默失败
        return VirtualProtectEx(hProcess, baseAddress, setSize, protect, &oldProtect);
    }

    HANDLE createThread(PVOID startAddress, PVOID lpParameter = nullptr) const {
        return CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)startAddress, lpParameter, 0, nullptr);
    }

    BOOL hijackRun(Stub stub, bool guiThreadOnly = false) const {
        DWORD pid = GetProcessId(hProcess);

        // 必须是JumpBack
        if (stub.getType() != Stub::Type::JumpBack) {
            return FALSE;
        }

        // 分配call-once全局标志
        PVOID remoteFlag = alloc(4);
        uint32_t zeroFlag = 0;
        writeMemory(remoteFlag, &zeroFlag, 4);

        // 写入Stub
        stub.setFlagAddr(remoteFlag);
        Log::Debug(std::format("Global call-once flag address: {:#x}", (uint64_t)remoteFlag));

        // 线程快照
        HANDLE hAllThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
        if (hAllThreads == INVALID_HANDLE_VALUE) {
            return FALSE;
        }
        
        // 枚举所有匹配线程，每个都注入 stub
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(hAllThreads, &te)) {
            do {
                if (te.th32OwnerProcessID == pid && (!guiThreadOnly || ThreadWindows(te.th32ThreadID).hasWindow())) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread == NULL) {
                        continue;
                    }

                    // 暂停线程，获取上下文
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_FULL;
                    SuspendThread(hThread);
                    GetThreadContext(hThread, &ctx);

                    // 每个线程有独立的 originRip，但共享同一个 flag_addr
                    std::vector<uint8_t> shellcode = stub.setOriginRip(ctx.Rip).toBytes();

                    // 写入目标进程
                    PVOID remoteShellcode = alloc(shellcode.size(), PAGE_EXECUTE_READWRITE);
                    writeMemory(remoteShellcode, shellcode.data(), shellcode.size());

                    // 设置Rip
                    ctx.Rip = (DWORD64)remoteShellcode;

                    // 写回上下文，继续执行
                    BOOL ret = SetThreadContext(hThread, &ctx);
                    DWORD lastErr = GetLastError();
                    ResumeThread(hThread);
                    CloseHandle(hThread);

                    if (ret) {
                        // 劫持成功
                        Log::Debug(std::format("Hajack thread {} Rip to {:#x}", te.th32ThreadID, ctx.Rip));
                    } else {
                        // 失败
                        Log::Error(std::format("Hiject fail! Last Error: {}", lastErr));
                    }
                }
            } while (Thread32Next(hAllThreads, &te));
        }
        CloseHandle(hAllThreads);
        return TRUE;
    }

    BOOL queueAPCRun(PVOID startAddress, PVOID lpParameter = nullptr, bool guiThreadOnly = false) const {
        // 只注入GUI进程
        DWORD pid = GetProcessId(hProcess);
        // 线程快照
        HANDLE hAllThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
        if (hAllThreads == INVALID_HANDLE_VALUE) {
            return FALSE;
        }
        
        // 枚举
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(hAllThreads, &te)) {
            do {
                if (te.th32OwnerProcessID == pid && (!guiThreadOnly || ThreadWindows(te.th32ThreadID).hasWindow())) {
                    // 只处理目标进程

                    // 注入APC
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread == NULL) {
                        continue;
                    }
                    QueueUserAPC((PAPCFUNC)startAddress, hThread, (ULONG_PTR)lpParameter);
                    CloseHandle(hThread);

                    Log::Debug(std::format("Inject APC into thread {}", te.th32ThreadID));
                }
            } while (Thread32Next(hAllThreads, &te));
        }
        return TRUE;
    }

    BOOL loadDll(const std::string& dllPath) const {
        std::wstring dllPathW = ToUtf16(dllPath);

        // 解析完整路径：
        //   裸文件名（不含路径分隔符） → SearchPathW 在系统/应用路径中查找
        //   含路径分隔符              → GetFullPathNameW 转绝对路径
        std::wstring dllFullPathW(MAX_PATH, L'\0');
        bool hasSep = dllPathW.find(L'\\') != std::wstring::npos
                   || dllPathW.find(L'/')  != std::wstring::npos;
        if (!hasSep) {
            DWORD found = SearchPathW(nullptr, dllPathW.c_str(), nullptr,
                                      MAX_PATH, dllFullPathW.data(), nullptr);
            if (found == 0) {
                // 系统路径中找不到，回退到原名（让远程进程自行搜索）
                dllFullPathW = dllPathW;
            } else {
                dllFullPathW.resize(found);
            }
        } else {
            DWORD len = GetFullPathNameW(dllPathW.c_str(), MAX_PATH,
                                         dllFullPathW.data(), nullptr);
            dllFullPathW.resize(len);
        }
        dllFullPathW.push_back(L'\0');
        Log::Info(std::format("Dll full path: {}", FromUtf16(dllFullPathW)));

        // 写入目标进程
        SIZE_T pathBytes = dllFullPathW.size() * sizeof(wchar_t);
        PVOID remoteDllPath = alloc(pathBytes);
        writeMemory(remoteDllPath, dllFullPathW.c_str(), pathBytes);

        // 在远程进程中调用 LoadLibraryW(remoteDllPath)
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        PVOID pLoadLibraryW = (PVOID)GetProcAddress(hKernel32, "LoadLibraryW");

        // APC方式
        queueAPCRun(pLoadLibraryW, remoteDllPath, false);

        Log::Info(std::format("Normal load dll: {} into {}", dllPath, getID()));
        return TRUE;
    }
    std::vector<MODULEENTRY32W> getLoadedDlls() const {
        std::vector<MODULEENTRY32W> dlls;
        
        HANDLE hAllDlls = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
        if (hAllDlls == INVALID_HANDLE_VALUE) {
            return {};
        }
        
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(hAllDlls, &me)) {
            do {
                dlls.push_back(me);
            } while (Module32NextW(hAllDlls, &me));
        }

        CloseHandle(hAllDlls);
        return dlls;
    }
    MODULEENTRY32W getDllInfo(const std::string& dllName) const {
        // 转UTF16
        std::wstring dllNameW = ToUtf16(dllName);
        dllNameW.push_back(0);

        MODULEENTRY32W result{};
        
        // 快照
        HANDLE hAllDlls = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
        if (hAllDlls == INVALID_HANDLE_VALUE) {
            return {};
        }
        
        // 遍历所有dll
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(hAllDlls, &me)) {
            do {
                if (!_wcsicmp(dllNameW.c_str(), me.szModule)) {
                    result = me;
                    break;
                }
            } while (Module32NextW(hAllDlls, &me));
        }

        CloseHandle(hAllDlls);
        return result;
    }
    PPEB getPebAddress() const {
        PROCESS_BASIC_INFORMATION remoteProcessInfo{};
        ULONG readSize = 0;

        NtQueryInformationProcess(hProcess, ProcessBasicInformation, &remoteProcessInfo, sizeof(remoteProcessInfo), &readSize);
        if (readSize == 0) {
            return nullptr;
        }

        return remoteProcessInfo.PebBaseAddress;
    }
    DWORD getID() const {
        return GetProcessId(hProcess);
    }
};

class RemoteModule {
    RemoteProcess proc;
    BYTE* base = nullptr;   // 远程基址
    std::string name;      // 模块名 (UTF-8)

    // 缓存的导出表信息（首次 getProcAddress 时惰性加载）
    bool    expLoaded = false;
    bool    expValid  = false;
    DWORD   expRVA    = 0;
    DWORD   expSize   = 0;
    DWORD   expBase   = 0;         // IMAGE_EXPORT_DIRECTORY.Base
    std::vector<DWORD> functions;  // AddressOfFunctions
    std::vector<DWORD> names;      // AddressOfNames
    std::vector<WORD>  ordinals;   // AddressOfNameOrdinals

    // 惰性加载导出表
    bool ensureExportTable() {
        if (expLoaded) return expValid;
        expLoaded = true;

        IMAGE_DOS_HEADER dosHeader;
        if (!proc.readMemory(base, &dosHeader, sizeof(dosHeader))
            || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        IMAGE_NT_HEADERS64 ntHeaders;
        if (!proc.readMemory(base + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders))
            || ntHeaders.Signature != IMAGE_NT_SIGNATURE)
            return false;

        auto& dir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0)
            return false;

        expRVA  = dir.VirtualAddress;
        expSize = dir.Size;

        IMAGE_EXPORT_DIRECTORY expDir;
        if (!proc.readMemory(base + expRVA, &expDir, sizeof(expDir)))
            return false;

        DWORD numFuncs = expDir.NumberOfFunctions;
        DWORD numNames = expDir.NumberOfNames;
        expBase = expDir.Base;
        if (numFuncs == 0) return false;

        functions.resize(numFuncs);
        proc.readMemory(base + expDir.AddressOfFunctions,
                         functions.data(), numFuncs * sizeof(DWORD));

        if (numNames) {
            names.resize(numNames);
            ordinals.resize(numNames);
            proc.readMemory(base + expDir.AddressOfNames,
                             names.data(), numNames * sizeof(DWORD));
            proc.readMemory(base + expDir.AddressOfNameOrdinals,
                             ordinals.data(), numNames * sizeof(WORD));
        }

        expValid = true;
        return true;
    }

public:
    RemoteModule(const RemoteProcess& proc, HMODULE hModule, const std::string& name = {})
        : proc(proc)
        , base((BYTE*)hModule)
        , name(name)
    {}

    HMODULE getBase() const { return (HMODULE)base; }
    const std::string& getName() const { return name; }
    explicit operator bool() const { return base != nullptr; }

    // 通过读取远程导出表解析函数地址
    // procName 可以是字符串名称，也可以是 MAKEINTRESOURCEA(ordinal)
    PVOID getProcAddress(LPCSTR procName) {
        if (!ensureExportTable()) return nullptr;

        DWORD funcIndex = (DWORD)-1;

        if (IS_INTRESOURCE(procName)) {
            WORD ordinal = LOWORD((DWORD_PTR)procName);
            funcIndex = ordinal - (WORD)expBase;
        } else {
            for (DWORD i = 0; i < (DWORD)names.size(); i++) {
                char nameBuffer[512]{};
                proc.readMemory(base + names[i],
                                 nameBuffer, sizeof(nameBuffer) - 1);
                if (strcmp(nameBuffer, procName) == 0) {
                    funcIndex = ordinals[i];
                    break;
                }
            }
        }

        if (funcIndex >= (DWORD)functions.size()) return nullptr;

        DWORD funcRVA = functions[funcIndex];

        // 转发导出：RVA 落在导出目录区间内
        if (funcRVA >= expRVA && funcRVA < expRVA + expSize) {
            char fwdStr[256]{};
            proc.readMemory(base + funcRVA, fwdStr, sizeof(fwdStr) - 1);

            char* dot = strchr(fwdStr, '.');
            if (!dot) return nullptr;
            *dot = '\0';
            char* fwdFunc = dot + 1;

            char fwdModuleName[256];
            _snprintf_s(fwdModuleName, sizeof(fwdModuleName), _TRUNCATE, "%s.dll", fwdStr);

            HMODULE hFwd = proc.getDllInfo(fwdModuleName).hModule;
            if (!hFwd) return nullptr;

            RemoteModule fwd(proc, hFwd, std::string(fwdModuleName));
            LPCSTR fwdProcName = (fwdFunc[0] == '#')
                ? MAKEINTRESOURCEA(atoi(fwdFunc + 1))
                : (LPCSTR)fwdFunc;
            return fwd.getProcAddress(fwdProcName);
        }

        return (PVOID)(base + funcRVA);
    }
};

// ApiSet V6 结构定义
struct API_SET_NAMESPACE {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
};
struct API_SET_NAMESPACE_ENTRY {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
};
struct API_SET_HASH_ENTRY {
    ULONG Hash;
    ULONG Index;
};
struct API_SET_VALUE_ENTRY {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
};

class Mapper {
public:
    enum class InjectMethod {
        HijackThread,   // 默认方式，但是对于一些现代GUI程序水土不服
        QueueAPC,       // 适用于GUI程序，但是可能延迟加载
        RemoteThread,   // 创建远程线程，最稳定，但隐蔽性差
    };

    static const char* InjectMethodToString(InjectMethod method) {
        switch (method)
        {
        case InjectMethod::HijackThread: return "Hijack Thread";
        case InjectMethod::QueueAPC:     return "Inject Queue APC";
        case InjectMethod::RemoteThread: return "Remote Thread";
        default:                         return "Unknown";
        }
        return nullptr;
    }
protected:
    Loader& loader;
    PBYTE mapSpace = nullptr;
    bool mapped = false;

    static DWORD sectionToPageProtect(DWORD sectionCharacteristics) {
        DWORD r = sectionCharacteristics & IMAGE_SCN_MEM_READ;
        DWORD w = sectionCharacteristics & IMAGE_SCN_MEM_WRITE;
        DWORD x = sectionCharacteristics & IMAGE_SCN_MEM_EXECUTE;

        if (r && w && x)    return PAGE_EXECUTE_READWRITE;
        if (r && w)         return PAGE_READWRITE;
        if (r && x)         return PAGE_EXECUTE_READ;
        if (r)              return PAGE_READONLY;
        if (w)              return PAGE_READWRITE;
        if (x)              return PAGE_EXECUTE;

        return PAGE_EXECUTE_READWRITE;
    }

    static std::string toRealDllName(const std::string& dllName, const RemoteProcess& proc) {
        // 转宽字符，便于与 ApiSetMap 中的 Unicode 名称比对
        std::wstring nameW = ToUtf16(dllName);

        // 统一转小写
        std::wstring nameLower = nameW;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

        // 去掉 .dll 后缀（用于哈希/比对）
        if (nameLower.ends_with(L".dll")) {
            nameLower = nameLower.substr(0, nameLower.length() - 4);
        }

        // 只处理 api- / ext- 前缀，其余直接返回原名
        if (!nameLower.starts_with(L"api-") && !nameLower.starts_with(L"ext-")) {
            return dllName;
        }

        // 读取远程 PEB::ApiSetMap
        PVOID pebAddr = proc.getPebAddress();
        if (!pebAddr) return dllName;

        PEB_FULL peb{};
        proc.readMemory(pebAddr, &peb, sizeof(peb));

        PVOID apiSetMapAddr = peb.ApiSetMap;
        if (!apiSetMapAddr) return dllName;

        // 先读头部取 Size，再整体读入
        API_SET_NAMESPACE schemaHdr{};
        proc.readMemory(apiSetMapAddr, &schemaHdr, sizeof(schemaHdr));

        if (schemaHdr.Version != 6) {
            // 仅实现 V6（Windows 10+），其他版本回退原名
            return dllName;
        }

        std::vector<BYTE> schemaBuf(schemaHdr.Size);
        proc.readMemory(apiSetMapAddr, schemaBuf.data(), schemaHdr.Size);

        auto* schema         = reinterpret_cast<API_SET_NAMESPACE*>      (schemaBuf.data());
        auto* hashEntries    = reinterpret_cast<API_SET_HASH_ENTRY*>     (schemaBuf.data() + schema->HashOffset);
        auto* nsEntries      = reinterpret_cast<API_SET_NAMESPACE_ENTRY*>(schemaBuf.data() + schema->EntryOffset);

        if (!schema->Count) return dllName;

        // 计算哈希（覆盖范围：最后一个 '-' 之前的部分）
        size_t hyphenIdx = nameLower.rfind(L'-');
        if (hyphenIdx == std::wstring::npos) return dllName;

        std::wstring hashedPart = nameLower.substr(0, hyphenIdx);

        ULONG hash = 0;
        for (wchar_t c : hashedPart) {
            hash = hash * schema->HashFactor + c; // nameLower 已全小写
        }

        // 二分查找哈希表
        LONG minIdx = 0, maxIdx = static_cast<LONG>(schema->Count) - 1;
        API_SET_NAMESPACE_ENTRY* foundEntry = nullptr;

        while (minIdx <= maxIdx) {
            LONG midIdx = (minIdx + maxIdx) / 2;
            API_SET_HASH_ENTRY& he = hashEntries[midIdx];

            if (hash < he.Hash) {
                maxIdx = midIdx - 1;
            } else if (hash > he.Hash) {
                minIdx = midIdx + 1;
            } else {
                // 哈希命中，字符串二次确认（防碰撞）
                API_SET_NAMESPACE_ENTRY& ne = nsEntries[he.Index];
                auto* schemaName = reinterpret_cast<PWCHAR>(schemaBuf.data() + ne.NameOffset);
                std::wstring schemaNameStr(schemaName, ne.HashedLength / sizeof(WCHAR));
                // 转小写再比较
                std::transform(schemaNameStr.begin(), schemaNameStr.end(), schemaNameStr.begin(), ::towlower);

                int cmp = hashedPart.compare(schemaNameStr);
                if (cmp < 0)       maxIdx = midIdx - 1;
                else if (cmp > 0)  minIdx = midIdx + 1;
                else { foundEntry = &ne; break; }
            }
        }

        if (!foundEntry || !foundEntry->ValueCount) return dllName;

        // 取默认宿主（ValueEntry[0]）
        auto* valueEntries = reinterpret_cast<API_SET_VALUE_ENTRY*>(schemaBuf.data() + foundEntry->ValueOffset);

        if (!valueEntries[0].ValueLength) return dllName; // not hosted

        PWCHAR hostNameW = reinterpret_cast<PWCHAR>(schemaBuf.data() + valueEntries[0].ValueOffset);
        std::wstring hostName(hostNameW, valueEntries[0].ValueLength / sizeof(WCHAR));

        return FromUtf16(hostName);
    }
public:
    Mapper(Loader& _loader): loader(_loader) {}
    ~Mapper() {
        if (mapSpace) {
            VirtualFree(mapSpace, loader.getNtHeader()->OptionalHeader.SizeOfImage, MEM_FREE);
        }
    }

    void fixReLocation(PVOID realBase) {
        PIMAGE_NT_HEADERS ntHeader = loader.getNtHeader();
        PIMAGE_BASE_RELOCATION relocTable = (PIMAGE_BASE_RELOCATION)(mapSpace + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        int64_t delta = (int64_t)realBase - ntHeader->OptionalHeader.ImageBase;

        for (PIMAGE_BASE_RELOCATION relocHeader = relocTable; relocHeader->VirtualAddress;) {
            // 下一项位置
            PVOID nextHeader = (PBYTE)relocHeader + relocHeader->SizeOfBlock;
            // 页地址
            uint64_t pageAddr = relocHeader->VirtualAddress;
            
            // 解析重定位项
            WORD* relocElems = (WORD*)((PBYTE)relocHeader + sizeof(IMAGE_BASE_RELOCATION));
            for (size_t i = 0; &relocElems[i] < nextHeader; i++) {
                // 类型
                BYTE type = relocElems[i] >> 12;
                // 页内偏移
                WORD offset = relocElems[i] & 0xFFF;

                // 目标地址
                PVOID targetAddr = mapSpace + pageAddr + offset;

                // 分类处理
                if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    // 跳过
                    continue;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    // 32位
                    int32_t* target = (int32_t*)targetAddr;
                    int32_t newVal = *target + delta;

                    Log::Debug(std::format("Reloc: {:#x} -> {:#x}", *target, newVal));

                    *target = newVal;
                } else if (type == IMAGE_REL_BASED_DIR64) {
                    // 64位
                    int64_t* target = (int64_t*)targetAddr;
                    int64_t newVal = *target + delta;

                    Log::Debug(std::format("Reloc: {:#x} -> {:#x}", *target, newVal));

                    *target = newVal;
                }
            }

            // 下一项
            relocHeader = (PIMAGE_BASE_RELOCATION)nextHeader;
        }
        
    }

    void fixImport(const RemoteProcess& proc) {
        PIMAGE_NT_HEADERS ntHeader = loader.getNtHeader();
        PIMAGE_IMPORT_DESCRIPTOR importTable = (PIMAGE_IMPORT_DESCRIPTOR)(mapSpace + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        // 记录已加载过的dll
        std::map<std::string, MODULEENTRY32W, CompareStringIgnoreCase> loadedDll;
        std::vector<MODULEENTRY32W> loadedModules = proc.getLoadedDlls();
        for (MODULEENTRY32W& me: loadedModules) {
            std::string dllName = FromUtf16(me.szModule);
            loadedDll[dllName] = me;
        }

        for (; importTable->Name; importTable++) {
            // 获取DLL名称
            std::string dllName = (const char*)(mapSpace + importTable->Name);

            // 解析到实际DLL名称
            std::string originDllName = dllName;
            dllName = toRealDllName(dllName, proc);
            Log::Debug(std::format("Dll name: {} -> {}", originDllName, dllName));

            // 如果未加载该dll，则加载
            if (loadedDll.find(dllName) == loadedDll.end()) {
                Log::Warning(std::format("Module {} not loaded, try load", dllName));
                proc.loadDll(dllName);
                MODULEENTRY32W me = proc.getDllInfo(dllName);
                loadedDll[dllName] = me;
                Log::Success(std::format("Remote load {} success, base address: {:#x}", dllName, (uint64_t)me.hModule));
            }

            // 远程dll地址
            HMODULE hRemoteModule = loadedDll[dllName].hModule;
            Log::Debug(std::format("Remote module: {}, base address: {:#x}", dllName, (uint64_t)hRemoteModule));

            // 构建 RemoteModule，缓存导出表供本DLL所有导入项复用
            RemoteModule remoteModule(proc, hRemoteModule, dllName);

            // 获取INT(Import Name Table)和IAT(Import Address Table)
            PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)(mapSpace + importTable->OriginalFirstThunk);
            PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(mapSpace + importTable->FirstThunk);

            // 如果OriginalFirstThunk为0，回退到FirstThunk
            if (!importTable->OriginalFirstThunk) {
                originalThunk = firstThunk;
            }

            for (; originalThunk->u1.AddressOfData; originalThunk++, firstThunk++) {
                PVOID funcAddr = nullptr;

                if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal)) {
                    // 按序号导入
                    WORD ordinal = IMAGE_ORDINAL(originalThunk->u1.Ordinal);
                    funcAddr = remoteModule.getProcAddress(MAKEINTRESOURCEA(ordinal));

                    Log::Debug(std::format("Import: {} -> {:#x}", ordinal, (uint64_t)funcAddr));
                } else {
                    // 按名称导入
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(mapSpace + originalThunk->u1.AddressOfData);
                    funcAddr = remoteModule.getProcAddress(importByName->Name);

                    Log::Debug(std::format("Import: {} -> {:#x}", importByName->Name, (uint64_t)funcAddr));
                }

                if (!funcAddr) {
                    Log::Error(std::format("Failed to resolve import from {}", dllName));
                    continue;
                }

                // 写入IAT
                firstThunk->u1.Function = (ULONGLONG)funcAddr;
            }

            Log::Debug(std::format("Fixed imports for: {}", dllName));
        }
    }
    
    void buildMemoryImage() {        
        PIMAGE_NT_HEADERS ntHeader = loader.getNtHeader();
        if (!ntHeader) {
            return;
        }
        
        // 分配空间
        mapSpace = (PBYTE)VirtualAlloc(nullptr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
        
        // 映射头
        loader.read(mapSpace, ntHeader->OptionalHeader.SizeOfHeaders, 0);

        // 展开节
        std::vector<IMAGE_SECTION_HEADER> sectionTable = loader.getSectionTable();
        for (auto& section: sectionTable) {
            // 目标地址
            void* dst = mapSpace + section.VirtualAddress;

            // 复制大小
            size_t numberOfBytes = _min(section.SizeOfRawData, section.Misc.VirtualSize);
            
            // 读取到内存
            loader.read(dst, numberOfBytes, section.PointerToRawData);

            Log::Debug(std::format("Copied section: Name: {}, RVA: {:#x}, Size: {}", (char*)section.Name, section.VirtualAddress, numberOfBytes));
        }

        mapped = true;
    }

    BOOL injectInto(const RemoteProcess& process, InjectMethod method = InjectMethod::HijackThread, bool guiOnly = true) {
        if (!mapped) {
            buildMemoryImage();
        }
        
        PIMAGE_NT_HEADERS ntHeader = loader.getNtHeader();
        
        // 分配远程映像内存
        PBYTE remoteImageBase = (PBYTE)process.alloc(ntHeader->OptionalHeader.SizeOfImage, PAGE_READWRITE);
        Log::Info(std::format("Remote image base: {:#x}", (uint64_t)remoteImageBase));

        // 修复导入表
        fixImport(process);

        // 修复重定位
        fixReLocation(remoteImageBase);

        // 复制完整镜像
        process.writeMemory(remoteImageBase, mapSpace, ntHeader->OptionalHeader.SizeOfImage);
        Log::Info(std::format("Write image into remote process[{:#x}]", (uint64_t)remoteImageBase));

        // 设置节保护
        std::vector<IMAGE_SECTION_HEADER> sectionTable = loader.getSectionTable();
        for (auto& section: sectionTable) {
            // 内存基址
            PBYTE target = remoteImageBase + section.VirtualAddress;
            // 掩码
            DWORD protect = sectionToPageProtect(section.Characteristics);
            
            // 设置Protect
            process.setProtect(target, section.Misc.VirtualSize, protect);
        }

        // 入口点
        PVOID dllMain = remoteImageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
        Log::Info(std::format("Entry point: {:#x}", (uint64_t)dllMain));

        // 运行DllMain
        if (method == InjectMethod::HijackThread) {
            // 劫持线程上下文方式
            // 构造Stub
            Stub stub = Stub(Stub::Type::JumpBack).setHInstance((HINSTANCE)remoteImageBase)
                                                  .setDllMain(dllMain);

            // 劫持执行
            process.hijackRun(stub, guiOnly);
        } else if (method == InjectMethod::QueueAPC) {
            // APC方式
            // 分配全局Call once flag
            PVOID remoteFlag = process.alloc(sizeof(DWORD));
            uint32_t zero = 0;
            process.writeMemory(remoteFlag, &zero, sizeof(zero));

            // 构造Stub
            std::vector<uint8_t> stub = Stub(Stub::Type::ReturnBack).setDllMain(dllMain)
                                                                    .setHInstance((HINSTANCE)remoteImageBase)
                                                                    .setFlagAddr(remoteFlag)
                                                                    .toBytes();
                                                                
            // 写入Stub Shellcode
            PVOID remoteStub = process.alloc(stub.size(), PAGE_EXECUTE_READWRITE);
            process.writeMemory(remoteStub, stub.data(), stub.size());
            
            // 注入APC
            process.queueAPCRun(remoteStub, nullptr, guiOnly);
        } else if (method == InjectMethod::RemoteThread) {
            // 远程线程方式
            // 分配全局Call once flag
            PVOID remoteFlag = process.alloc(sizeof(DWORD));
            uint32_t zero = 0;
            process.writeMemory(remoteFlag, &zero, sizeof(zero));

            // 构造Stub
            std::vector<uint8_t> stub = Stub(Stub::Type::ReturnBack).setDllMain(dllMain)
                                                                    .setHInstance((HINSTANCE)remoteImageBase)
                                                                    .setFlagAddr(remoteFlag)
                                                                    .toBytes();
                                                                
            // 写入Stub Shellcode
            PVOID remoteStub = process.alloc(stub.size(), PAGE_EXECUTE_READWRITE);
            process.writeMemory(remoteStub, stub.data(), stub.size());

            // 创建远程线程并等待
            HANDLE hThread = process.createThread(remoteStub);
            Log::Info(std::format("Remote thread: {}", GetThreadId(hThread)));
            WaitForSingleObject(hThread, INFINITE);

            // 清理
            process.free(remoteStub, stub.size());
        } else {
            return FALSE;
        }

        Log::Success(std::format("Inject into Process ID: {}", process.getID()));
        
        mapped = false;
        return TRUE;
    }
};

void QuickInject(DWORD processId, const std::string& dllPath) {
    Loader ld(dllPath);
    Mapper(ld).injectInto(RemoteProcess(processId));
}

void QuickInject(const std::string& processImageFileName, const std::string& dllPath) {
    HANDLE hAllProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hAllProcess == INVALID_HANDLE_VALUE) {
        return;
    }
    
    // 转换到UTF16宽字节
    std::wstring imageFileNameW = ToUtf16(processImageFileName);
    imageFileNameW.push_back(0);

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hAllProcess, &pe)) {
        do {
            if (!_wcsicmp(imageFileNameW.c_str(), pe.szExeFile)) {
                QuickInject(pe.th32ProcessID, dllPath);
            }
        } while (Process32NextW(hAllProcess, &pe));
    }
}

} // namespace PEMapper

#endif