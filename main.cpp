#include "PEMapper.hpp"

int main(int argc, char const *argv[]) {
    PEMapper::UnicodeInit();

    PEMapper::Mapper::InjectMethod method = PEMapper::Mapper::InjectMethod::HijackThread;
    std::string dllPath;
    std::string processImageFileName;
    DWORD processId = 0;
    bool guiOnly = true;
    bool hideHeader = false;

    if (argc < 3) {
        PEMapper::Log::Error("Invalid arguments.");
        std::cout << std::format("Usage: {} -im <ProcessImageFileName> -dll <DllFilePath>", argv[0]) << '\n';
        std::cout << std::format("Example: {} -im notepad.exe -dll dlltest.dll", argv[0]) << '\n';
        std::cout << std::endl;
        return 1;
    }

    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-im")) {
            processImageFileName = argv[++i];
        } else if (!strcmp(argv[i], "-pid")) {
            processId = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-dll")) {
            dllPath = argv[++i];
        } else if (!strcmp(argv[i], "-apc")) {
            method = PEMapper::Mapper::InjectMethod::QueueAPC;
        } else if (!strcmp(argv[i], "-rth")) {
            method = PEMapper::Mapper::InjectMethod::RemoteThread;
        } else if (!strcmp(argv[i], "-d")) {
            PEMapper::Log::level = PEMapper::Log::Level::Debug;
            PEMapper::Log::Debug("Log level: Debug");
        } else if (!strcmp(argv[i], "-nogui")) {
            guiOnly = false;
            PEMapper::Log::Info("Target process have not GUI, inject all thread.");
        } else if (!strcmp(argv[i], "--hide-header")) {
            hideHeader = true;
        }
    }

    PEMapper::Log::Info(std::format("Inject method: {}", PEMapper::Mapper::InjectMethodToString(method)));

    PEMapper::Loader loader(dllPath);
    if (!loader.isInited()) {
        PEMapper::Log::Error(std::format("Load dll file: {} fail!", dllPath));
        return 1;
    }
    
    PEMapper::Mapper mapper(loader);
    
    if (processId != 0) {
        // 已指定ProcessID优先使用pid
        mapper.injectInto(PEMapper::RemoteProcess(processId), method, guiOnly, hideHeader);
    } else {
        if (dllPath.length() == 0) {
            // 未指定DLL路径
            PEMapper::Log::Error("DLL path not specified!");
            return 1;
        }
        
        // 注入所有名称匹配的进程

        // 创建所有进程快照
        HANDLE hAllProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hAllProcess == INVALID_HANDLE_VALUE) {
            PEMapper::Log::Error("Create process snapshot fail!");
            return 1;
        }
        
        // 转换到UTF16宽字节
        std::wstring imageFileNameW = PEMapper::ToUtf16(processImageFileName);
        imageFileNameW.push_back(0);

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hAllProcess, &pe)) {
            do {
                if (!_wcsicmp(imageFileNameW.c_str(), pe.szExeFile)) {
                    mapper.injectInto(PEMapper::RemoteProcess(pe.th32ProcessID), method, guiOnly, hideHeader);
                }
            } while (Process32NextW(hAllProcess, &pe));
        }
    }
    
    return 0;
}