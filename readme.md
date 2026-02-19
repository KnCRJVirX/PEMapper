# PE Mapper

## 快速开始

```powershell
.\PEMapper.exe -im <ProcessImageFileName> -dll <DllFilePath>
```

例：

```powershell
.\PEMapper.exe -im notepad.exe -dll dlltest.dll
```

## 特性

- 加载目标DLL时，完全手动进行映射，不依赖 `LoadLibrary` ，隐蔽性强

- 默认劫持线程触发 `DllMain` ，无ETW事件

已支持的映像修复：

| 映像修复 | 是否支持 |
|---------|---------|
| 导入表修复 | √ |
| 重定向修复 | √ |
| TLS修复 | × |
| 异常处理（SEH）注册 | × |

## 用法

| 选项 | 说明 |
|-----|------|
| `-im` | 指定目标进程映像名称 |
| `-pid` | 指定目标进程ID（同时指定名称和ID时优先使用ID） |
| `-dll` | 指定DLL文件路径 |
| `-apc` | 使用APC方式触发DllMain |
| `-rth` | 创建远程线程触发DllMain |
| `-d` | 启用调试模式，日志等级调整为 Debug |
