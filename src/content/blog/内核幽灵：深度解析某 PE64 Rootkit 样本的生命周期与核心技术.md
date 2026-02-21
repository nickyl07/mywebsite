---
title: 内核幽灵：深度解析某PE64 Rootkit 驱动样本的生命周期与核心技术
description: ''
pubDate: 2024-09-23
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---
## 前言：为什么 Rootkit 与众不同？

在分析样本之前，我们需要理解 Rootkit 与普通病毒（Trojan/Virus）的本质区别。

普通病毒运行在 **Ring 3（用户层）**，受到操作系统的严格监管，杀毒软件可以轻易通过扫描文件或监控行为将其查杀。而 Rootkit（内核后门）则通过加载 `.sys` 驱动程序，直接运行在 **Ring 0（内核层）**。

一旦进入 Ring 0，病毒就拥有了与操作系统内核同等的“上帝权限”。它不仅能直接访问硬件，还能修改操作系统的核心数据结构。此时，**它不再是操作系统里运行的一个程序，它已经成为了操作系统的一部分。**

本文将以一个具体的 PE64 驱动样本为例，以病毒的完整生命周期，剖析其运作机制及技术特性。

## 样本概览

- **File**: 973fe1392e8145daf907fad7b4fbacdc.exe

- **文件类型**: PE64 Driver (Windows 64位驱动程序)

- **架构**: AMD64 2

- **SHA1**: 92416161edf05680f6626184a58a902943c4ef78

- **威胁定性**: Rootkit / 内核后门 / 流量劫持 

## 第一阶段：潜入与扎营 (初始化阶段)

**核心行为：驱动加载与设备通信**

任何驱动程序的生命都始于 `DriverEntry` 入口函数。对于 Rootkit 而言，这一阶段的首要任务是“合法”地驻留下来，并建立与外界（用户层）通信的秘密通道。

### 1. 源码级启动流程复盘 (基于 DriverEntry)

为了更清晰地理解代码执行流，根据逆向出的伪代码整理分析其启动逻辑：

```c++
NTSTATUS __stdcall DriverEntry(_DRIVER_OBJECT *DriverObject, PUNICODE_STRING RegistryPath)
{
  // 1. 设置关机回调：防止系统关闭时蓝屏或用于清理痕迹
  DriverObject->MajorFunction[16] = CompleteIRPAndTriggerExit; // IRP_MJ_SHUTDOWN
  
  // 2. 创建通信基站：创建设备对象和符号链接，作为与应用层通信的桥梁
  if ( MalDeviceInitialization(DriverObject) < 0 ) 
    return -1073741823;

  // 3. 隐身与权限准备：执行 SSDT Hook，并准备注入 lsass.exe 等进程
  CredentialTheft_EntryPoint(); 

  // 4. 启动下载器线程：C2 线程调度器，负责循环下载恶意文件
  PsCreateSystemThread(&ThreadHandle, ..., C2ThreadScheduler, ...);
  ZwClose(ThreadHandle);

  // 5. 准备钓鱼环境：初始化锁首所需的 HTML 资源
  PhishingModule_Entry(); 
  DecodeConfigAndExtractURLs(); // 解密内置的推广链接（如 hao123）

  // 6. 布设监控网：注册回调，监控浏览器进程启动和镜像加载
  PsSetLoadImageNotifyRoutine(MonitorBrowser_LoadImageCallback);
  PsSetCreateProcessNotifyRoutine(FindEPROCESSParentPIDOffset_0, 0);

  // 7. 核心网络劫持：Hook AFD 驱动，从内核底层控制网络流量
  ObReferenceObjectByName_AFD(NetRequestHook); 

  // 8. 文件系统过滤：注册 Minifilter，拦截文件操作
  FltMgrFilter(DriverObject, 1); 

  // 9. 启动对抗线程：专门针对 360 安全卫士的注册表项进行篡改
  PsCreateSystemThread(..., Tamper360SafeRegistryKeyLoop, ...);

  // 10. 启动更新线程：后台检查配置更新
  if ( !g_TrojanUpdateFlag )
  {
    PsCreateSystemThread(..., UpdateThread, ...);
  }
  return v4;
}
```

### 2. 关键步骤详解

#### **A. 建立通信基站 (`MalDeviceInitialization`)**

- **功能**：调用 `IoCreateDevice` 创建设备对象 `\Device\93218ec2da92e0af`。

>   通过创建这个特定名称的设备和符号链接，用户层的恶意程序（通过 `CreateFile`）就能找到这个驱动，并发送控制指令。

##### 建病毒设备对象

![image-20260117160847402](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222357147.png)

###### CreateMalDeviceObject

##### ![image-20260117160910406](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222415849.png)

###### ResetDeviceAndHijackIRPCreate

![image-20260117162826514](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222426896.png)

#### **B. 隐身与注入准备 (`CredentialTheft_EntryPoint`)**

- **功能**：这一步通常包含 **SSDT Hook**（修改系统服务表）和 **进程挂靠准备**（针对 `lsass.exe`）。
- **目的**：为后续的凭据窃取和隐藏自身打下基础。

![image-20260117220434601](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222432900.png)

#### **C. 核心网络劫持 (`ObReferenceObjectByName_AFD`)**

- **技术深度**：这是该样本最核心的技术之一。它没有选择传统的应用层注入来劫持浏览器，而是直接在内核层 Hook 了 **AFD (Ancillary Function Driver for WinSock)**。
- **后果**：AFD 是 Windows Socket 通信的底层驱动。控制了它，就等于控制了所有通过 Winsock 发起的网络请求（包括浏览器访问网页）。这就是为什么它能精准地进行 HTTP 重定向。

![image-20260117223716530](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222435188.png)

![image-20260117223759705](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222438047.png)

## 第二阶段：穿上隐身衣 (隐匿对抗阶段)

**核心技术：SSDT Hook (系统服务描述符表挂钩)**

这是 Rootkit 最标志性的特征。为了防止被杀毒软件发现或清除，它必须修改系统的“规则书”。

### 1.修改内核规则 

样本在 `CredentialTheft_EntryPoint ` 函数中实施了 SSDT Hook。SSDT 是一张表，记录了 Windows 所有系统服务函数的地址。病毒将表中的关键函数地址替换为自己的函数地址。

**主要被劫持的函数：**

1. **`ZwCreateThreadEx` / `NtCreateThreadEx`**:
   - **目的**: 监控系统中的线程创建。病毒可以拦截杀毒软件启动扫描线程，或者辅助自身将恶意代码注入到其他进程。
2. **`ZwProtectVirtualMemory` / `ZwReadVirtualMemory` / `ZwWriteVirtualMemory`**:
   - **目的**: **内存保护**。当安全软件试图扫描病毒所在的内存区域，或者试图修复被篡改的代码时，这些 Hook 函数会拦截请求，返回虚假数据或拒绝访问。

**技术原理**：

> 此时，操作系统已经“撒谎”了。当你打开任务管理器或使用普通工具查看系统状态时，你看到的只是病毒想让你看到的样子。

![image-20260117220700100](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222443342.png)

## 第三阶段：伸出触手 (注入与穿透阶段)

**核心技术：APC 注入与进程挂靠**

虽然身在内核，但病毒往往需要利用用户层的合法程序来执行网络请求（因为内核层网络编程复杂且容易暴露）。

### 1.寄生于系统进程

样本锁定了两个系统关键进程：`smss.exe` (会话管理器) 和 `lsass.exe` (本地安全认证子系统)。

- **技术动作**: 使用 `KeStackAttachProcess`。
- **行为分析**: 这是一个强大的内核 API，允许驱动程序临时“附身”到目标进程的内存空间中。一旦附身成功，病毒就可以以 `smss.exe` 的名义执行操作。

![image-20260117220943257](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222447190.png)

### 2.执行用户层 API

在挂靠状态下，病毒通过 APC (异步过程调用) 或直接寻找函数地址的方式，调用用户层的 `WinExec` 等函数。这实现了从 Ring 0 到 Ring 3 的反向控制，让合法的系统进程替它干坏事。

![image-20260117221048460](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222451482.png)

## 第四阶段：捕猎与收割 (负载执行阶段)

**核心行为：流量劫持、下载器与反杀软**

在确立了隐身地位并打通了控制链路后，病毒开始执行其真正的获利逻辑。这一阶段由之前创建的后台线程并行执行。

### 1.全网通缉：浏览器监控 

病毒调用 `PsSetLoadImageNotifyRoutine` 注册了镜像加载回调。这意味着，系统中任何程序启动，病毒都会第一时间收到通知。

代码中内置了一份详细的**猎杀名单**：

- `IEXPLORE.EXE`
- `CHROME.EXE`
- `QQBROWSER.EXE`
- `360SE.EXE`
- ...以及搜狗、猎豹、Firefox 等。

一旦发现这些浏览器启动，病毒就会立即激活劫持逻辑。

![image-20260117221712129](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222455314.png)

### 2.流量绑架：Minifilter 驱动

样本注册了一个 Minifilter（微过滤驱动）。这是 Windows 文件系统过滤的标准架构。

- **行为**: 它可以拦截浏览器读取配置文件的请求，或者直接篡改网络数据包。

- **后果**: 用户打开浏览器时，会被强制重定向到 `hao123.com`（带推广ID）或其他恶意广告页。

  ![image-20260117221847518](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222458535.png)

### 3.终极对抗：拔掉卫士的牙齿

为了确保存活，病毒有一个专门的线程 (`Tamper360SafeRegistryKeyLoop`) 针对 **360安全卫士**。

- **操作**: 修改注册表 `\Registry\Machine\Software\Wow6432Node\360Safe\safemon`。

- **目的**: 试图禁用 360 的主动防御模块，使其失效。

  ![image-20260117221945596](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222500814.png)

### 4.下载器

另一个后台线程 (`C2ThreadScheduler`) 充当下载器角色。

- 它会循环连接远程服务器（如 `mmm.sbjj888.com`）。
- 下载最新的盗号木马或勒索软件。
- 将文件释放在 `C:\WINDOWS\TEMP\` 下，并用随机文件名伪装运行。

![image-20260117222135282](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222546737.png)

## 总结

这个 Rootkit 样本展示了一个成熟内核病毒的完整闭环：

1. **DriverEntry** 加载，建立 Ring 0 级据点。
2. 利用 **SSDT Hook** 欺骗操作系统，实现隐身。
3. 利用 **KeStackAttachProcess** 穿透隔离，借尸还魂（寄生系统进程）。
3. 利用 **AFD Hook** (NetRequestHook) 从底层劫持网络。
4. 利用 **Minifilter** 和 **NotifyRoutine** 实施精准的流量劫持和推广获利。

这种“高权限、深隐藏”的特性，决定了简单的删除文件无法清除 Rootkit。对抗此类威胁，通常需要使用专业的内核对抗工具（如 PCHunter, XueTr 等）来检测被 Hook 的系统表，并强制摘除恶意的内核钩子。