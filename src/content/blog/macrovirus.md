---
title: 宏病毒深度剖析：从原理到对抗技术全解析
description: '' 
pubDate: 2025-02-23
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---
# 科普篇

## 什么是“宏”？

从本质上讲，宏是一组**提前教给电脑的指令集**。它的工作原理可以概括为：

- **录制/编写：** 把一连串复杂的动作记下来。
- **一键触发：** 赋予它一个简单的指令或快捷键。
- **自动执行：** 电脑像执行脚本一样，自动干完这一连串的活儿。

Microsoft Word中对宏定义为：

> **“宏就是能组织到一起、作为一个独立的命令使用的一系列命令。它能使日常工作变得更容易。”**

## “宏病毒”又是什么？

宏病毒是一种利用软件（如 Word、Excel、PPT 等）中的**宏编程语言**（通常是 VBA）编写的恶意程序。

宏病毒通常伪装成一个看似正常的文档。只有当你打开这个文档并**点击“启用宏”**时，病毒就会被激活。

## “宏病毒”藏在哪？

普通的文本文件（如 `.txt`）是一串连续的数据流，而传统的 Office 文档（`.doc`, `.xls`, `.ppt`）其实是一个虚拟的磁盘空间。它在单个文件内部模拟了类似硬盘的存储方式，这就是为什么它被称为“复合文档”。

一个 .doc 文件中，文本内容通常存在 \Root Entry\WordDocument 这个 Stream 里；而如果文档里有宏，它们会被整齐地放在 \Root Entry\Macros\ 这个 Storage 下。

复合文档结构主要针对的是老旧格式，新旧格式有着本质的区别：

二进制复合文档 (.doc, .xls, .ppt)：

- OLE 架构。它是二进制格式，结构复杂，必须用专门的工具（如 SSView）才能看到内部的 Stream。
- 安全性：宏直接嵌入在二进制流中，隐蔽性强。

现代 XML 格式 (.docx, .xlsx, .pptx, .docm)：

- 压缩包架构。它们本质上是 ZIP 压缩包。
- 如果你把 .docx 后缀改成 .zip 并解压，你会看到里面是一堆 .xml 文件和文件夹。
- 注意：.docx 默认不允许包含宏，只有 .docm 才是支持宏的压缩格式。.docx (XML)本质上不运行宏，而 .docm才是现代 Office 的带毒载体 。

# 防御篇

## 如何查看宏代码

现在通常文档中的宏是被默认禁用的，选择“启用内容”后，宏才会执行。

![image-20240728185305988](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144953.png)

查看宏代码：

在选项中勾选开发工具

![image-20240728185456720](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144954.png)

选择Visual Basic，即可打开VB编辑器，查看宏代码。或者使用快捷键“Alt+F11”打开。

![image-20240728185522358](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144955.png)

执行恶意功能的宏就是宏病毒，使用VBA编写。宏病毒只在Microsoft Office办公软件创建的电子文档中感染。

# 分析篇

## 静态分析



#### 基本信息

File:demo2.doc

sha1:9abeef3ed793f28a24562c3e5c3104eee99daa1c

![image-20240728234520091](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144958.png)

查看VBA，宏被加密了，提示需要密码

![image-20240728234740973](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144959.png)

##### 使用工具VBA Password Bypasser解密

![202407291829125](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144960.png)

##### 使用oledump分析流

oledump.py  demo2.doc

[^]: 用python2跑

![202407291828146](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144961.png)

列出此文件的Stream数据，标记字母‘M’的一行，表示这段数据中存在宏。

oledump.py -s  段号：选择分析出的某一段来查看内容

oledump.py -v：解压缩VBA宏

两个参数结合：oledump.py -s A3 -v demo2.doc

![202407291831475](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144962.png)

参数选择‘a’，表示分析所有段的数据，使用‘>’，宏代码数据将存储在新文件中

oledump.py -s a -v demo2.doc>1.txt

decoder_ay.py -d：将文件中的exe数据dump下来

oledump.py -s 14  -D decoder_ay.py -d 1.doc  >1.exe

## 动态分析

#### 基本信息

File:bab93bc258ed673a849e8a8a6da080cf82e3dab3fdb29f6ae42031280cda49ef

md5:71c7d149cec1d8a3a7e54711b3b64383

![202408051833344](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144963.png)

##### 使用动态调试的方法

点击视图开启立即窗口、本地窗口和监视窗口
![image-20240806010204071](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144964.png)
Set nZsXAIAmrwsMOxkvh = gxUVYeacLIkNroPKoYAd.CreateTextFile(oCHIUZS, True, True)，创建文件，通过设置断点，通过观察本地窗口变量的值可知创建了文件"C:\Users\Adif\Downloads\deer.ini"
![image-20240806010556053](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144965.png)
接着是大量的字符串拼接，后面应该会进行解密写文件操作
![image-20240806010637075](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144966.png)
UNMfYyPswUtPDcyphmZwEXyU先对字符串进行了base64的解密，再写入到了“C:\Users\Adif\Downloads\deer.ini”文件中
![image-20240806232428643](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144967.png)
执行生成的vba脚本

```
Set VWjEFsxZ = CreateObject("Shell.Application")
CallByName VWjEFsxZ, "ShellExecute", VbMethod, "wscript.exe", "C:\Users\Adif\Downloads\deer.ini //e:VBScript //b", "", "", 0
```

最后写注册表，实现自启
![image-20240806011024885](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144968.png)
**deer.ini分析**
新建一个word，启动visualBasic编辑器，并将beer.ini的内容复制进去。同样使用动态调试来分析。
创建"C:\Users\Adif\deer.exe"，写注册表

```
HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Security\AccessVBOM为1 HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Security\VBAWarnings
```

使用WMI测试是否能ping通coagula.online

```
"SELECT * FROM Win32_PingStatus WHERE Address=" + "'coagula.online'"
```

可以使用debug.print调试输出url，得到一个url
![图片描述](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144969.png)

# 技术篇

## 宏病毒的恶意利用手段

宏病毒的恶意利用手段主要体现在对Windows API和外部例程的调用。

| 外部例程             | 介绍                                                         |
| -------------------- | ------------------------------------------------------------ |
| MSXML2.ServerXMLHTTP | Xmlhttp是一种浏览器对象， 可用于模拟http的GET和POST请求      |
| Net.WebClient        | 提供网络服务                                                 |
| Adodb.Stream         | Stream 流对象用于表示数据流。配合XMLHTTP服务使用Stream对象可以从网站上下载各种可执行程序 |
| Wscript.shell        | WScript.Shell是WshShell对象的ProgID，创建WshShell对象可以运行程序、操作注册表、创建快捷方式、访问系统文件夹、管理环境变量。 |
| Poweshell            | PowerShell.exe 是微软提供的一种命令行shell程序和脚本环境     |
| Application.Run      | 调用该函数，可以运行.exe文件                                 |
| WMI                  | 用户可以利用 WMI 管理计算机，在宏病毒中主要通过winmgmts:\\.\root\CIMV2隐藏启动进程 |
| Shell.Application    | 能够执行sehll命令                                            |

### 远程模板注入执行宏

本地文件中没有宏，利用文档模板尝试执行远程文件中宏。

File: APT28.DOCX
      SHA1: 8fb0124def0e5a7a12495ede2a20a9c48a7929a6

文档被设计为通过内嵌在DOCX文档中的settings.xml.rels组件来从hxxp://109.248.148.42/office/thememl/2012/main/attachedTemplate.dotm加载恶意启用宏的内容

![202408011404136](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144970.png)

参考：[APT28新动向：利用英国脱欧主题钓鱼邮件传播Zekapab恶意软件 ](https://www.secrss.com/articles/7061)



### 窃取NTLM Hashes

NTLM Hashes通常是指Windows系统下Security Account Manager中保存的用户密码hash。

此技术利用DOCX文档中的webSetings.xml.rels文件，且只有在Office2010及之后版本才能利用成功。

恶意构造的docx打开时会访问远程资源，访问远程资源使用NTLM协议进行身份验证，从而泄露NTLM Hashes信息。

![webSettings XML Relationship File - Contents](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144971.png)

参考：[pentestlab](https://pentestlab.blog/2017/12/18/microsoft-office-ntlm-hashes-via-frameset/)

### VBA stomping

VBA在Office文档中可以以下面三种形似存在

1、源代码。宏模块的原始源代码被压缩，并存储在模块流的末尾，可以使用'Attribut'字符串识别。

2、P-Code。P-code，即Pseudo Code（伪代码），是vba宏代码被vba编辑器编译之后的代码。平常Alt+F11打开所看到的正是反编译的P-Code。

3、ExeCodes。当P-Code执行一次之后，其会被一种标记化的形式存储在__SRP__流中，之后再次运行时会提高VBA的执行速度，可以将其删除，并不影响宏的执行。

![image-20240805233544057](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144972.png)

“Attribut”的地方是源代码

![image-20240806000238585](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144973.png)

![image-20240806000546594](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144974.png)

每一个流模块中都会存在一个未被文档化的PerformanceCache，其中包含了被编译后的P-Code代码，如果_VBA_PROJECT流中指定的Office版本与打开的Office版本相同，则会忽略流模块中的源代码，去执行P-Code代码。

即如果满足脚本编译环境和执行环境的VBA版本一致，可以修改源码部分，以干扰分析工具，绕过AV检测，解释器会直接执行旧缓存。

将恶意的源码与非恶意的VBA源码进行交换，保留p-code不变。宏被特定版本的 Office 打开时才会执行恶意宏代码，除此之外的 Office 版本打开时执行正常宏代码。

此工具实现了这一攻击过程，https://github.com/outflanknl/EvilClippy

### VBA purging

与VBA stomping相反，VBA purging保留了源码，删除了p-code及相关部分。
从模块流和_VBA_PROJECT流中删除Pcode，将MODULEOFFSET的值更改为0，并删除所有SRP流。更容易绕过AV检测和YARA规则
此工具实现了这一攻击过程，https://github.com/fireeye/OfficePurge

### Hiding macros

当文档运行p-code时，VBA引擎会根据p-code修复源码。所以只要p-code运行，使用vba编辑器查看到的就还是源码。即便将doc的源码进行了替换，但是用word打开时还是原来的代码。

想要在VBA编辑器中隐藏真正的宏，只需要修改PROJECT流中的"Module=abcdefg\x0D\x0A"删除并重新保存。这样能够达成成功执行vba代码，但是vba编辑器看不到对应的源码的效果。

可使用工具EviClippy实现，使用-g参数隐藏vba源码。

要使项目锁定且不可看，可以修改PROJECT流ProjectProtectionState和ProjectVisibilityState这两个属性。

将其内容改为任意值，会使得VBA工程被锁定且不可看，只修改ProjectVisibilityState，VBA工程目录可看，但单个代码模块不可看。

可以使用EvilClippy解除锁定，EvilClippy -uu 目标文件。

### 字符串混淆

因为宏代码很容易获取，所以对宏代码的处理往往是进行字符串混淆。

#### Chr()函数

Chr()，返回以数值表达式值为编码的字符（例如：Chr(70)返回字符‘F’）。举例如下：

```VB
Nrh1INh1S5hGed = "h" & Chr(116) & Chr(61) & "t" & Chr(112) &Chr(58) & Chr(47) & Chr(59) & Chr(47) & Chr(99) & Chr(104) & Chr(97) & "t" & Chr(101) & Chr(97) & Chr(117) & Chr(45) & Chr(100) & Chr(60) & Chr(101) & Chr(115) & Chr(45) & Chr(105) & Chr(108) & "e" & Chr(115) & Chr(46) & Chr(61) & Chr(99) & Chr(111) & Chr(109) & Chr(47) & Chr(60) & Chr(52) & Chr(116) & Chr(102) & Chr(51) & Chr(51) & Chr(119) & Chr(47) & Chr(60) & Chr(119) & "4" & Chr(116) & Chr(52) & Chr(53) & Chr(51) & Chr(46) & Chr(59) & Chr(101) & Chr(61) & Chr(120) & Chr(101)
```

解混淆： 查找--替换-转换

“ht=tp:/;/chateau-d<es-iles.=com/，4tf33w/<w4t453.;e=xe”

Chr（）函数还可以利用表达式：

Ndjs = Sgn(Asc(317 - 433) + 105）

ATTH = Chr(Ndjs) + Chr(Ndjs + 12) + Chr(Ndjs + 12) + Chr(Ndjs + 8)

#### Replace（）函数

Replace函数的作用就是替换字符串，返回一个新字符串，其中某个指定的子串被另一个子串替换。

承接上文，把Nrh1INh1S5hGed中多余字符去掉，这里使用Replace函数把多余字符替换为空

```VB
Nrh1INh1S5hGed = Replace(Replace(Replace(Nrh1INh1S5hGed,Chr(60), ""), Chr(61), ""), Chr(59), "")
```

处理之后：Nrh1INh1S5hGed=“[http://chateau-des-iles.com/4tf33w/w4t453.exe”](http://chateau-des-iles.com/4tf33w/w4t453.exe%E2%80%9D)

#### CallByname 函数

CallByname函数允许使用一个字符串在运行时指定一个属性或方法。用法如下：

```VB
 Result = CallByName(Object, ProcedureName, CallType, Arguments())
```

第一个参数，包含要对其执行动作的对象名。

第二个参数，ProcedureName是一个字符串，包含将要调用的方法。

第三个参数，CallType 包含一个常数，代表要调用的过程的类型：方法 (vbMethod)、property let (vbLet)、property get (vbGet)，或 property set (vbSet)。

| [vbGet](https://learn.microsoft.com/zh-cn/dotnet/api/microsoft.visualbasic.constants.vbget?view=net-7.0#microsoft-visualbasic-constants-vbget) | 指定在调用 `CallByName` 函数时，应检索一个属性值。         |
| ------------------------------------------------------------ | ---------------------------------------------------------- |
| [vbLet](https://learn.microsoft.com/zh-cn/dotnet/api/microsoft.visualbasic.constants.vblet?view=net-7.0#microsoft-visualbasic-constants-vblet) | 指示在调用 `CallByName` 函数时，应将属性值设置为对象实例。 |
| [vbMethod](https://learn.microsoft.com/zh-cn/dotnet/api/microsoft.visualbasic.constants.vbmethod?view=net-7.0#microsoft-visualbasic-constants-vbmethod) | 指定在调用 `CallByName` 函数时，应调用一个方法。           |
| [vbSet](https://learn.microsoft.com/zh-cn/dotnet/api/microsoft.visualbasic.constants.vbset?view=net-7.0#microsoft-visualbasic-constants-vbset) | 指示在调用 `CallByName` 函数时，应设置一个属性值。         |

最后一个参数是可选的，它包含一个变量数组，数组中包含该过程的参数。

例如：CallByName Text1, "Move", vbMethod, 100, 100 就相当于执行Text1.Move(100,10) 。

利用callByName，可以用脚本控制控件:

```VB
Dim obj As Object[/align]        
Set obj = Me

    Set obj = CallByName(obj, "Text1", VbGet)

    Set obj = CallByName(obj, "Font", VbGet)

    CallByName obj, "Size", VbLet, 50

    '以上代码="Me.Text1.Font.Size = 50"

Dim obj As Object

Dim V As String

    Set obj = Me

    Set obj = CallByName(obj, "Text1", VbGet)

    Set obj = CallByName(obj, "Font", VbGet)

    V = CallByName(obj, "Size", VbGet)

    '以上代码="V = Me.Text1.Font.Size"
```

#### Alias别名

Alias子句是一个可选的部分，用户可以通过它所标识的别名对动态库中的函数进行引用。

```VB
Public Declare Function clothed Lib "user32" Alias "GetUpdateRect" (prestigiation As Long, knightia As Long, otoscope As Long) As Boolean
```

释义："user32" 库里的函数"GetUpdateRect"的别名clothed。调用clothed函数相当于调用user32库里的GetUpdateRect函数。

更多时候使用别名是，因为Visual Basic不允许调用以下划线为前缀的函数，而在Win32 API函数中有大量C开发的函数可能以下划线开始。使用别名可以绕过这个限制。

#### 利用窗体、控件隐藏信息

控件里可能存放着关键字符串，程序用到上述字符串时，再调用标签控件的caption属性。

控件的各个属性（name、caption、controtiptext、等）都可以成为危险字符串的藏身之所。而仅仅查看宏代码，分析者无法得知这些字符串内容，必须进入编辑器查看窗体属性才能看到。

#### 利用文件属性

这种方式和利用窗体属性的方式类似，就是将一切能存储数据的地方利用起来。就像Demo3中读取文件详细信息中的备注

![202407301833032](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144975.png)

#### 恶意行为字符串

常见宏病毒执行恶意操作时代码中含有的字符串，详见下表：

| 字符串          | 描述                                                         |
| --------------- | ------------------------------------------------------------ |
| http            | URL连接                                                      |
| CallByName      | 允许使用一个字符串在运行时指定一个属性或方法，许多宏病毒使用CallByName执行危险函数 |
| Powershell      | 可以执行脚本，运行.exe文件，可以执行base64的命令             |
| Winmgmts        | WinMgmt.exe是Windows管理服务，可以创建windows管理脚本        |
| Wscript         | 可以执行脚本命令                                             |
| Shell           | 可以执行脚本命令                                             |
| Environment     | 宏病毒用于获取系统环境变量                                   |
| Adodb.stream    | 用于处理二进制数据流或文本流                                 |
| Savetofile      | 结合Adodb.stream用于文件修改后保存                           |
| MSXML2          | 能够启动网络服务                                             |
| XMLHTTP         | 能够启动网络服务                                             |
| Application.Run | 可以运行.exe文件                                             |
| Download        | 文件下载                                                     |
| Write           | 文件写入                                                     |
| Get             | http中get请求                                                |
| Post            | http中post请求                                               |
| Response        | http中认识response回复                                       |
| Net             | 网络服务                                                     |
| WebClient       | 网络服务                                                     |
| Temp            | 常被宏病毒用于获取临时文件夹                                 |
| Process         | 启动进程                                                     |
| Cmd             | 执行控制台命令                                               |
| createObject    | 宏病毒常用于创建进行危险行为的对象                           |
| Comspec         | %ComSpec%一般指向你cmd.exe的路径                             |

### 宏VBA密码工程文件密码破解

![image-20250223133832872](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144976.png)

使用 WinHex软件二进制编辑器打开vbaProject.bin，搜索【DPB】,将【DPB】改为【DPX】并保存。

![image-20250223133858937](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144977.png)

将修改后的vbaProject.bin替换掉原来的文件,文件重新改回到原来的格式。

打开文件，忽略错误，就可以查看VBA代码了，为了防止报错可以重新添加密码。

![image-20250223133958091](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144978.png)

【开发工具】-->【Visual Basic】-->【工具】-->【VBA Project属性】-->【保护】重新设置密码

![image-20250223134050855](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232144979.png)

保存文件，关闭后重新打开，输入设置的密码，即可

TIPS

1>    ProjectPassword (section 2.3.1.16): "DPB=" 是密码保护 

2>    ProjectProtectionState (section 2.3.1.15): "CMG=" 是保护模式，是否可编辑。 

3>    ProjectVisibilityState (section 2.3.1.17): "GC=" 是否可见。



参考

https://github.com/TonyChen56/Virus-Analysis

[宏VBA密码工程文件密码破解 - 吾爱破解](https://www.52pojie.cn/thread-1634125-1-1.html)

[office病毒分析资料整理-看雪](https://bbs.kanxue.com/thread-268255.htm#msg_header_h1_4)

