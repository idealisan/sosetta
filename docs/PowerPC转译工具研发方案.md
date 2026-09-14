# **跨平台 PowerPC Mac 应用程序动态二进制转译器（x86-64/ARM64 宿主）研发方案调研报告**

## **方案概述与系统整体架构设计**

在计算机体系结构的演进历程中，指令集架构（ISA）的迁移必然伴随着既有软件资产继承的技术挑战1。历史上，Apple 公司经历了从 Motorola 68k 到 PowerPC、从 PowerPC 到 Intel x86，以及从 Intel x86 到 Apple Silicon ARM64 的多次重大架构转变1。在 2006 年从 PowerPC 向 Intel 迁移的阶段，Apple 引入了基于 Transitive 公司 QuickTransit 技术的 Rosetta 转译层，实现了在 Intel 宿主上透明运行 PowerPC（G3、G4 及 AltiVec 扩展）应用程序的功能1。而在近年向 ARM64 迁移的过程中，Apple 则推出了自主研发的 Rosetta 21。为了在现代 x86-64 及 ARM64 宿主硬件（运行 macOS 或 Linux 操作系统）上重新构建类似的兼容层，以透明运行传统 32 位及 64 位 PowerPC Mac 应用程序，必须针对指令转译、内存模型、二进制容器以及系统接口进行综合设计1。  
PowerPC 架构作为典型的大端序（Big-Endian）精简指令集（RISC），与现代小端序（Little-Endian）的 x86-64（CISC）及 ARM64（RISC）存在显著差异7。研发此类转译工具的核心技术瓶颈在于四大维度：其一是处理大端序与小端序在寄存器与虚拟内存存取时的映射与性能开销7；其二是针对 PowerPC 特有的条件寄存器（Condition Register, CR）及 AltiVec 向量指令集进行高效的机器码转译1；其三是在宿主系统上对 Mach-O 二进制文件与 dyld 动态链接器进行准确装载6；其四是在 macOS 与 Linux 环境下分别完成 Darwin/XNU 内核接口（BSD 系统调用与 Mach Traps）及 Cocoa/Carbon 运行时的兼容11。  
为应对上述技术挑战，转译工具在系统架构设计上被划分为四个层次分明且紧密协同的子系统：

> 1. **Mach-O 容器装载与解析器**：负责装载 PowerPC 架构的 Mach-O 可执行文件与动态链接库，解析包含大端序数据的加载命令（Load Commands）与符号表，分配并映射进程虚拟地址空间6。  
> 2. **动态二进制转译引擎（DBT Engine）**：采用中间表示（IR）或即时编译（JIT）技术，将 PowerPC 机器码转化为目标宿主架构（x86-64 或 ARM64）的原生代码13。同时，结合转译块链接（Direct Block Chaining）与延迟条件码评估（Lazy Condition Evaluation）算法以保障执行效率14。  
> 3. **系统调用与内核接口适配层**：负责拦截 PowerPC 代码发起的 sc 指令，抽取系统调用号与参数，完成参数结构体的字节序反转与对齐调整7。在 macOS 宿主上实现 32 位到 64 位系统调用的映射，在 Linux 宿主上则借助用户态内核服务器（如 darlingserver）模拟 Mach 端口与 IPC 机制12。  
> 4. **高层 API 桥接与框架垫片层（HLE Thunking Layer）**：拦截对于系统动态库（如 CoreFoundation、Carbon 及 Cocoa）的符号调用，跳过对庞大基础框架的低层指令转译，直接重定向并映射至宿主原生 64 位动态库执行，以此实现数量级上的性能提升6。

## **PowerPC 指令集二进制转译核心引擎设计**

### **架构映射与寄存器分配策略**

PowerPC 架构定义了丰富的寄存器资源，包括 32 个通用寄存器（GPR0–GPR31）、32 个双精度浮点寄存器（FPR0–FPR31）、32 个 128 位 AltiVec 向量寄存器（VR0–VR31），以及特殊功能寄存器如条件寄存器（CR）、计数寄存器（CTR）、链接寄存器（LR）和固定点异常寄存器（XER）1。在运行时，转译引擎需要维持一个代表 PowerPC CPU 完整状态的结构体（CPUState）14。  
在不同的宿主架构上，寄存器映射策略呈现出不同的设计路径：

* **x86-64 宿主**：x86-64 架构仅提供 16 个通用寄存器，无法实现对 PowerPC 32 个 GPR 的全一对一物理映射14。因此，转译器必须在内存的 CPUState 中维护全局寄存器数组，并采用局部动态分配算法14。仅将访问极频繁的虚拟寄存器固定映射至 x86-64 物理寄存器（例如将 PowerPC 栈指针 GPR1 映射至 r12，将环境指针映射至 r13），其余通用寄存器则在转译块执行期间根据上下文动态装载与溢出写回（Spill and Fill）14。  
* **ARM64 宿主**：ARM64 架构拥有 31 个通用寄存器（x0–x30）以及 32 个 128 位 SIMD/浮点寄存器（v0–v31）。这使得转译器能够建立接近一对一的直映射关系：将 PowerPC GPR0–GPR31 直接映射至 ARM64 的物理通用寄存器，将 FPR 与 VR 映射至 ARM64 的 NEON 寄存器。这种硬件层面的对称性大幅减少了内存存取频次，使得 ARM64 宿主在转译 PowerPC 代码时具有天然的性能优势。

### **大端序与小端序转换机制**

PowerPC Mac OS X 程序完全运行于大端序（Big-Endian）内存模式下，而 x86-64 与 ARM64 硬件均运行于小端序（Little-Endian）模式7。转译引擎必须保证内存与寄存器中的数值在维持程序语义的前提下实现高性能转换7。  
系统应当遵循“寄存器本地方向，内存源架构方向”的转译原则7。所有在宿主物理寄存器中进行运算的数据均保持宿主本地小端序形态，而进程虚拟内存空间中的数据则严格维持 PowerPC 大端序形态7。  
当转译器遇到 PowerPC 访存指令（如 lwz、stw、lhz 等）时，会在生成的原生代码中自动注入字节反转指令7。在 x86-64 宿主上，可以利用带字节交换的访存指令（如 movbe）或显式的 bswap 指令完成转换；在 ARM64 宿主上，则利用 rev（rev32、rev16）指令在数据装载后或存储前进行转置。同时，在程序初始化以及系统调用交互边界，转译器需对 Mach-O 头部、环境变量、命令行参数及数据缓冲区统一实施预处理字节反转7。

### **条件寄存器（CR）与延迟评估（Lazy Evaluation）优化**

PowerPC 条件寄存器（CR）为一个 32 位寄存器，划分成 8 个 4 位的条件字段（cr0–cr7），用于记录比较操作或算术运算结果的负数（LT）、正数（GT）、零（EQ）及溢出（SO）状态9。由于许多 PowerPC 算术指令（如带 . 结尾的 add.、subf.）都会隐式更新 cr0，如果每次运算都实时计算并合成 32 位的 CR 状态，将带来极其严重的指令膨胀14。  
为解决这一效率瓶颈，转译引擎应采用延迟条件码评估机制（Lazy Condition Evaluation）14。当执行更新 CR 字段的算术或逻辑指令时，JIT 转译器并不生成合成标志位的指令，而是仅将该操作的操作数一（CC\_SRC）、操作数二（CC\_DST）及操作符类型（CC\_OP）写入 CPUState14。只有当控制流到达条件分支指令（如 bc、beq）或显式读取条件寄存器的指令（如 mfcr）时，转译器才根据保存的 CC\_SRC、CC\_DST 和 CC\_OP 动态生成宿主计算代码，推导具体的标志位14。进一步结合死代码消除（DCE）分析，若某个 CR 字段在被显式读取之前就被后续指令覆盖，之前的延迟评估状态将被直接丢弃，从而消除了大部分不必要的标志位计算开销14。

### **转译块（TB）生成与动态链接控制流**

动态二进制转译引擎以基本块为单位生成转译块（Translation Block, TB）14。每一个 TB 包含一段连续的 PowerPC 指令序列，止于分支指令、系统调用或异常抛出点14。  
转译控制流的管理包含以下关键组件：

> 1. **两级转译缓存**：转译引擎维护一个全局转译哈希表以及一个极轻量的跳跃缓存（CPUJumpCache）20。当 CPU 执行到新的 PowerPC PC 地址时，优先通过 PC 哈希在 CPUJumpCache 中查找已转译的 TB 宿主入口，若未命中则回退至全局哈希表；若仍未命中，则触发 JIT 编译器生成新的 TB 并写入缓存20。  
> 2. **直接块链接技术（Direct Block Chaining）**：在默认情况下，执行完一个 TB 后必须返回转译器主循环以分发下一个 TB14。为了避免频繁返回主循环带来的上下文切换损耗，转译引擎在遇到已知跳转目标的条件或无条件分支时，会在宿主代码层面对前一个 TB 的末尾指令进行原子 Patching，直接将其跳转指令的目标地址修正为后一个 TB 的宿主原生代码入口，从而形成流畅的原生控制流拼接14。

## **Mach-O 可执行文件加载与动态链接处理**

### **32 位/64 位 Mach-O 解析与内存布局**

Mac OS X 上的 PowerPC 应用程序均封装为 Mach-O 文件格式（包括 Fat Binary 通用二进制与 Thin Binary 单架构二进制）1。加载器必须按顺序完成以下解析与布局步骤：

> 1. **头部解析与端序反转**：读取文件头部的 mach\_header 或 mach\_header\_64 结构6。由于文件数据以 PowerPC 大端序存储，加载器需要对 magic、cputype、cpusubtype、ncmds 等字段进行字节反转7。校验 cputype 是否满足 CPU\_TYPE\_POWERPC（0x12）或 CPU\_TYPE\_POWERPC646。  
> 2. **段命令映射（Segment Load Commands）**：遍历 LC\_SEGMENT 或 LC\_SEGMENT\_64 加载命令，通过 mmap 系统调用将 \_\_TEXT（代码段）、\_\_DATA（数据段）、\_\_LINKEDIT（符号链接段）等按照指定的虚拟地址（vmaddr）和对齐保护属性映射至进程的虚拟地址空间中10。  
> 3. **栈空间与初始化环境搭建**：分配 PowerPC 运行栈（将 GPR1 指向栈顶），并将转译与字节反转后的命令行参数 argv、环境变量 envp 以及 Apple 专有的 apple 属性向量压入栈中7。

### **动态链接器（dyld）与符号绑定机制**

PowerPC Mac 程序高度依赖 Apple 的动态链接器 dyld 来完成运行时符号解析与动态库加载5。在转译系统的工程设计中，主要存在两种符号绑定处理方案：  
方案一是映射 Apple 开源的 PowerPC 原生 dyld 二进制文件6。加载器将原生 dyld 装载至进程地址空间，并将转译控制权移交至 dyld 的入口点，由 dyld 自行解析应用程序的依赖项并执行符号绑定6。  
方案二是转译器接管 Lazy Symbol Binding 过程21。在 Mach-O 格式中，跨动态库的函数调用通常借由 Symbol Stub、Stub Helper 以及 Lazy Symbol Pointer 配合实现21。初次调用时，Stub 指向 Stub Helper，进而触发动态绑定逻辑21。转译器可以通过拦截 Stub Helper 的跳转，将符号解析行为捕获，并根据符号归属选择将 Lazy Pointer 改写为转译后的 PowerPC 函数地址，抑或是改写为重定向至宿主原生 Native 函数的 HLE 桩地址21。

## **操作系统接口与运行时环境兼容层（macOS 与 Linux 宿主）**

### **系统调用拦截与适配机制**

PowerPC 应用程序在执行系统调用时，通过 sc 指令触发内核中断10。Mac OS X 继承了 Darwin/XNU 内核设计，包含两套独立的系统调用体系：编号为正数的 BSD POSIX 系统调用，以及编号为负数的 Mach Traps（如 mach\_msg、mach\_reply\_port）10。  
转译引擎在识别到 sc 指令后，不能将其直接转换为宿主机的 syscall（x86-64）或 svc（ARM64）指令，因为两者在系统调用号、参数传递寄存器以及结构体对齐上存在本质差异12。转译器需要生成跳出（Call-out）机制，跳转至统一的系统调用适配器：

> 1. **参数抽取与状态提取**：适配器从虚拟 CPU 状态中读取 GPR0（存储系统调用号）以及 GPR3–GPR10（存储第 1 至第 8 个参数）12。  
> 2. **数据内存格式转换（Marshalling）**：对于涉及指针传递复杂结构体的系统调用（例如 sys\_stat、sys\_gettimeofday），适配器必须将 PowerPC 大端序结构体中的字段解析并重新组装为宿主操作系统所期望的小端序结构体7。系统调用返回后，再将结果结构体重新转置回大端序写回用户空间7。  
> 3. **状态码映射（Errno Translation）**：BSD 系统调用的返回值与错误码在 Linux 与 Darwin 之间并不完全一致，适配器必须在返回前对错误码实施映射（如利用 errno\_bsd\_to\_linux 转换函数）12。

### **macOS 宿主与 Linux 宿主的差异化实现**

转译工具在 macOS 与 Linux 两种不同的宿主操作系统上运行时，面临着截然不同的兼容性瓶颈与工程重点：  
在 macOS 宿主（x86-64 或 Apple Silicon ARM64）上，由于底层内核原生即为 Darwin/XNU，系统原生支持 Mach Traps 与 BSD 系统调用12。然而，从 macOS 10.15 (Catalina) 开始，系统彻底移除了对 32 位 User-Space ABI 的支持。由于大多数 PowerPC 应用程序均为 32 位，转译器必须以 64 位原生进程的身份运行，在用户态构建一个 32 位的虚拟内存地址空间，并在转译器内部手动完成 32 位到 64 位系统调用及指针参数的“升轨（Thunking）”。  
在 Linux 宿主上，操作系统缺乏 Darwin 内核接口，必须结合类似 Darling 的开源兼容层架构5。此时，系统不仅需要转译 CPU 指令，还必须在用户态完整模拟 Darwin 运行环境：

* **Mach 核心与 IPC 模拟**：通过用户态内核服务器（darlingserver）建立进程间通信通道，模拟 Mach 端口、Mach 消息传递及 POSIX 信号映射12。  
* **文件系统隔离**：采用基于 Linux overlayfs 的 chroot 容器技术，为 PowerPC 进程提供符合 macOS 规范的目录结构（如 /System/Library、/Library）6。  
* **基础框架重构**：借由 Cocotron、GNUstep 或 Apportable Foundation 开源项目，在 Linux 上重新编译出原生 64 位 Cocoa 及 CoreFoundation 库供转译层调用5。

### **高层 API 桥接（HLE Thunking）**

对于图形界面应用程序，如果完全依赖底层的机器指令转译去逐条执行系统级动态库（如 QuartzCore、AppKit），会产生巨大的计算开销与帧率瓶颈6。采用高层模拟（High-Level Emulation, HLE）与参数垫片（Thunking）技术是提升转译性能的核心路径11。  
当转译器识别到 PowerPC 代码准备调用系统框架的高层 API（例如 CoreFoundation 中的 CFDictionarySetValue）时，拦截机制会将控制权转移至 HLE 垫片函数：

> 1. **参数提取与转化**：垫片函数从虚拟 PowerPC 状态中提取参数（如 32 位大端序的 CFDictionaryRef 指针与 Key/Value 指针）7。  
> 2. **指针与对象重映射**：转译器维护一个内部对象映射表，将 32 位虚拟地址映射为宿主 Native 内存空间中的 64 位原生 CoreFoundation 对象。  
> 3. **原生函数执行**：直接调用宿主 macOS 操作系统或 Linux Darling 框架中原生的 64 位 CFDictionarySetValue 函数，利用宿主硬件与 GPU 驱动完成计算或渲染。  
> 4. **返回值封装**：将 Native 函数的返回值转换回大端序并写入 PowerPC 的 GPR3 寄存器，随后绕过原本的 PowerPC 库函数代码，直接返回至调用者的下一条指令7。

## **关键技术选型对比与研发路径规划**

### **动态二进制转译引擎选型对比**

针对核心转译引擎的技术实现，研发团队有多种路线可选。下表展示了不同技术选型的关键维度对比：

| 选型维度 | 基于 QEMU TCG 模块二次开发 | 基于 Unicorn Engine 框架集成 | 基于 LLVM ORC JIT 架构自研 | 基于 Peephole 规则与超级优化自研 |
| :---- | :---- | :---- | :---- | :---- |
| **开发与维护难度** | 中等；利用现有的 PPC 前端与 TCG 模块27 | 较低；提供封装良好的 C/Python 绑定 API28 | 极高；需自行实现前端解码与 LLVM IR 映射13 | 高；需建立庞大的模式匹配与规则库7 |
| **运行时转译性能** | 良好；支持直接块链接与 MTTCG 多线程14 | 中等；受到频繁的 C 语言 API 回调开销限制28 | 极高；得益于 LLVM 强大的编译优化管线3 | 良好；对特定计算密集型片段极其高效30 |
| **JIT 编译延迟** | 较低；TCG 生成代码过程极其轻量26 | 较低28 | 较高；LLVM 优化管线较重，启动延迟明显13 | 极低；主要为直接模式替换7 |
| **代码可控性与扩展性** | 较差；QEMU 源码庞大且存在系统仿真历史包袱31 | 一般；底层绑定 QEMU 逻辑28 | 极高；可自由定制寄存器映射与内存 hook13 | 高；规则与流水线完全自主控7 |
| **工程适用场景** | 快速工程验证与基础指令转译构建 | 原型验证与单指令集单元测试 | 追求极致性能的工业级商业兼容层13 | 针对热点代码块的专门二次优化30 |

### **操作系统兼容策略选型对比**

针对宿主系统上的兼容策略，根据目标运行环境的不同，存在以下实现路径对比：

| 选型维度 | macOS 宿主：64 位用户态 Thunking | Linux 宿主：Darling 兼容框架集成 | 全系统仿真（System Emulation） |
| :---- | :---- | :---- | :---- |
| **执行效率** | 极高；直接调用 Native 系统 API 与 GPU 硬件 | 中等；依赖 Darling 用户态服务与 Cocoa 模拟度5 | 极低；需整体运行系统虚拟机与软件 MMU16 |
| **工程研发工作量** | 中等；核心在于 32 位到 64 位升轨与端序映射 | 极高；需维护复杂的 Mach/POSIX 翻译服务12 | 较低；直接复用现有 QEMU System 仿真 |
| **图形与 GUI 体验** | 原生；无缝集成 Quartz/AppKit 窗口系统1 | 基础；仅能支持简单 Cocoa 界面与 CLI5 | 基础；局限于虚拟 framebuffer 画面输出 |
| **用户集成度** | 透明运行，应用表现如同原生 64 位程序1 | 容器化运行，类似 Wine 的桌面体验5 | 隔离独立，需要单独启动虚拟机窗口 |

### **研发实施路径规划**

项目的工程研发建议划分为四个阶段递进推进：

#### **第一阶段：转译引擎核心与 Mach-O 加载器实现（第 1–4 个月）**

> 1. 研发 32 位 PowerPC Mach-O 解析器，完成大端序加载命令解析与内存 mmap 映射6。  
> 2. 基于 QEMU TCG 或自研 IR 构建基础转译器，实现 PowerPC 基础通用指令集（G3/G4 算术、逻辑、分支跳转）的转译1。  
> 3. 实现大端序访存自动插桩与延迟条件码评估（Lazy CR）机制7。  
> 4. 阶段目标：成功加载并转译执行简单的 PowerPC 纯计算 CLI 应用程序（如 Factorial、Matrix Multiply）6。

#### **第二阶段：系统调用映射与 Darwin 运行环境适配（第 5–8 个月）**

> 1. 建立系统调用拦截机制，实现基本 POSIX/BSD 系统调用（如 read、write、mmap）的参数格式转换与对齐适配7。  
> 2. 在 macOS 宿主上实现 32 位至 64 位系统调用升轨器；在 Linux 宿主上对接 darlingserver 以支持 Mach Traps12。  
> 3. 扩展指令转译引擎，引入 PowerPC 浮点指令（FPU）及 128 位 AltiVec 向量指令集支持1。  
> 4. 阶段目标：稳定运行复杂的命令行工具链（如 PPC 架构的 Python 解释器、Perl 及 Unix 基础工具）6。

#### **第三阶段：动态链接与 API HLE 垫片层开发（第 9–12 个月）**

> 1. 实现 Mach-O 动态符号绑定拦截机制，解析 Stub Helper 与 Lazy Symbol Pointer21。  
> 2. 针对 libSystem.B.dylib 及 CoreFoundation.framework 开发核心 HLE 垫片，将 PPC 符号调用映射至宿主 Native 动态库6。  
> 3. 处理跨架构调用时的 C++ vtable 布局映射与 Objective-C 消息发送（objc\_msgSend）接管机制。  
> 4. 阶段目标：能够成功运行简单的 GUI 应用程序（如基于 Cocoa/Carbon 的基础 Mac 界面程序）6。

#### **第四阶段：代码生成优化与兼容性攻坚（第 13–18 个月）**

> 1. 引入转译块直接链接（Direct Block Chaining）与两级跳跃缓存（CPUJumpCache），提升热点循环的运行效率14。  
> 2. 实现多线程原子指令（PowerPC lwarx/stwcx.）向 x86-64 lock 指令及 ARM64 ldxr/stxr 独占存取指令的正确映射。  
> 3. 针对 PowerPC G5 64 位指令以及复杂 AltiVec 算法实施超级优化（Superoptimization）模式匹配1。  
> 4. 阶段目标：达到接近原生 Rosetta 1 的流畅度，能够稳定运行大型商业软件及经典 PowerPC Mac 游戏1。

## **结论与工程落地建议**

研发运行于 x86-64 和 ARM64 宿主上的 PowerPC Mac 应用程序动态二进制转译工具，是一项贯穿 CPU 体系结构、动态编译优化、操作系统内核接口以及高层框架的复合型工程1。  
基于上述调研分析，针对研发团队提出以下三点工程落地建议：

> 1. **采用“低层转译 \+ 高层 API 垫片”的双轨并行路线**：纯粹依赖底层指令转译去运行庞大的 Mac OS X 系统框架会导致不可接受的性能衰减6。团队应将指令转译的边界限制在应用程序代码及其私有依赖库内，将系统级 API（如 Quartz、CoreFoundation、AppKit）尽可能通过 HLE 垫片重定向至宿主原生 Native 库执行6。  
> 2. **优先以 ARM64 作为主力目标宿主平台**：由于 ARM64 架构拥有 31 个通用寄存器与 32 个 SIMD 向量寄存器，能够实现对 PowerPC 寄存器状态的近乎直射映射，大幅降低转译代码中的内存存取开销。相比 x86-64，ARM64 更易于获得突破性的运行效率。  
> 3. **充分复用成熟开源生态以降低研发风险**：在底层指令转译部分，建议前期利用 QEMU TCG 或 Unicorn Engine 快速构建原型并验证端序转换与 Mach-O 装载逻辑7；在 Linux 宿主兼容性方面，建议深度吸收 Darling 项目在用户态 Mach 服务与 POSIX 模拟领域的既有成果，避免重复构建底层的 OS 翻译机制5。

#### **引用的著作**

> 1. Rosetta (software) \- Wikipedia, [https://en.wikipedia.org/wiki/Rosetta\_(software)](https://en.wikipedia.org/wiki/Rosetta_\(software\))  
> 2. A brief history of architecture transitions \- The Eclectic Light Company, [https://eclecticlight.co/2025/05/17/a-brief-history-of-architecture-transitions/](https://eclecticlight.co/2025/05/17/a-brief-history-of-architecture-transitions/)  
> 3. PA-RISC to IA-64: transparent execution, no recompilation, [https://www.researchgate.net/publication/2955242\_PA-RISC\_to\_IA-64\_transparent\_execution\_no\_recompilation](https://www.researchgate.net/publication/2955242_PA-RISC_to_IA-64_transparent_execution_no_recompilation)  
> 4. Why so few games for Macs? \- Steam Community, [https://steamcommunity.com/discussions/forum/2/694248165029849215/?ctp=2](https://steamcommunity.com/discussions/forum/2/694248165029849215/?ctp=2)  
> 5. Darling | macOS translation layer for Linux, [https://www.darlinghq.org/](https://www.darlinghq.org/)  
> 6. Darling (software) \- Wikipedia, [https://en.wikipedia.org/wiki/Darling\_(software)](https://en.wikipedia.org/wiki/Darling_\(software\))  
> 7. Binary Translation Using Peephole Superoptimizers, [http://theory.stanford.edu/\~sbansal/pubs/osdi08\_html/index.html](http://theory.stanford.edu/~sbansal/pubs/osdi08_html/index.html)  
> 8. A-profile CPU architecture support — QEMU documentation, [https://www.qemu.org/docs/master/system/arm/emulation.html](https://www.qemu.org/docs/master/system/arm/emulation.html)  
> 9. Interprocedural Analysis of Low-Level Code, [https://d-nb.info/101343708X/34](https://d-nb.info/101343708X/34)  
> 10. Mach-O linking and loading tricks \- Darling Development Blog, [https://blog.darlinghq.org/2018/07/mach-o-linking-and-loading-tricks.html](https://blog.darlinghq.org/2018/07/mach-o-linking-and-loading-tricks.html)  
> 11. Apple Plans to Use Its Own Chips in Macs from 2020, Replacing Intel, [https://news.ycombinator.com/item?id=16737072](https://news.ycombinator.com/item?id=16737072)  
> 12. System call emulation \- Darling Docs, [https://docs.darlinghq.org/internals/basics/system-call-emulation.html](https://docs.darlinghq.org/internals/basics/system-call-emulation.html)  
> 13. Efficient Code Generation in a Region-based Dynamic Binary, [https://www.pure.ed.ac.uk/ws/files/24354382/main\_3.pdf](https://www.pure.ed.ac.uk/ws/files/24354382/main_3.pdf)  
> 14. QEMU, a Fast and Portable Dynamic Translator \- USENIX, [https://www.usenix.org/legacyurl/usenix-05-151-technical-paper-freenix-track-4](https://www.usenix.org/legacyurl/usenix-05-151-technical-paper-freenix-track-4)  
> 15. Emulation \- UTK-EECS, [https://web.eecs.utk.edu/\~mrjantz/slides/teaching/runtime\_systems/emulation.pdf](https://web.eecs.utk.edu/~mrjantz/slides/teaching/runtime_systems/emulation.pdf)  
> 16. Translator Internals — QEMU 2.7.0 documentation \- Red Hat People, [https://people.redhat.com/pbonzini/qemu-test-doc/\_build/html/topics/Translator-Internals.html](https://people.redhat.com/pbonzini/qemu-test-doc/_build/html/topics/Translator-Internals.html)  
> 17. darlinghq/darling: Darwin/macOS emulation layer for Linux \- GitHub, [https://github.com/darlinghq/darling](https://github.com/darlinghq/darling)  
> 18. Binary Translation PowerPoint Presentation, free download, [https://www.slideserve.com/xia/binary-translation-powerpoint-ppt-presentation](https://www.slideserve.com/xia/binary-translation-powerpoint-ppt-presentation)  
> 19. TCG Intermediate Representation — QEMU documentation, [https://www.qemu.org/docs/master/devel/tcg-ops.html](https://www.qemu.org/docs/master/devel/tcg-ops.html)  
> 20. Inside QEMU: How TCG Implements Dynamic Binary Translation, [https://medium.com/@eltrixpain/inside-qemu-how-tcg-implements-dynamic-binary-translation-caching-and-a-virtual-cpu-b3e16dc02c89](https://medium.com/@eltrixpain/inside-qemu-how-tcg-implements-dynamic-binary-translation-caching-and-a-virtual-cpu-b3e16dc02c89)  
> 21. Mach-O linker information \- Efiens Blog, [https://blog.efiens.com/post/luibo/osx/linker-info/](https://blog.efiens.com/post/luibo/osx/linker-info/)  
> 22. Mach-O: Add the ability to parse the dyld binding info \#597 \- GitHub, [https://github.com/gimli-rs/object/issues/597](https://github.com/gimli-rs/object/issues/597)  
> 23. Mach-O: special analysis for dyld\_stub\_binder() function · Issue \#165, [https://github.com/avast/retdec/issues/165](https://github.com/avast/retdec/issues/165)  
> 24. Inside a Hello World executable on OS X \- Alex Drummond, [https://adrummond.net/posts/macho](https://adrummond.net/posts/macho)  
> 25. Implementation of Linux syscall translation layer to MacOS \- Reddit, [https://www.reddit.com/r/C\_Programming/comments/1l8tpbq/implementation\_of\_linux\_syscall\_translation\_layer/](https://www.reddit.com/r/C_Programming/comments/1l8tpbq/implementation_of_linux_syscall_translation_layer/)  
> 26. Translator Internals — QEMU documentation, [https://www.qemu.org/docs/master/devel/tcg.html](https://www.qemu.org/docs/master/devel/tcg.html)  
> 27. QEMU Internals, [https://qemu.weilnetz.de/doc/2.7/qemu-tech-20160903.html](https://qemu.weilnetz.de/doc/2.7/qemu-tech-20160903.html)  
> 28. Unicorn Engine \- GitHub, [https://github.com/unicorn-engine](https://github.com/unicorn-engine)  
> 29. unicorn-engine/unicorn: Unicorn CPU emulator framework ... \- GitHub, [https://github.com/unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn)  
> 30. Binary Translation Using Peephole Superoptimizers, [https://theory.stanford.edu/\~aiken/publications/papers/osdi08.pdf](https://theory.stanford.edu/~aiken/publications/papers/osdi08.pdf)  
> 31. LLVM ORC vs QEMU TCG : r/EmuDev \- Reddit, [https://www.reddit.com/r/EmuDev/comments/gp5111/llvm\_orc\_vs\_qemu\_tcg/](https://www.reddit.com/r/EmuDev/comments/gp5111/llvm_orc_vs_qemu_tcg/)  
> 32. Run macOS Software on Linux Using Darling \- Sovin IT, [https://sovin.se/en/blog/run-macos-software-on-linux-using-darling-1788244847145](https://sovin.se/en/blog/run-macos-software-on-linux-using-darling-1788244847145)