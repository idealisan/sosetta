# 002 — 验收测试初次实测报告（curl / ffmpeg / python）

日期：2026-09-14
对象：sosetta 0.1.0（Phase 1 完成态，commit 19c7b62 之上未提交修改）
环境：WSL2 Ubuntu-22.04（`Ubuntu-22.04` 发行版，`~/sosetta-build`），Unicorn 2.1.4（FetchContent 源码构建）
回归状态：改造后 CTest 5/5 通过，无回归

## 1. 测试对象

三个真实 PowerPC 程序，均来自 [danupsher/tiger-ppc-builds](https://github.com/danupsher/tiger-ppc-builds/releases)（GCC 15.2.0 + ld64-97.17 管线交叉编译，目标 powerpc-apple-darwin8 / Mac OS X 10.4u SDK，上游已在真机 iMac G5 验证）：

| 程序 | 版本 | 主二进制 | 实测命令 |
|------|------|---------|----------|
| curl | 8.12.1 | 6.4 MB | `curl --version` |
| ffprobe/ffmpeg | 7.1.1 | ~20 MB | `ffprobe -version` |
| python | 3.13.12 | ~25 MB（+stdlib） | `python3.13 -V` |

三者共同特征（Mach-O 解析确认）：`MH_MAGIC`、`cputype=0x12`、`MH_EXECUTE`、入口 `LC_UNIXTHREAD`（flavor=1，count=40）、`MH_NOUNDEFS`、无 `LC_LOAD_DYLINKER`。**注意：它们并非真正自包含**——详见 §3 R1（本次实测最重要的发现）。

## 2. 发现的问题与处置

### F1 — LC_UNIXTHREAD 解析过严【已修复】

- **现象**：三个程序加载阶段全部被拒：`bad LC_UNIXTHREAD command`
- **根因**：`macho.h` 硬编码 `PPC_THREAD_STATE_COUNT=42`，要求 cmdsize ≥ 184 字节；真实 Apple/ld64 二进制为 40 字（cmdsize=176）。项目自带的 hello fixture 按 42 字手搓，故 Phase 1 测试从未暴露
- **修复**：以命令自身 `count` 字段为准并与 cmdsize 交叉校验；寄存器偏移修正为 Apple 布局 `srr0(pc), srr1, r0..r31, cr(34), lr(35), ctr(36), xer(37), mq(38)`（原实现 lr/xer/ctr 顺序有误）

### F2 — 静态 crt 运行时依赖 dyld【根因确认，未解决 → §3 R1】

- **现象**：加载后执行即崩 `UC_ERR_FETCH_UNMAPPED (pc=0x8fe01000)`，且未发生任何 syscall
- **根因**：`__DATA,__dyld` 段含两个函数指针（`0x8fe01000`/`0x8fe01008`，真实系统上 dyld 恒定映射于 `0x8fe00000`），`__start` 会调用
- **缓解**：runtime 加载时映射 `0x8fe00000..0x8ff00000`（1 MB，覆盖真实 Tiger dyld 体积）填充 `li r3,0; blr` 桩（语义："无 dyld，返回 NULL"）。桩使程序推进了几个函数调用，但随后死在 lazy-binding 逻辑上（见 §3 R1）

### F3 — Unicorn ppc32 无法映射 0xC0000000 附近【已缓解】

- **现象**：python 的线程状态带 `r1(sp)=0xC0000000`（Apple PPC 默认栈顶），`setup_stack` 报 `map 0xbfff0000+0x10000 failed: UC_ERR_MAP`
- **缓解**：线程 sp 不可映射时回退 `SOSETTA_STACK_TOP`(0x80000000) 并覆盖 r1。python 验证有效
- **备注**：`0x8fe00000` 可映射而 `0xBFFF0000` 不可，Unicorn ppc32 高端地址存在限制，Phase 2 需系统性摸清可用地址窗口

### F4 — 缺乏诊断设施【已补齐】

原实现在未知 syscall 时静默返回 ENOSYS、停机时无任何上下文。新增 `SOSETTA_TRACE=1`：
- 未实现的 BSD syscall（去重，含参数）/ Mach trap（r0 高位为 1 时按负数解释）
- 已实现 syscall 的失败 errno
- `uc_mem_map` 失败详情；停机时打印 `uc_strerror` + PC
- 块级跟踪（进入 dyld 区间事件 + 最近 8 个块）——本次定位 F2/R1 的关键工具
- `setup_stack` 各失败路径的定位日志

### F5 — WSL 全新构建缺依赖【环境问题，已解决】

全新构建 unicorn 报 `PROT_READ undeclared`：pkg-config 缺失导致 configure 探测失败。`apt-get install pkg-config libglib2.0-dev` 后恢复。**应写入开发文档/CI**。

## 3. 核心发现（R1）：所谓"静态"二进制运行时依赖 dyld 惰性绑定

三个程序最终全部死在同一位置：crt 的 lazy-binding 辅助桩循环调用 dyld 空间函数，直至走出 1 MB 桩区（`pc=0x8ff00000`）。

证据链（以 curl 为例，其余相同）：
1. `__la_symbol_ptr` 共 187 项，**全部指向同一地址 `0x2680`**（`__text` 内的 dyld 绑定辅助桩）
2. `__symbol_stub1` 跳表经由 la_ptr 进入辅助桩，辅助桩调用 `__dyld` 段函数指针（dyld 空间）
3. LC_SYMTAB/LC_DYSYMTAB 解析出 **192 个未定义符号**，全部为标准 libc/libSystem/zlib 函数：
   `malloc/free/realloc/calloc/memcpy/str*`、stdio（`___sF/fopen/fprintf$LDBL128/...`）、
   `pthread_*`（14 个）、socket 系列、`errno`（`___error`）、`sysctlbyname`、`getenv`、
   `atexit/__cthread_init_routine/mach_init_routine`、`_dyld_*` 等
4. DYSYMTAB 间接符号表（766 项）完整记录了 stub/la_ptr 槽位与符号的对应关系

**结论**：上游"statically linked" 的实际含义是"无需额外安装 dylib"，但二进制在运行时仍需要 dyld + 系统库（Tiger 自带）。对 sosetta 而言，三个验收目标统一指向同一项工作：**加载期符号绑定 + libc HLE 层**——这正是 Phase 3 "HLE shim layer" 的前置核心，本轮实测将其提前拉入了视野。

## 4. 结果总表

| 程序 | 加载 | 栈建立 | 执行推进 | 当前卡点 |
|------|------|--------|----------|----------|
| curl 8.12.1 | ✅（F1 修复后） | ✅（默认栈） | crt 初始化、若干 dyld 桩调用 | R1 惰性绑定 |
| ffprobe 7.1.1 | ✅ | ✅ | 同上（相同桩地址模式） | R1 |
| python 3.13.12 | ✅ | ✅（F3 回退后） | 同上 | R1 |

三者均在 `pc=0x8ff00000` 处 `UC_ERR_FETCH_UNMAPPED` 终止；全程零 BSD syscall 触达（libc 初始化尚未完成）。

## 5. 本次代码改动清单

- `src/macho.c`：LC_UNIXTHREAD 按 count 解析 + 寄存器偏移修正（F1）
- `src/runtime.c`：dyld 桩区映射（F2 缓解）；栈不可映射时回退（F3）；停机诊断（F4）
- `src/syscall.c`：SOSETTA_TRACE 跟踪（未实现 syscall/Mach trap/errno）（F4）
- `src/cpu.c`：映射失败诊断 + 块级跟踪钩子（F4）

## 6. 对路线图的修订建议

1. **新增 Phase 2.5：加载期绑定 + libc HLE**（R1 的解法，是三个验收目标共同的必经之路）
   - 解析 LC_DYSYMTAB 间接符号表，加载期将 `__la_symbol_ptr`/`__symbol_stub1` 槽位重写到 HLE 跳板
   - HLE 跳板以 `sc` 陷阱或未映射页故障的形式进入宿主，按符号名分发
   - 首批目标符号集：`malloc` 族（guest 堆管理）、`str*`/`mem*`、`getenv`、`atexit`、`___error`（errno TLS）、stdio 写路径
2. Phase 2 优先级调整：FPU（ffmpeg）不变；**线程（pthread_*）复杂度高**，python/curl 深度验收前需专项设计（Unicorn 单核下串行化或协作调度）
3. 系统性测试 Unicorn ppc32 可映射地址窗口，形成 sosetta 的 guest 地址布局规范（F3）
4. unicorn/pkg-config 依赖写入开发文档与 CI（F5）
5. `macho.c` 应增加对真实二进制特性的单测：count=39/40 的 thread state、间接符号表、weak dylib——fixture 生成器需支持这些形态

## 7. 复现命令

```bash
# WSL Ubuntu-22.04
cd ~/sosetta-build/build && make -j$(nproc) && ctest   # 基线 5/5
cd ~/sosetta-build/accept
SOSETTA_TRACE=1 ../build/sosetta curl-8.12.1-ld64/curl --version
SOSETTA_TRACE=1 ../build/sosetta ffmpeg-7.1.1-ld64/ffprobe -version
SOSETTA_TRACE=1 ../build/sosetta usr/local/bin/python3.13 -V
```
