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


---

## 追加（2026-09-14 第二轮：加载期绑定 + libc HLE 实现）

### 实现内容

1. **加载期符号绑定**（`macho.c` section/DYSYMTAB 解析 + `hle.c` 绑定 pass）：解析 section 头（含 reserved1/reserved2 间接符号索引），将 `__la_symbol_ptr` 槽位重写为 HLE 陷阱地址；`__nl_symbol_ptr` 中的数据符号（`___sF`、`__DefaultRuneLocale`、`__cthread_init_routine`、`_mach_init_routine`、`_errno`）填入 guest 存储地址；`__dyld` 段重定向到可写 shim 页。
2. **HLE 跳板机制**：陷阱区（未映射）+ `UC_HOOK_MEM_FETCH_UNMAPPED` 按地址分发 → 宿主执行 → `uc_emu_stop` + runtime 循环恢复到 LR。曾尝试 `sc` 指令跳板，但 Unicorn PPC 对 `sc` 存在双重 `nip += 4` 及状态回滚问题，弃用。
3. **libc HLE v1**（~150 符号）：malloc/calloc/realloc/free（guest 堆 arena + 地址序合并空闲链）、str/mem 族、stdio（FILE 槽位 + fopen/fread/fwrite/printf 精简实现）、getenv/atexit/signal、pthread 全系（stub）、zlib stub、bsearch（**客户机比较回调**经陷阱往返执行）、qsort（暂为 no-op）。
4. **网络 HLE**：socket/connect/send/recv/getsockopt(SO_ERROR)/select（fd 映射表）、getaddrinfo（数值 IPv4）、fstat/stat（Darwin 结构布局）、fcntl。
5. **dyld 语义**：`dyld_func_lookup`（写返回桩地址）、`__dyld_image_count=1`、`get_image_header/name` 陷阱、crt 的 `__dyld[1]` 置零操作落在可写 shim 页。
6. **诊断增强**：HLE 调用/返回值跟踪、`SOSETTA_WATCH` 写监视点、写保护报告、块级环形缓冲。

### 关键 bug 与修复

| Bug | 根因 | 修复 |
|-----|------|------|
| section flags/reserved 偏移错误 | Mach-O section 头 flags 在 +56（误写 +60） | 修正后绑定立即生效 |
| dyld 桩区字节序错误 | `uc_mem_write` 传入宿主机序 uint32 数组 | `put_be32` 组字节 |
| `__dyld[1]` 被.crt 置零崩溃 | 真实 dyld 代码区可写，我们的只读 | 可写 shim 页 |
| NULL 函数指针调用 | `_errno` 等数据符号未提供存储 | errno 页 |
| bsearch 全部选项 unknown | `findlongopt` 用 libc bsearch + 客户机回调 | 陷阱往返实现客户机回调 |
| pc=0 "干净停止" | `emu_start(begin=0, until=0)` 的 until=0 即停止地址 | until 哨兵改为 1；空调用拦截返回 r3=0 |

### 当前状态

- **`curl -V` 完整成功**：输出 "curl 8.12.1 (powerpc-apple-darwin8) libcurl/8.12.1 OpenSSL/3.6.1 zlib/1.2.5"，exit 0。
- **`curl --help`、参数解析、配置构建全部工作**（bsearch 往返生效）。
- **HTTP/file 请求仍退出 27（CURLE_OUT_OF_MEMORY）**：发生在 `operate()` 的 `curl_share_init()` 之后、`curl_easy_init` 之前，无任何分配失败记录（HLE 层无 NULL 返回、无堆耗尽），疑似 libcurl 内部（share/互斥或 OpenSSL 惰性初始化）路径依赖未实现的宿主行为。这是下一个会话的第一调查点。
- 回归：CTest 5/5 通过。

### 下一步（按优先级）

1. 定位 share-init 静默失败：在 HLE 层对照 libcurl share.c 源码逐步验证；怀疑 `Curl_mutex_init`/`curl_share_setopt` 语义。
2. 打通 resolver：验证同步 pthread 机制与 threaded resolver 的兼容性（`Curl_thread_create` → 同步执行 → done 标志）。
3. HTTP GET 127.0.0.1 端到端（socket/connect/send/recv 已就绪）。
4. qsort 的客户机回调实现（bsearch 同款机制复用）。
