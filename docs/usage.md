# code-analyzer 使用教程

`code-analyzer` 用于一次性扫描 C/C++ 工程，并保存 Cppcheck、Flawfinder、
Splint 的原始报告、执行清单、HTML 索引和脱敏 ZIP。它不会自动安装软件、
运行构建、判断误报或修改被扫描的源码。默认还会从原生 XML、SARIF、CSV
和诊断日志派生非权威 review；review 不会覆盖原生证据，findings 与工具/
配置 diagnostics 始终分开。

## 1. 安装

在本项目根目录执行：

```bash
python3 -m pip install -e .
code-analyzer --version
```

需要 Python 3.11 或更高版本。没有安装命令入口时，也可以使用：

```bash
python3 -m code_analyzer --version
python3 run_code_analyzer.py --version
```

## 2. 检查运行环境

```bash
code-analyzer doctor
code-analyzer doctor --json
```

Doctor 会检查 Python、WSL、Ubuntu、`C.UTF-8` locale，以及三个分析器的
可执行文件和必需能力。它只给出 Ubuntu 24.04 安装建议，不会执行安装。

当前 Ubuntu 提供的 Cppcheck 2.13.0 虽然实际接受 `--xml-version=2`，但其
帮助页没有声明该参数时，doctor 会运行最小临时 canary；如果实际能力可用，
会记录为经 canary 验证的 `compatible`，而不是误判为不兼容。

## 3. 全屏配置界面

交互终端中不带参数会以当前目录为 SOURCE 打开中文 TUI；也可以显式指定：

```bash
code-analyzer
code-analyzer tui ./project
code-analyzer tui ./project --config ./review-config.toml
```

TUI 是单页基础扫描界面，仅显示 SOURCE、显式配置文件、输出目录、Compile DB
模式与路径、三个工具开关、共享 ZIP 和失败阈值，并提供可见的保存、预检、退出
和开始扫描按钮。宽度不小于 120 列时自动双栏显示，较窄终端回落为单栏；操作
按钮固定在表单下方，不随滚动消失。聚焦某个字段时状态栏会显示其帮助说明；
评分分级说明通过 `F1` 或点击表单内链接查看。超时、并发、源码 glob、宏和
include 等高级配置继续通过 TOML 或 CLI 设置；TUI 会继承并保留这些隐藏值，
不会把它们重置为默认值。

`F5` 在后台执行只读预检，展示 compile database 候选、覆盖率和工具兼容性；
`F9` 先展示 SOURCE、工具、输出、排除规则、review/gate 和文件系统影响，再由
用户确认。缺少工具或能力是警告，可确认后沿用现有容错语义；没有选择任何工具
是阻塞错误。新报告固定使用本文件“代码审查分级参考”所述的四级格式。

界面修改默认只存在内存中。只有 `Ctrl+S` 并确认路径/覆盖后才写入完整、可复现
的 v2 快照；写入使用同目录临时文件、重载一致性校验和原子替换。TUI 不会生成
compile database、运行 CMake 或安装工具。扫描中 `Ctrl+C` 经确认后安全停止，
已有报告目录保留并写入 `interrupted/130` manifest。界面至少需要 80×24，且
必须在 TTY 中运行；非 TTY 的无参数或 `tui` 调用退出 `2`。

### 3.1 扫描运行视图

扫描开始后表单让位给运行视图：一行标题说明此刻在查什么，一行汇总（百分比、
已运行时长、静态与 LLM 的完成数、token 预算），一条进度条，然后是**扫描流程**
面板与实时日志。

```text
正在扫描 · splint src/dev.c
46% · 已运行 01:15 · 静态 1/3 · LLM 1/30 · prompt 41.2k/4.2M（估算：字符/4）
╭─ 扫描流程 · 20260901T140000Z-ab12cd34ef56 ──────────────╮
│   ✓ 发现            3 文件 · compile-db 2 条            │
│ ├ ✓ cppcheck        单元 2/2                            │
│ ├ ⠙ splint          单元 12/57 · src/dev.c · 01:15      │
│ ├ ⠙ llm-security    单元 3/5 · src/dev.c (high) · 01:15 │
│ │   … 另外 5 个       5 等待                             │
│ └→ ○ 稳定 → ○ 审查 → ○ 导出 → ○ 报告                    │
╰─────────────────────────────────────────────────────────╯
```

第一行是发现阶段，`├` 从它扇出到每个 producer，`└→` 汇入尾链——这就是 DAG，
与 `serve` 实时页画的是同一张图、同一套状态词汇：`✓` 完成、`✕` 失败、`●`/旋转
字符运行中、`○` 等待。**静态分析与 LLM 扫描是并发的**，所以同时有多行在转不是
错觉。

每行右侧是"方式"，即这一步实际在怎么查：

| 显示 | 含义 |
|---|---|
| `单元 2/2` | 已完成单元数 / 计划数；计划数未知时显示 `已完成 N 单元`，绝不编造分母 |
| `compile-db` / `fallback` | cppcheck 的构建感知遍 / 纯源码回退遍 |
| `分片 3/5`（`shard-000N`） | flawfinder 的分片；分片数来自 `units/planned` 事件，未宣布时不显示分母 |
| `src/dev.c` + `范围 build · jobs 4` | splint 正在检查的翻译单元与其扫描范围 |
| `src/dev.c (high)` + `等待 / 流式 / 读取 x.h / 解析 / 校验` | LLM scanner 正在审查的单元、风险档位，以及会话进行到的**步骤** |
| `8 findings` | 该 producer 已报告的 finding 数——静态工具在单元报告解析完成时累加，LLM 每个会话结束时累加 |
| `◐` | 部分完成：工具跑完了，但有单元失败、超时或未调度；节点详情列出原因直方图 |
| `prompt 41.2k/4.2M（估算：字符/4）` + `12 tok/s · ETA 18 分` | token 预算；**估算说明永远随数字出现**；速率与 ETA 来自最近 20 个会话的滑动均值 |

运行中可用的按键（`F1` 也列出）：

| 键 | 作用 |
|---|---|
| `↑` `↓` | 在 producer 行之间移动光标（`▶` 标记） |
| `Enter` | 光标所在节点的详情：原因直方图、未调度/被跳过的单元、正在进行的步骤 |
| `p` / `P` | 暂停 / 恢复 LLM 泳道 / 静态泳道；正在运行的单元会完成，下一单元在检查点等待 |
| `s` | 跳过光标所在 producer 尚未开始的单元（确认对话框）；已有证据保留 |
| `+` / `-` | 调整 LLM 并发（上限 8；第三方 provider 见 12.5 节的速率限制） |
| `r` | LLM 重试：把未得到模型回答的单元（断路器/预算未调度、传输或提供方失败）作为新一轮重新扫描；可勾选"仅传输/提供方失败" |
| `d` | 重新打开推迟的构建上下文补丁对话框（见 8.1 节） |
| `F3` / `F4` | 切换右侧面板（日志 / LLM / 问题）/ 切换日志过滤（全部 / 警告 / 错误） |
| `Ctrl+C` | 协作式取消 |

每一次操作都会以 `control/*` 事件写入 `events.jsonl` 与 `logs/runner.log`：谁在什么时候
暂停、跳过、改了并发、做了什么决定，事后都查得到。

终端宽度 ≥120 列时流程图与日志左右并排，较窄时上下堆叠且流程图自动折叠——
**运行中的节点永远不会被折叠掉**，被省略的用 `… 另外 N 个` 汇总。`F2` 可隐藏
流程图，把行数全部还给日志。

动画只有两处：运行中节点的旋转字符，以及脊线上流动的光点；字符宽度始终不变，
不会抖动。`CODE_ANALYZER_NO_ANIMATION=1`、`TERM=dumb` 或 `TEXTUAL_ANIMATIONS=none`
会**冻结动画但不隐藏任何信息**（运行中节点显示静态 `●`），与第 4 章 CLI 的
开关一致。

## 4. 开始扫描

最简单的调用：

```bash
code-analyzer analyze /path/to/c-project
```

例如：

```bash
code-analyzer analyze trusted-firmware-m
```

扫描进度实时写到 stderr，例如：

```text
[code-analyzer] discovering source files and build context
[code-analyzer] inventory ready: 42 files; compile database entries: 8
[code-analyzer] tool 1/3 cppcheck: starting
[code-analyzer] tool 1/3 cppcheck: unit 1/2 compile-db: scanning 8 files
[code-analyzer] tool 1/3 cppcheck: unit 1/2 compile-db: completed in 3.42s
[code-analyzer] run finished: status complete, exit code 0
```

在交互式终端中，两条进度消息之间会显示一个原地旋转的状态行和已运行时间，
例如 `⠹ active 00:18 · ... scanning ...`，用于确认长时间扫描仍在继续。输出被
重定向、由 CI 捕获或终端为 `dumb` 时会自动退回普通逐行文本，不会写入 ANSI
控制字符。需要手动关闭动画时：

```bash
CODE_ANALYZER_NO_ANIMATION=1 code-analyzer analyze ./project
```

stdout 始终只输出最终私有报告目录。因此脚本可以安全捕获路径，同时让进度
继续显示在终端：

```bash
run_dir=$(code-analyzer analyze ./project)
echo "报告目录：$run_dir"
```

## 5. Compile database

自动模式会在以下有界位置查找并校验 `compile_commands.json`，不会跟随符号
链接，也不会因此运行 CMake 或构建命令：

- `SOURCE/compile_commands.json`
- `SOURCE/build*`、`SOURCE/cmake-build-*`、`SOURCE/out`
- `SOURCE.parent/build`、`SOURCE.parent/out` 下最多三层

有多个候选时，依次按源码 TU 覆盖数、有效工作目录比例和修改时间选择。候选
诊断与最终选择记录在 `manifest.json` 的 `compile_database.discovery` 中。
缺失时，`analyze` 在 stderr 给出下一条命令并继续降级扫描；stdout 仍只包含
报告目录。

只读检查（不会执行生成）：

```bash
code-analyzer compile-db ./project --json
```

若已找到有效数据库，普通 `compile-db` 只输出其绝对路径。CMake 工程可由向导
只运行 configure，默认输出目录为 `SOURCE/build/code-analyzer`：

```bash
code-analyzer compile-db ./project --method cmake
code-analyzer compile-db ./project --method cmake --generator Ninja --yes
code-analyzer compile-db ./project --method cmake --preset linux-debug --yes
code-analyzer compile-db ./project --method cmake \
  --cmake-arg=-DCMAKE_TOOLCHAIN_FILE=/opt/toolchain.cmake --yes
```

向导会强制传入 `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`，但不会执行
`cmake --build`、清理 build 目录或安装 CMake/Ninja/Make。自定义构建必须同时
给出预期产物和完整 argv：

```bash
code-analyzer compile-db ./project \
  --method command \
  --expected-db ./project/compile_commands.json \
  --yes \
  -- bear -- make -j8
```

命令以 `shell=False` 执行。交互终端在展示 cwd、完整 argv、输出路径和影响后
询问 `[y/N]`；非交互环境只有显式 `--yes` 才执行。生成日志保存在
`code-analyzer-reports/compile-db/`，成功后输出可复制的 `analyze` 命令与
`[build]` TOML 片段，但不会修改项目配置。

`compile-db` 的退出码为：`0` 表示找到或成功生成并验证，`10` 表示仅给出引导
或用户取消，`20` 表示生成失败/超时/产物验证失败，`2` 表示参数或路径错误，
`130` 表示用户中断。

显式指定数据库：

```bash
code-analyzer analyze ./project \
  --compile-db ./build/compile_commands.json
```

禁用数据库：

```bash
code-analyzer analyze ./project --no-compile-db
```

数据库缺失或被禁用时仍会扫描，但 manifest 会记录
`analysis_context: "degraded"`。

有有效数据库时，Splint 默认只扫描数据库覆盖的 C TU/配置，未覆盖 C 文件写入
`inputs/splint-not-in-build.txt`，不算 completed 或 unscheduled。Cppcheck 仍会
对数据库外 inventory 做 fallback，Flawfinder 始终覆盖完整 inventory：

```bash
code-analyzer analyze ./project --splint-scope auto
code-analyzer analyze ./project --splint-scope build
code-analyzer analyze ./project --splint-scope inventory
```

## 6. 选择分析器

默认请求三个工具。只运行一个或两个工具：

```bash
code-analyzer analyze ./project --tool cppcheck

code-analyzer analyze ./project \
  --tool cppcheck \
  --tool flawfinder
```

未选择的工具也会出现在 manifest 中，状态为 `not_requested`。

## 7. 输出目录

```bash
code-analyzer analyze ./project \
  --output-root /tmp/code-review-reports
```

相对输出路径相对于当前工作目录。每次运行都会创建唯一目录，不覆盖或自动
删除旧报告。

## 8. 提供 fallback 构建参数

```bash
code-analyzer analyze ./project \
  --no-compile-db \
  --include ./project/include \
  --system-include /opt/sdk/include \
  --define PRODUCT_VERSION=2 \
  --define FEATURE_X \
  --undefine LEGACY_MODE \
  --c-standard c11 \
  --cpp-standard c++20 \
  --cppcheck-platform unix64
```

这些参数只用于未被 compile database 覆盖的 fallback 扫描。

### 8.1 让工具自己找出缺的构建上下文

没有 compile database 时，Splint 常常在第一条 `#include` 就死掉：头文件明明在树里，
只是没人告诉它去哪找。`[build] assist`（默认 `propose`）让运行在静态工具跑完后
多走一个**修补循环**：

1. **诊断**：汇总失败单元记录下的原因——缺哪些头文件、哪些 `#error`、几处解析错误。
2. **推断**（确定性代码）：只提出树能证明的东西——唯一地携带某个缺失头文件的目录成为
   `-I`；同名头文件出现在多个板级目录时，按失败文件所在子树给出 `[[build.overrides]]`；
   保留名警告是唯一失败原因时提出 `report_reserved_names = false`；树里根本没有的头文件
   可以生成**空的桩头文件**（默认不勾选，永远由代码生成、放在报告目录内、排在 `-I` 最后）。
3. **咨询模型**（8.2 节）：只要 `[llm]` 端点可达就会问一次，与 `llm.enabled` 无关。
4. **探针**：先在 ≤ `assist_probe_units`（默认 12）个失败单元上试跑补丁，报告有几个
   现在能到达 `Finished checking`。
5. **决定**：TUI 弹出逐项勾选的对话框；终端上是 `[y/N]`；无 TTY 的运行只记录不应用，
   除非给了 `--build-assist-yes`。`assist = "auto"` 只在补丁全部来自确定性推断且探针有
   改善时自动应用。
6. **重跑**：只重跑失败单元，作为 attempt 2 写进**新的**单元目录；原尝试保留并标记
   `superseded_by`，审查表中对应行的 `evidence_context` 带 `/superseded` 后缀，
   dashboard 可按"已被替代的尝试"过滤。

```bash
code-analyzer analyze ./project --no-compile-db --build-assist propose        # 询问（默认）
code-analyzer analyze ./project --no-compile-db --build-assist-yes            # 无人值守：应用预选项
code-analyzer analyze ./project --build-assist off                            # 关闭
code-analyzer tools-resume ./reports/<slug>/<run> --tool splint               # 事后续跑同一循环
```

证据全部在报告目录里：`inputs/build-context/r<N>/` 下有 `diagnosis.json`、`patch.json`、
`probe.json`、`llm.json`、`decision.json`、`applied-config.toml`、`stubs/`；
`suggested-config.toml` 是可以直接粘进项目 TOML 的 `[build]` 片段；`manifest.json` 的
`build_context` 记录每一轮的前后对比。循环**从不**改写项目自己的 `.code-analyzer.toml`、
不往源码树写任何文件、不运行构建命令、不安装工具。

`tools-resume` 从上一轮之后继续：无人值守时只记录了补丁的运行，事后在终端里确认一次
即可应用并重新推导审查报告。

### 8.2 LLM 配置器

确定性推断解决不了"这个子树到底按哪块板编译"、"`#error` 要的宏该是什么值"、
"哪些缺失头文件真的是外部 SDK"这类问题。`build-context-configurator` 技能把诊断
（只有计数、头文件名与目录名，没有源码正文）交给 `[llm]` 端点的模型，允许它只读地翻
几个头文件，然后返回一个 JSON 提议。提议里的每一项都经过与手写 TOML 相同的校验：
路径必须是树内目录、`match` 必须命中至少一个文件、宏定义必须符合 `NAME[=VALUE]`、
桩头文件名必须来自诊断的 external 列表；不合规的项被丢弃并逐条记录在
`llm/sessions/build-context-configurator/r<N>/proposal.json` 的 `problems` 里。模型提出的
项在对话框里标为 **LLM**，探针没有改善时默认不勾选，且**永远**不会被 `auto` 模式
自动应用。第三方端点会在决策摘要里注明"诊断已离开本机"。

排除路径或选择读取 `.gitignore`：

```bash
code-analyzer analyze ./project \
  --exclude "fixtures/broken/**" \
  --exclude "generated/test.c" \
  --respect-gitignore
```

默认不读取 `.gitignore`。

## 9. 超时设置

```bash
code-analyzer analyze ./project \
  --cppcheck-timeout 7200 \
  --flawfinder-timeout 1800 \
  --splint-tu-timeout 60 \
  --splint-total-timeout 14400 \
  --splint-jobs 4 \
  --splint-heartbeat 10 \
  --termination-grace 5
```

所有时间单位都是秒。超时后会终止对应进程组并继续其他任务；预算耗尽后未
启动的 pass、shard 或 TU 会记录为 `unscheduled`。

## 10. 配置文件

项目配置可放在 `SOURCE/.code-analyzer.toml`，也可显式指定：

```bash
code-analyzer analyze ./project --config ./review-config.toml
```

示例：

```toml
config_schema_version = 2

[run]
output_root = "./reports"
profile = "exhaustive"
shareable_export = true
termination_grace_seconds = 5

[source]
include = ["**/*"]
exclude = ["fixtures/**"]
follow_symlinks = false
respect_gitignore = false
hash_algorithm = "sha256"

[build]
compile_database_mode = "auto"
c_standard = "c11"
cpp_standard = "c++20"
cppcheck_platform = "unix64"
include = ["include"]
system_include = []
define = ["PRODUCT=1"]
undefine = []
assist = "propose"            # off | propose | auto（8.1 节）
assist_rounds = 1
assist_probe_units = 12
approval_timeout_seconds = 0  # 0 = 一直等操作者
stub_headers = true

[[build.overrides]]           # 子树专属的 include / define
match = "platform/ext/target/arm/rse/**"
include = ["platform/ext/target/arm/rse/common/partition"]

[review]
enabled = true
fail_on = "none"
max_markdown_findings = 200

[tools.cppcheck]
enabled = true
executable = "cppcheck"
timeout_seconds = 7200

[tools.flawfinder]
enabled = true
executable = "flawfinder"
timeout_seconds = 1800

[tools.splint]
enabled = true
executable = "splint"
tu_timeout_seconds = 60
total_timeout_seconds = 14400
scope = "auto"
jobs = 1
heartbeat_seconds = 10
mode = "weak"                 # weak | standard | checks | strict
report_reserved_names = true
try_to_recover = true
skip_system_headers = true
```

配置优先级是：内建默认值、小于 `SOURCE/.code-analyzer.toml`、小于显式
`--config`、小于 CLI 参数。TOML 路径相对于配置文件，CLI 路径相对于当前
工作目录。

## 11. 查看结果

运行目录主要包含：

```text
manifest.json
index.html
review/summary.json
review/summary.md
inputs/
logs/runner.log
tools/cppcheck/
tools/flawfinder/
tools/splint/
exports/<run-id>-shareable.zip
```

- `index.html`：完整离线仪表盘（检测报告版式，中英文界面可一键切换），首屏
  为判定横幅（运行状态印章、发现总数与严重度构成条、报告完整性、质量门禁、
  源码稳定性、分析上下文与降级原因），另含执行状态、覆盖率、分析单元完成/
  失败/超时分解、findings、diagnostics、评分等级与规范化严重度按证据上下文
  的构成条、文件×严重度矩阵、top rules、CWE、nearby overlap、原生等级列、
  筛选、排序、分页和原始证据链接。评分参考文档的元数据不再在页面显式展示，
  仅保留在内嵌数据与 `review/summary.json` 中。
- `review/summary.json`：review schema v2 的完整派生数据；schema v1 仍可由
  Dashboard 读取。
- `review/summary.md`：适合文本审阅的摘要。
- `manifest.json`：正式、机器可读的执行契约。
- `tools/cppcheck/*/report.xml`：Cppcheck 原始报告。
- `tools/flawfinder/*/report.sarif`：Flawfinder 原始报告。
- `tools/splint/*/report.csv`：Splint 原始报告。
- `exports/*.zip`：机器路径、用户名和主机路径脱敏后的共享包。非核心坏报告会
  被安全省略并记录，导出状态为 `partial`。
- `inputs/sanitizer-map.private.json`：只在私有目录保存，不进入 ZIP。

共享 ZIP 仍可能包含源码片段和业务内容，分享前需要自行评估。

### 代码审查分级参考

报告的代码审查分级参考为
`datas/NXP_iMXRT700-AVA_TP_v1.1 (1).pdf`（SHA-256：
`54c9cff44e72b489ab95f5f309ee9043508cc7657fb662092c6fc57b19540f35`）
第 7 章，重点采用 7.4.1 “Security Levels”和 7.4.2 “Issue
Categorization”（PDF 第 26–29 页）的四级定义：`Information`、`Style`、
`Warning`、`Error`。

`review_level` 只对原生等级名称完全匹配上述四级的 finding 直接映射；
Flawfinder 数值风险等级、Splint 以及其他工具专用等级标为 `unmapped`，并保留
`original_severity` 和既有 normalized `severity`。Dashboard 以参考分级作为
findings 的主要维度（构成图、筛选与列），参考文档本身的元数据只保留在
`review/summary.json` 与内嵌数据中，不在页面显式展示；`--fail-on` 仍使用
normalized severity，以保持现有配置兼容。PDF 明确要求结合人工核验，因此任何
工具等级都不自动等同于已确认漏洞或误报。

### 重建离线 Dashboard

如果现有运行目录中的 `index.html` 缺失或来自旧版本，可只重建 Dashboard，
无需重新执行任何分析器：

```bash
code-analyzer rebuild-dashboard /path/to/report-directory
```

该命令从必需的 `manifest.json` 和可选的 `review/summary.json` 生成新的
`index.html`，并同步 manifest 中该页面的大小和 SHA-256。其他 artifacts、
运行状态、退出码和原生 XML/SARIF/CSV 证据不会改变。参数必须是解压后的完整
运行目录；共享 ZIP 不会被原地修改。

### 恢复完整派生报告

如果旧运行因为单个坏 XML/SARIF/CSV 导致 review、Dashboard 或共享导出缺失，
可执行：

```bash
code-analyzer recover-report /path/to/report-directory
```

恢复只读取 manifest、source inventory 和有效原生 artifacts，不运行分析器、
不修改源码或原生证据。它重建 schema v2 review、Markdown、Dashboard，并创建
带 recovery 时间戳的新共享 ZIP；旧 ZIP 不会覆盖。原扫描的工具状态、整体状态、
退出码及开始/结束时间保持不变，manifest 另记恢复审计和派生文件 SHA-256。
成功时退出 `0`，stdout 只输出恢复后的 `index.html` 绝对路径；无效目录退出 `2`。

## 12. LLM 专家 scanner（第二条检测路径）

LLM 层默认**关闭**：一次可能耗时数小时的扫描，绝不能是 `analyze .` 顺手触发的结果。
启用后，六个专家 scanner 各自独立复审每一个扫描单元——彼此不可见，也看不到静态工具
的结果。它们是**第一层检测器**，不是静态结果的复核者。

| Scanner | 范围 |
|---|---|
| `llm-memory-safety` | 空间/时间：越界、不安全拷贝、空指针、生命周期、未初始化、栈使用 |
| `llm-undefined-behavior` | 算术/语义：整数溢出、符号与宽度转换、对齐与别名、移位与求值顺序 |
| `llm-resource-error` | 资源泄漏、错误路径未清理、未检查返回值、句柄误用 |
| `llm-security` | 认证、输入校验、协议解析、硬编码密钥、信息泄露、固件更新、调试后门、密码学 |
| `llm-firmware-concurrency` | ISR 竞态、`volatile`、原子性、RTOS 同步、看门狗、MMIO、DMA、超时、复位 |
| `llm-logic` | 闭合四类：`state-machine` / `inverted-condition` / `dead-code` / `unreachable-branch` |

### 12.0 选 provider profile

内置三个 profile，各自只提供 `endpoint` / `model` / `api_key_env` 三个默认值，任何显式设置
的同名键都优先于它：

| profile | 端点 | 模型 | 源码离开本机 |
|---|---|---|---|
| `gpu-host`（默认） | SSH 隧道后的本机 `11435` | `qwen3.8:27b` | 否 |
| `gpu-host-uncensored` | 同上 | `qwen3_8_uncensored:latest` | 否 |
| `openrouter` | `openrouter.ai/api/v1` | `stealth/ox-alpha` | **是** |

`gpu-host-uncensored` 是同一台机器上换一个未做安全对齐的模型。被扫描的源码按定义就是
「漏洞形状」的——一个写全的缓冲区溢出正是 memory-safety scanner 要看的东西——对齐模型
可能以拒答回应，而拒答在解析层就是一份不可解析的响应，整个单元作废。用哪个模型评审代码
是操作者的决定，每次运行的 `manifest.json` 都记录了实际用的是哪一个。

其它 provider 用 `--llm-endpoint` / `--llm-model` 直接指定即可，不需要新 profile。

### 12.1 先体检，再扫描

```bash
code-analyzer llm-doctor ./project --llm-profile gpu-host
```

它会列出端点上的模型、确认配置的模型确实在其中、核对**回复上盖的模型名**是否就是它
（这两件事不是一回事：端点可能列出 A 却用 B 回答）、比较端点实际提供的 context window
与配置值（更小的窗口会**静默截断** prompt，scanner 会去评审一段被砍掉的代码）、实测一次
请求的 tok/s，并按本次源码树的确定性单元计划估算全扫壁钟。任一项不通过时退出码 `20`。

### 12.2 扫描

```bash
code-analyzer analyze ./project --llm --llm-profile gpu-host
```

预算有四道闸：单元步数、模型往返次数、token 账本、总壁钟 deadline。任何一道用尽时，
剩余单元记为 `unscheduled` 并如实写进覆盖率——**不会**截断上下文去硬塞。
`total_prompt_tokens` / `total_completion_tokens` 是**单个 scanner** 的基数，未显式设置
时按启用 scanner 数线性放大；显式设置则原样使用。

### 12.3 续扫与验证

```bash
code-analyzer llm-resume ./reports/<run>     # 补扫 unscheduled / interrupted 的单元
code-analyzer assess     ./reports/<run>     # 第二层 validator 对关联候选逐个判定
```

`llm-resume` 重放该次运行**自己存下的 prompt**（`llm/units/<unit_id>.json`），而不是
按今天的源码重新规划——否则同一个 unit_id 下会混进不同的代码。它确实会调用 scanner，
因此在 manifest 里标记 `analyzers_invoked: true`，与永不调用分析器的 `recover-report`
明确区分。

`assess` 产出 `audit/assessment.json` 中的 `verdict`：`CONFIRMED` / `LIKELY` /
`UNCERTAIN` / `FALSE_POSITIVE`。它**永不**改动 `review/summary.json`，也不影响退出码。

### 12.4 门禁与章程

LLM 发现在 `review/summary.json` 中带 `gate_eligible: false`，默认**不影响退出码**——
一条幻觉出来的 critical 不该让任何人的流水线失败。团队若为自己的仓库明确选择了另一种
取舍，可以打开：

```toml
[review]
fail_on = "high"
gate_includes_llm = true
```

### 12.5 源码会离开本机吗？

第三方端点还有两件事要知道：`[llm] reasoning = "low"` 之类的推理档位会作为请求参数
传给 provider（始终思考的模型拒绝 `off`，思考 token 计入 `max_completion_tokens`，
给足 4000 以上）；`jobs` 超过 provider 的并发配额时会收到 HTTP 429，单元以
`provider RATE_LIMIT` 失败，运行中按 `-` 降低并发、按 `r` 重试即可。


用 `gpu-host` 这类本地 profile 时不会。切换到第三方 profile（如 `openrouter`）时，
被扫描的固件源码会发送给该服务商及其背后的模型提供方；CLI 与 `llm-doctor` 都会打印
这条警告。API key 只通过**环境变量名**配置（`api_key_env`），绝不写进 TOML、
`manifest.json`、`inputs/effective-config.toml` 或共享 ZIP。

## 13. 退出码

| 退出码 | 含义 |
|---:|---|
| `0` | 所有请求且适用的工具完成，源码稳定，脱敏导出成功或已禁用 |
| `1` | 完整运行命中显式 `--fail-on` severity gate |
| `10` | 至少有一个有效报告，但某些工具、子单元、源码稳定性或导出有问题 |
| `20` | 没有请求且适用的工具产生有效报告 |
| `2` | CLI、配置、输入、compile database 或输出路径错误 |
| `130` | 用户中断 |

默认 `--fail-on none`，findings 不影响退出码。只有运行原本完整时才应用显式
severity gate；错误优先级为 `130 > 2 > 20 > 10 > 1 > 0`。可用
`--no-review` 禁用派生层，或用 `--fail-on medium|high|critical` 启用门禁。
