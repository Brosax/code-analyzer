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

- `index.html`：完整离线仪表盘（检测报告版式，中英文界面可一键切换），含总
  体判定横幅（运行状态、报告完整性、质量门禁、源码稳定性、分析上下文与降级
  原因、运行时长）、执行状态、覆盖率、分析单元完成/失败/超时分解、findings、
  diagnostics、评分等级与规范化严重度按证据上下文分开统计、top rules、CWE、
  nearby overlap、原生等级列、筛选、排序、分页和原始证据链接。
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
`original_severity` 和既有 normalized `severity`。Dashboard 将参考分级作为主视图，
同时保留 normalized severity 的筛选和展示；`--fail-on` 仍使用 normalized
severity，以保持现有配置兼容。PDF 明确要求结合人工核验，因此任何工具等级都
不自动等同于已确认漏洞或误报。

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

## 12. 退出码

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
