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

## 3. 对话界面

在一个源码目录里直接运行 `code-analyzer`（交互式终端），或显式指定：

```bash
code-analyzer
code-analyzer tui /path/to/project
code-analyzer tui /path/to/project --config ./review-config.toml
```

界面就是一条对话：**一个滚动的记录 + 一个输入框**，没有表单，没有模式。你说的每
一句话是一个块，工具的每一次回答是一个块，一次扫描是一个可以展开的块，它中途要问
你的每一个问题也是同一条记录里的一轮。全部可以往上翻。

界面至少需要 80×24，且必须在 TTY 中运行；非 TTY 的无参数或 `tui` 调用退出 `2`。

### 3.1 谁在理解你输入的那句话

**只有两种输入走 0ms 的确定性快路**，因为只有这两种无歧义：

| 你输入 | 解析为 | 耗时 |
|---|---|---|
| `/scan ~/fw --llm-jobs 4` | 斜杠命令。**尾巴交给 `code-analyzer analyze` 自己的 parser**，所以它接受的 flag 与子命令逐字相同，`--llm-jobs 0` 也用同一句话拒绝 | 0ms |
| `~/fw/tfm` | 裸路径 → 提议扫描它（**只是提议**，仍要确认） | 0ms |
| **其余一切** | **自动交给模型**，不需要任何前缀 | 21–31 秒（实测） |

以前还有第三种：一张关键词表，在整行任意位置匹配动词。它被**删除**了。它是在用查表
冒充理解，而且能凭一个子串启动几小时的扫描——「帮我扫描一下这个目录」里那个「扫描」。

**三条边刻意保持确定性**，因为交给模型只会更差：

- **不存在的路径**：意图模型的 skill 声明 `allowed-tools: []`，它**没有文件系统**，
  修不了 `~/fwm` 这种错字。把最常见的键盘错误变成最贵的操作是荒谬的。
- **含 `manifest.json` 的目录**：五个读法、其中四个会写。模型拿到的输入和解析器一模一样，
  只会花二三十秒在同一份目录里挑同样五个候选。只升级**呈现**，不升级读者。
- **中文没有空格**：`扫描~/fw` 是**一个 token**，含 `/` 和 `~`，会被裸路径通道认领并
  死在「路径不存在」——而这正是中文操作员最自然的写法。所以加了 CJK 判据。

`parse()` 仍然不 import textual / `llm.*` / harness：`ASK` 是**数据**，这个模块从不调
`gate()` 或 `propose()`。所以主干在什么都没装、什么都连不上时依然回答。

### 3.2 模型能拿它理解到的东西做什么

目录（catalogue）从注册表**生成**，所以模型说得出的 action 一定存在。护栏逐条：

- 目录之外的 action 按名字丢弃；
- 提议的配置改动必须是真实叶子、可写、且过 `validate_config`；
- `llm.profile` / `llm.endpoint` / `llm.api_key_env` **一律拒绝**——三者都能通过校验，
  却会悄悄把会话指向计费的第三方，而计费警告读的正是 `llm.profile`，模型等于能关掉
  关于它自己的警告；
- **每一条丢弃都写明理由**；最多三步。

**只读的直接跑。** 一个步骤的 action 若声明了**不写入、不花钱、不阻塞**，就直接执行——
按代码审计，这恰好是 `doctor` / `preflight` / `config` 三个。其余全部确认一次，并在确认框里
**点名将要写入的文件**。带 `/set` 的步骤**永不自动执行**，无论其 action 策略：配置是实测中
模型最高频的错误面（它发明过 `llm.scanners=['memory-safety']`），而 `validate_config` 挡得住
不存在的叶子，挡不住一个合法但不是你要的值。

执行的永远是**你本来也能敲出来的那条斜杠命令**，所以确认检查只有一处，自动执行路径绕不过它。

**模型只路由，不回答。** 提不出操作时，块里显示它自己说的不确定之处，并指向 `/help`。
屏幕上永不出现模型的自由散文。

模型拿到的是：目录、当前路径、与默认值不同的配置项、以及被围栏标成 DATA 的那句话。
**拿不到 finding、拿不到分析器输出、拿不到源码**——`docs/platform-architecture.md` §2.3
那条硬规则不因这条通道放宽，skill 也不授予 `fs`。

### 3.2.1 等待、打断、排队

一次往返实测 **21–31 秒**（把 skill 内联进提示词之前是 58–79 秒——模型当时要调七次
`skill` 工具去取自己的说明，把六步预算全烧光）。所以等待必须诚实：

```text
› 帮我看看哪些单元最值得先扫
  ↳ → 模型
  ⠹ 正在理解这句话… 24s · 等待模型的第一个 token · Ctrl+C 放弃
    上次 21.7s（本会话测量）

› 然后扫一下 ~/fw
  ↳ 排队中（1）
```

- 转圈的是**运转指示**，帧和流程图、CLI 用的是同一套（一个产品，一种待机动画），
  由 5Hz 的定时器推进：只靠秒表的话，一秒才动一次的计数器和卡死的计数器分不出来。
  底部状态栏同步转同一帧。`CODE_ANALYZER_NO_ANIMATION=1` 或 `TERM=dumb` 时它不再转动，
  但仍显示一个 `●`——「在跑」这件事不该因为关掉动画就消失。
- 两个阶段（`探测端点` / `等待模型的第一个 token`）都为真，**并且真的会切换**：闸门探测
  实测毫秒级，其后整整二三十秒都在等第一个 token，所以 lane 在发出请求那一刻回调前端改写
  这一行。此前它整段时间都写着「探测端点」。
- 秒表本身由已有的 1Hz 定时器保底，动画关掉时仍然走字。
- 「上次 N 秒」是**测量值并标注为测量**；首次提问不显示。**不发明 ETA。**
- `Ctrl+C` 是**脱手不是杀死**：`HarnessRuntime` 只在通知回调里轮询取消谓词，SDK 没有
  cancel 句柄，所以实测 18–52 秒的首 token 窗口**真的打不断**。界面因此说明
  「请求可能仍在提供方那边跑，晚到的回答会被丢弃」，第三方计费时再加一句。
  全会话至多**一个**在飞的 provider 请求。
- 思考期间**可以继续敲**：自由文本排队并显示位置，`/命令` 与运行控制不排队、立即执行，
  `Esc` 清空队列。
- **不画运行块的操作也有指示**。`/doctor`、`/llm-doctor`、`/preflight`、`/serve` 这几个
  不是 `long_running`，屏幕上没有流程图可转；它们运行时底部状态栏显示
  `⠹ 运行中 12s · Ctrl+C 取消`。`/llm-doctor` 是一次真实生成（实测 18–52 秒），此前
  这段时间里屏幕上没有任何东西在动。

### 3.2.2 模型不可达时

四条机制：路由闸门用 `ROUTE_PROBE_SECONDS = 3.0`（扫描 preflight 仍是 15 秒）；
请求超时 `ROUTE_REQUEST_TIMEOUT = 120.0`（不再继承 600）；闸门结果按
`(endpoint, model)` 缓存（up 60 秒 / down 20 秒，都是**估算**；一次成功的回答直接刷新它）；
`CODE_ANALYZER_NO_MODEL=1` 在任何 socket 之前短路。

实测：网络黑洞时，**三句话共 6.4 秒**（此前 15 秒的超时要付两次、每句 30 秒，共 90 秒）。

```text
模型不可达：<原因>
  离线仍然可用：/help 列出全部命令；/scan <目录>、/preflight <目录> 直接可用；
  直接输入一个目录也可以。/llm-doctor 重新探测。
  你可能想要：/scan ~/fw      ← 仅当整行第一个 token 精确等于某个注册表名/别名
```

同一原因**只说一次**，重复时只有一行「模型仍不可达（同上）」——但**提示会保留**，因为它
说的是这一句话而不是这台主机。那条提示不是关键词表复活：它只精确匹配 token 0、返回的是
一个**字符串**而不是 `Intent`、`parse()` 够不到它、且必须你按回车。

**已接受的退化**：「扫描 ~/fw」在 GPU 主机关机时不再可用，只有 `/scan ~/fw` 可用。

ask 通道的证据写在 `~/.code-analyzer/ask`（或 `CODE_ANALYZER_ASK_ROOT`），保留最近 50 轮
——**不在你当前所在的目录**，否则每个错字都会在别人的项目里建一棵树。


### 3.3 配置

`/config` 列出已设的项与它们的来源（default / 某个 TOML / session），
`/config --all` 连同 59 个高级项一起列出，`/set <路径> <值>` 可以改 83 个 schema
叶子中的任意一个。值在你输入的地方就被校验——`FieldSpec.minimum` 第一次真正被读，
`llm.jobs 0` 当场被拒而不是留到 `validate_config`。

一处**诚实的例外**：`build.overrides` 是 83 个里唯一的表格型配置
（`[[build.overrides]]`），一行编辑器表达不了它，所以 `/set` 明确拒绝并说明只能在
TOML 里改，而不是假装能改。

`Ctrl+S` 写 TOML 快照（同目录临时文件 + 重载一致性校验 + 原子替换）。

### 3.4 运行块

一次扫描是对话里的一个可折叠块。折叠时是一行活摘要；`Enter` 展开是完整的流程图、
泳道进度条、速度条、逐 scanner 面板和模型自己的对话记录（`F6` 显示发送的提示词）。

```text
▼ 正在扫描 · llm-memory-safety copy.c · 85% · 已运行 03:32 · 静态 3/3 · LLM 1/2
     ✓ 发现                       1 文件 · 无 compile-db
   ├ ✓ cppcheck                 单元 1/1 · 4 findings
   ├ ⠦ llm-memory-safety        单元 1/2 · copy.c (medium)
   └→ ○ 修补 → ○ 稳定 → ○ 审查 → ○ 关联 → ○ 导出 → ○ 报告
   静态分析    ██████████████████████ 100%  3/3 工具
   LLM 扫描    ███████████░░░░░░░░░░░  50%  1/2 单元
   ⚡ qwen3.8:27b · 18.8 tok/s（估算） · 峰值 36.0 · 输入 15,772 · 输出 427 tok（测量）
```

**两种速度，永不混淆**：回复还在流入时只有字符可数，按 `字符/4`（预算用的同一除数）
给**估算**；provider 报回自己的 `outputTokens` 后换成 `输出 token / 会话耗时` 的
**测量**值。窗口过期就什么都不显示——停住的 provider 不该看起来很快。

运行结束后块折叠成一行：状态、退出码、用时、报告目录；历史留在上面可以往上翻。
**流程图是用这次运行真正使用的配置画的**——旧界面用的是会话配置，于是
`--llm-scanner llm-memory-safety` 会画出五个没人要的 scanner 一直停在「等待」。

### 3.5 运行中的按键与命令

| 输入 | 作用 |
|---|---|
| `/pause llm` `/resume static` | 暂停 / 恢复一条泳道（在下一个单元边界） |
| `/skip <producer>` | 跳过某个 producer 尚未开始的单元 |
| `/jobs 4` | 调整 LLM 并发 |
| `/retry` | 把未得到模型回答的单元作为新一轮重扫 |
| `/decide` | 查看待决策的构建上下文补丁 |
| `Ctrl+C` | 放弃正在进行的理解 → 取消正在跑的操作 → 回答待答问题 → 退出（按此顺序） |
| `Esc` | 回到输入框；输入框为空时清空排队 |
| `F2` | 展开 / 折叠最后一个运行块 |
| `F5` / `F4` | 日志面板 / 日志过滤 |
| `F6` | 显示 / 隐藏发送给模型的提示词 |

这些以前是单字母键（`p P s + - d r`）。现在是可以被发现、补全、写进日志的名字——
每一次操作仍然以 `control/*` 事件写入 `events.jsonl` 与 `logs/runner.log`。

**底部状态栏**（输入框上面那一行）报告随时都想知道、又不值得占一个对话块的东西：模型思考
的秒数、运行进度百分比与 LLM 泳道是暂停还是在跑、`排队 N`、`● 配置未保存`、以及当前
`Ctrl+C` 会做什么。它一直是这么写的，但直到 2026-09-04 都**看不见**——它和 `Footer` 同样
`dock: bottom`，而 `Footer` 不让出最后一行，于是整条状态栏被画在页脚下面。现在两者各占一行。

### 3.6 对话记录落盘

整场对话写进 `~/.code-analyzer/sessions/<时间戳>.jsonl`：你输入的、解析成了什么
action、确认与否、结果指向哪个报告目录。与 `events.jsonl` 同性质——**进度日志，
不是证据**，不进共享包，不进 artifact 索引。`CODE_ANALYZER_NO_JOURNAL=1` 关掉它。
主目录不可写时它自动降级为不记录，绝不因此挡住一次扫描。

### 3.7 一处定义，两个前端

对话能做的每一件事，CLI 也能做，走的是同一个 action 注册表：
`doctor`、`llm-doctor`、`preflight`、`compile-db`、`analyze`、`llm-resume`、
`tools-resume`、`assess`、`rebuild-dashboard`、`recover-report`、`serve`、`config`。
其中 `preflight` 与 `config` 是这次重构才有的子命令。

`code-analyzer <你说的一句话>` 也走同一个解析器，但**自由文本一律拒绝**（在 TTY 上也拒绝：
一次性 argv 不是对话），提示改用 `code-analyzer tui`。理由未变——无人值守绝不能调用
provider，provider 故障绝不能改变退出码——只是面从一个字面的 `/ask` 变成了每一个不认识的词。
**裸路径在非 TTY 下只打印它将要运行的那条命令然后退出 2**：一次扫描不是副作用。

**确认策略只影响对话界面。** `cli.py` 从不读 `Action.confirm`（`cli.py:305-312`），
无人值守的退出码不能因为审计而改变。

### 3.8 每个 action 会做什么（审计结论）

`confirm` 与 `auto_run` 是从声明的**效果**派生出来的属性，不是手写的字段——手写的字段会和
调用树不一致，而且确实不一致过：`rebuild-dashboard`、`recover-report`、`serve` 三个都曾标着
「从不确认」，却在重写 `manifest.json`（节点真相的唯一来源）或开着一个不会关的端口。

| action | 写入 | 花钱 | 阻塞 | 手敲时 | 模型推断时 |
|---|:--:|:--:|:--:|---|:--:|
| `doctor` | — | — | — | 直接跑 | **直接跑** |
| `preflight` | — | — | — | 直接跑 | **直接跑** |
| `config` | — | — | — | 直接跑 | **直接跑** |
| `llm-doctor` | — | ✔ | — | 直接跑 | 要确认 |
| `compile-db` | CWD 与源码树内 | — | — | 要确认 | 要确认 |
| `scan` | 输出目录 + 缓存 | ✔ | — | 要确认 | 要确认 |
| `llm-resume` | 报告目录六个派生文件 | ✔ | — | 要确认 | 要确认 |
| `tools-resume` | 报告目录 | ✔ | ✔ | 要确认 | 要确认 |
| `assess` | 报告目录 | ✔ | — | 要确认 | 要确认 |
| `rebuild-dashboard` | `index.html` + `manifest.json` | — | — | 要确认 | 要确认 |
| `recover-report` | 六个派生文件 + 每次一个新 ZIP | — | — | 要确认 | 要确认 |
| `serve` | — | — | ✔ | 要确认 | 要确认 |

两栏不同，是因为同意有两种：**手敲即同意**（点了它的名），**模型推断不算同意**。
`llm-doctor` 不写文件，但它是一次真实的生成请求——计费、实测 18–52 秒——所以你敲它可以，
模型替你敲不行。

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
| `gpu-host`（默认） | 本网段 GPU 主机 `192.168.5.10:11434` | `qwen3.8:27b` | 否 |
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

运行**中**，TUI 的 `r` 键（或 `serve` 页面的"重试 LLM"）把未得到模型回答的单元——
断路器或预算未调度的、传输/提供方失败的——作为新一轮在本次运行内重跑，断路器重新
合上，`llm/plan.json` 记一条 `decided_by: "operator"` 的轮次。运行**结束后**同样的
单元交给 `llm-resume`。


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
