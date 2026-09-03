# 智能代码审查平台架构：融合版设计

本文档回应「Multi-Agent Code Review Platform」规范的 18 项交付物。
它不是从零设计，而是把规范逐项对照本仓库的现状：哪些已经存在，哪些可以扩展，
哪些与既有契约冲突，哪些是规范自己原则意义上的过度设计。

每一节标注判定并锚定到真实的 `file:line`。判定写于设计时（HEAD `1a3a370`，296 tests）；
**P1–P3 已实现**，实现后的状态见每节的「已交付」注记与 §18 的路线表（HEAD `cdfeff2`，410 passed，ruff 干净）。
本文经过一轮对抗性评审（逐条核对代码）；评审发现的错误已订正，并在相应处标注「评审订正」。

| 判定 | 含义 |
|---|---|
| EXISTS | 已实现，引用代码 |
| EXTEND | 已有可扩展的形态，说明怎么扩、代价多少 |
| CONFLICTS | 与既有契约/不变量/测试矛盾，给出保留契约的化解方案 |
| NEW | 确实不存在，给出规模与接入缝 |
| OVERREACH | 违反规范自己的"不要为了 multi-agent 而复杂化"，给出更便宜的等价物 |

前置阅读：`docs/llm-scan-architecture.md`（既有设计，其 Phase 0–1 已实现）。

---

## 0. 先定词汇

规范与仓库对同一个词的用法不同，不先定词汇后面每一节都会歧义。

| 词 | 规范的用法 | 仓库的用法 | **本文采用** |
|---|---|---|---|
| Skill | 静态工具的包装（`cppcheck/SKILL.md + runner.py`） | 给模型看的 Markdown 指令（`llm/skills.py:49`），被挂为 agent 的 skill root（`harness/cordis.py:211-217`，`includeDefaultRoots: false`） | **仓库用法**。照搬规范会让工具包装文档**可被扫描模型调用**——正是 `includeDefaultRoots: false`（`cordis.py:217`，**已验证**的上游控制）堵住的注入洞，且炸掉 `tests/test_skills.py:79,93-103` |
| Scanner | 静态工具 + AI agent 的并集 | **只指 LLM**：`summary["scanners"]`、`[llm] scanners`（`config.py:58`）、`--llm-scanner`（`cli.py:76`） | **仓库用法** |
| — | — | `PRODUCER_ORDER`（`tools/__init__.py:13`）= 静态 + LLM 的并集 | **Producer** = 规范的"Scanner" |
| — | — | `tools/__init__.py:1` 自称 "adapters" | **Adapter** = 规范的"Skill"（静态工具包装） |
| — | — | 不存在 | **Producer Manifest** = 新增的声明块。为避免与 `manifest.json` 混淆，本文提到运行清单时**一律带扩展名** `manifest.json`；不带扩展名的 Manifest 只指 Producer Manifest |

后文一律：**Producer**（任何产出 finding 的东西）、**Adapter**（静态工具包装）、
**Scanner**（LLM producer）、**Skill**（dsh 模型指令）、**Manifest**（声明元数据）。

---

## 1. 整体架构 — EXISTS，扩展三条泳道

既有设计 §1 的两条 pipeline 与 §0.3 的两层证据模型不变。本规范增加三条泳道：
事件流与实时视图、有界重规划、审计层。

```text
                               User / CI
                                  │
                  ┌───────────────┼────────────────┐
                  │               │                │
                  ▼               ▼                ▼
          code-analyzer      code-analyzer    code-analyzer
             analyze            assess            serve
                  │               │                │
                  ▼               │                │
     ┌── 确定性主干 runner._analyze (runner.py:43) ──┐     │
     │                                                 │     │
     │  inventory ─ compile-db ─ risk ─ unit plan      │     │  SSE
     │         │                                       │     │  tail
     │   ┌─────┴──────────────┐                        │     │
     │   ▼                    ▼                        │     │
     │ Pipeline A          Pipeline B                  │     │
     │ 静态 Adapters       LLM Scanners               │     │
     │ cppcheck            llm-memory-safety           │ ──► events.jsonl ──►
     │ flawfinder          llm-security                │     │
     │ splint              llm-firmware-concurrency    │     │
     │   │                 (+ resource-error, ub,      │     │
     │   │                    logic —— P3)             │     │
     │   │                    │                        │     │
     │   │          ┌─────────┘                        │     │
     │   │          │  有界重规划 (P4, 默认 0 轮)        │     │
     │   │          │  llm/plan.json 为证据             │     │
     │   ▼          ▼                                  │     │
     │  review/summary.json  ← 冻结：不合并、不判误报    │     │
     │  manifest.json        ← 节点状态的唯一来源        │ ──► graph(manifest) ──► DAG
     │  review/summary.sarif ← CI 接入                  │     │
     └─────────────────────────────────────────────────┘     │
                          │                                   │
                          ▼                                   │
                  ┌── audit 层 ──────────────────┐            │
                  │ Correlator  → candidates     │ ← analyze 内，确定性，零模型
                  │ Validator   → verdict 标签    │ ← assess 子命令，显式调用
                  │ audit/assessment.json        │            │
                  │ "non-authoritative"          │            │
                  └──────────────────────────────┘            │
                          │                                   │
                          ▼                                   ▼
                  index.html（离线，冻结契约）        实时页（serve，链接到 index.html）
```

三条原则贯穿全文：

1. **主干确定性。** `analyze .` 的输出完全可复现；模型只在显式开启的点介入。
2. **证据层冻结、意见层追加。** `review/` 永不合并、永不删除；`audit/` 明确非权威。
3. **`manifest.json` 是节点状态的唯一来源。** DAG、实时页、离线页都从它派生，不另存。
4. **Correlator 是确定性的，跑在 `analyze` 内；Validator 调模型，只在显式的 `assess` 内。**
   （评审订正：初稿的 §1 图与 §16 时序图对此不一致；既有设计 §10.4 把关联也归给 `assess`，
   本文改为关联进 `analyze`——它零模型、字节稳定，放在主干上才能让 origin 指标
   在不调模型时就可用。`assess` 只负责 verdict。）

---

## 2. Main Agent 的职责与决策逻辑 — EXTEND；字面意义的 Main Agent 是 OVERREACH

### 2.1 规范的 Main Agent 做的大多数事不需要模型

规范把下列决策归给 Main Agent。在本仓库它们全是**确定性**的，且已有测试：

| 规范说 Main Agent 负责 | 现状 | 位置 |
|---|---|---|
| 分析项目语言、目录、规模 | 扩展名判定语言、哈希、清单 | `inventory.py:34 discover()` |
| 判断哪些文件值得检查 | 风险分级 + 机器可读理由 | `llm/risk.py:104 classify()` |
| 判断启用哪些检查能力 | 工具可用性探测与兼容性 | `doctor.py:24 probe_all()`、`preflight.py:32` |
| 制定 Code Review Plan | 扫描单元计划，**字节稳定** | `llm/units.py:51 build_plan()`；`tests/test_llm_index.py:287` 钉死 |
| 调度工具与 agent | 11 阶段主干 | `runner.py:43 _analyze()` |
| 收集所有结果 | 派生 review | `review.py:36 build_review()` |

让模型做这些只引入不确定性、成本和一个新的注入面（§2.3），
违反规范自己的"优先设计简单、可靠、可扩展的架构"。

### 2.2 真正需要判断力的决策点 ≤ 3 个，默认路径一个都不触发

| 决策点 | 期 | 触发条件 | 输入 | 输出 |
|---|---|---|---|---|
| **单元扫描** | 已建 | `[llm] enabled = true` | 扫描单元 + 上下文 | findings |
| **验证判定** | P2 | 显式 `code-analyzer assess` | candidate + 源码 + 全部证据 | `verdict.label` |
| **有界重规划** | P4 | `[llm] max_replan_rounds > 0` | **只看结构化信号** | 动作词汇表中的一个动作 |

可选的自然语言前端（"帮我重点看内存安全和硬件相关问题"）放在 `_analyze` **之外**。

**2026-09-03 修订（用户决定，已交付）。** 原文把该前端限制为"只能产出受约束的 config
patch（`[llm] scanners`、`risk_overrides`、`min_tier`）"。这一条**有意放宽**：`/ask`
（`llm/propose.py`）的模型可以提议 action 注册表里的**任何** action。放宽的边界与仍然
成立的部分：

- **主干依然无感知。** 模型产出的是一个待确认的提议；勾选后它被转成"操作员本来也能敲出
  来的那条斜杠命令"，走的是与手敲**完全相同**的代码路径。`runner._analyze` 不知道有
  这条通道。
- **§2.3 不放宽。** 用户选的是"可提任何 action"而**不是**"还能读已完成的报告"，所以
  finding 的自由文本**从不**进入任何规划模型的输入。`tests/test_propose.py` 用一个
  确实含 findings 的运行目录钉死这一点。skill 的 frontmatter 也不授予 `fs`
  （`tool_allowlist` 只给 `skill`），所以意图模型能看到的唯一不可信文本就是操作员
  自己那句话。
- **护栏**：目录（catalogue）从注册表生成，模型说得出的 action 必然存在；目录外的按
  名字丢弃；提议的配置改动必须是真实叶子、可写、且过 `validate_config`；目标不存在也
  丢弃；每一条丢弃写明理由；每一步默认不勾选，最多三步。与 build-context configurator
  同构。
- **provider 不可达是闸门而非异常**（`propose.gate`）：`/ask` 说明原因，确定性主干
  不受影响。非 TTY 下 `/ask` 直接拒绝，免得一次 provider 故障改变无人值守的退出码。
- **延迟是这条设计的理由之一。** 实测一次 `/ask` 58–79 秒（qwen3.8:27b，2026-09-03）；
  "把并发改成 4"不该等半分钟，所以确定性解析器是主干而不是回退。

**2026-09-03 二次修订（用户决定，已交付）：方向反过来。** 上一条把确定性解析器定为主干、
模型定为兜底。用户要的是相反的：输入框就是 agent 输入框，任何内容都自动交给模型理解，
不需要 `/ask` 前缀。现在：

- **只有两种输入还走确定性快路**：斜杠命令，和一个存在的裸路径。其余一切自动到模型。
  上一版的关键词简写表（`Action.keywords` + `intent._shorthand`）**删除**——它在整行任意
  位置匹配动词，能凭一个子串启动几小时的扫描，是在用查表冒充理解。
- **三条边仍然确定性**，且理由不是"省事"：不存在的路径（意图模型 `allowed-tools: []`，
  没有文件系统，修不了错字）；含 `manifest.json` 的目录（五个读法四个会写，模型拿到的
  输入与解析器一模一样）；以及 CJK 判据（`扫描~/fw` 是一个 token，中文不需要空格）。
- **§2.1 与 §2.3 都不受影响。** 语言判定、风险分级、扫描计划、调度、review 派生仍全是
  确定性的；finding 的自由文本仍然永不进入任何规划模型的输入，`tests/test_propose.py`
  用一个确实含 findings 的运行目录钉死这一点。
- **延迟的数字变了，结论没变。** 把 skill 内联进提示词后，一次往返从 58–79 秒降到
  **21–31 秒**——此前模型要调七次 `skill` 工具去取自己的说明，把六步预算全烧光
  （`agent step ceiling of 6 reached`）。`llm/scan.py:1001-1007` 早就发现并修过同一件事。
  即便 21 秒，"把并发改成 4"仍然不该等——所以斜杠命令仍是 0ms 的快路。
- **同意分成两个轴**：`Action.confirm`（手敲时；点名即同意，只有效果才要问）与
  `Action.auto_run`（模型推断时；不写、不花钱、不阻塞）。两者都从声明的效果**派生**，
  不是存储字段——存储字段会和调用树不一致，而且三个确实不一致过。模型可自动执行的
  只有 `doctor` / `preflight` / `config`，2026-09-04 起加上 `model`（只列模型，不生成）。

规范的流程 "理解需求 → 分析项目 → 制定计划 → 选择工具 → 执行扫描 → AI 深度审查 →
汇总 → 去重/验证 → 生成报告" 与主干一一对应，模型步骤是其中三个："AI 深度审查"
（`llm/scan.py`）、"验证"（`assess`）与"汇总"（`summarize`，2026-09-04）。前两个逐条产出，
第三个只跑一次、读的是运行自己的账本而不是源码，落在与 `assess` 同一个意见层里——
它不改证据行、不进质量门、不能移动退出码。

### 2.3 Orchestrator 是新的提示注入面

既有设计 §11.4 已把被扫描源码当作送给持有 `fs` 工具的 agent 的不可信输入。
一个读取中间结果来重规划的 orchestrator 引入**第二个**注入面：finding 的
`message` / `description` 是模型写的文本，可能被源码里的注入内容污染。

硬规则：**重规划决策只消费结构化字段**——各类别计数、severity 分布、tier 分布、
路径、`unscheduled` 数——**永不把 finding 的自由文本喂给规划模型**。

### 2.4 规模

确定性主干留在 `runner.py`；新增的是三个钩子与它们的证据落盘。估算 500–700 行生产代码。

---

## 3. Agent / Tool / Skill 的接口设计 — EXTEND ✅ 已交付（P2）

### 3.1 现状：三个 Adapter 的签名不一致

```python
# tools/cppcheck.py:14
def run(executable, source, run_dir, inventory, filtered_db, covered, config, progress, *, cancelled, unit_event, output_event)
# tools/flawfinder.py:30
def run(executable, source, run_dir, inventory, config, progress, *, cancelled, unit_event, output_event)
# tools/splint.py:19
def run(executable, source, run_dir, inventory, filtered_db, config, progress, *, compile_db_present, cancelled, unit_event, output_event)
```

因此 `runner.py:214-226` 是硬编码的 `if name == "cppcheck": … elif "flawfinder": … else:`。
新增一个静态工具今天需要改约 21 处。其中 **4 处是崩溃点**（不改就 `KeyError`）：
`runner.py:526-529`（`_incompatibility` 的字典索引，在 `try` 之外）、`review.py:55`（`parsers[tool]`）、
`doctor.py:49`、`doctor.py:140`。另有 **1 处静默误派发**，比崩溃更糟：`runner.py:226` 的 `else:`
会把任何未知名字交给 `splint.run`。（评审订正：初稿把 `runner.py:214,220` 列为崩溃点，实际它们不抛异常。）

### 3.2 Adapter 协议（P2）✅ 已交付

**实现与下面的草案有一处刻意的差异**：`Adapter` 落地为 `tools/adapter.py` 的**冻结
dataclass（字段即绑定的模块函数）**，而不是 Protocol + 三个类——三个工具模块本就是函数
的集合，包成对象只增加仪式、不增加接缝。`validate_report` 没有进协议：它今天只被各
adapter 自己的 `run()` 调用，没有外部消费者，凭空导出一个没人调的方法不是设计。
字段还多了两个实现需要的：`reported_version`（doctor 报的版本号，与 manifest 记录的
整行原文不是同一件事）与 `apt_package`。四个崩溃点已全部改为具名 `UserError`
（`tests/test_adapters.py`）。


```python
class RunContext:            # 一次运行中 adapter 需要的全部只读输入
    source: Path
    run_dir: Path
    inventory: list[dict]
    compile_db: CompileDb | None      # filtered_db + covered + present 合为一个对象
    config: dict
    progress: Callable[[str], None]
    cancelled: Callable[[], bool]
    unit_event: Callable[..., None]
    output_event: Callable[..., None]

class Adapter(Protocol):
    name: str
    def run(self, executable: str, ctx: RunContext) -> dict: ...          # 返回工具执行记录
    def validate_report(self, path: Path) -> tuple[bool, str | None]: ...
    def parse(self, source: Path, run_dir: Path, execution: dict) -> tuple[list[dict], list[dict]]: ...
    def normalize_severity(self, raw: str, scale: str | None) -> str: ...
    def probe(self, executable: str) -> dict: ...                         # doctor / preflight
```

`review.py:893 _report_integrity()` 已经把 validator 当作参数注入——它是分析层唯一一处
按值传递 per-tool 行为的地方，是这个协议的雏形。

### 3.3 LLM 侧接口已存在

| 层 | 接口 | 位置 |
|---|---|---|
| 运行时生命周期 | `HarnessRuntime`（上下文管理器、`run()`、取消、超时） | `harness/runtime.py:185` |
| 单元会话 | `run_unit()` → unit 记录 + 五个证据文件（`events.jsonl` / `request.json` / `response.json` / `findings.json` / `meta.json`） | `harness/session.py:73` |
| 输出契约 | `FINDING_SCHEMA`（`additionalProperties: False`）+ `parse_findings()` 宽松解析/严格校验 | `harness/schema.py:75,121` |
| 工具授予 | `cordis_document()`，allow-list，`FORBIDDEN_TOOLS` 含 `shell`。**注意**：文档顶层的 `tools` / `skills` / `filesystem` 段是本项目的词汇，上游 loader 是否消费**未验证**（`cordis.py:21-28` 如实记录）；已验证生效的是 `packages` 内的 `includeDefaultRoots: false`（`:217`） | `harness/cordis.py:115,86,211-217` |
| 执行模型 | `_Phase.execute_all()` | `llm/scan.py:381` |

Validator（§12）作为 `_Phase` 的另一种消费者实现，不另起炉灶。

---

## 4. Producer 注册表 — EXISTS，扩展为 Manifest

### 4.1 现状

```python
# tools/__init__.py:4-13
TOOL_NAMES     = ("cppcheck", "flawfinder", "splint")
LLM_PRODUCERS  = ("llm-memory-safety", "llm-security", "llm-firmware-concurrency")
PRODUCER_ORDER = TOOL_NAMES + LLM_PRODUCERS
```

LLM 侧：`llm/skills.py:75 skill_names()` / `:84 load_skill()` 从打包目录发现 Skill，
`pyproject.toml` 的 package-data 保证 wheel 安装时 `SKILL.md` 随包分发。

### 4.2 Producer Manifest（P2）◐ 部分交付

已交付的是**行为**部分：每个静态工具一份 `Adapter` 声明（§3.2），一次查表拿到
run/parse/severity/探测/canary/包名；`allowed-tools` 并集已接入 `cordis.py`
（`harness/cordis.py:tool_allowlist`），并记录 `granted_by` 与
`requested_unavailable`——被声明但当前可信插件树无法授予的工具（如 `lsp`）如实记为
不可用，而不是悄悄当作已授予。

**未交付**的是下面 TOML 里的元数据部分：`capabilities` / `languages` / `applies_to`
仍散在各 adapter 的代码里（`splint.py:35` 只扫 `.c`；`cppcheck.py:34-40` 的
compile-db pass + fallback）。把它们提成声明式表格是可做的，但今天没有第二个消费者，
提了也只是换个地方写同一件事。


每个 producer 一份声明块。静态工具在 `tools/<name>/manifest.toml`，
LLM scanner 复用 `SKILL.md` 的 frontmatter：

```toml
name = "cppcheck"
kind = "adapter"                 # adapter | scanner
capabilities = ["memory-safety", "undefined-behavior", "resource-leak", "api-misuse"]
languages = ["c", "cpp"]
applies_to = { suffixes = [".c", ".cc", ".cpp", ".cxx"], needs_compile_db = false }
output = "xml"
default_timeout_seconds = 7200.0
cost = "cpu-bound"               # cpu-bound | network-bound
```

三条规则：

1. **`applies_to` 由 Python 求值**，不是给模型读的散文。现有的适用性判断已是声明式的
   （`splint.py:35` 只扫 `.c`；`cppcheck.py:34-40` 的 compile-db pass + fallback），只是散落各处。
2. **manifest 的 timeout 只是 `DEFAULTS["tools"][name]`（`config.py:17`）的种子**，
   不是影子。按运行覆盖的能力（`config.py:84-94`、`cli.py:65-71`）必须保留。
3. **`LLM_PRODUCERS` 保持为声明的元组，但用测试钉住「声明 == 磁盘发现」。**
   （评审订正：初稿说"从磁盘派生"。那是循环导入——`llm/skills.py:22` 从 `tools` 导入
   `LLM_PRODUCERS`，`skill_names()` 又按 `_producer_rank` 排序；而且会让 `cli.py:76` 的 choices
   与 `config.py:58` 的默认值在 import 期做文件系统 I/O，并把 `PRODUCER_ORDER`（决定
   `review/summary.json` 的排序）从声明序变成发现序。）一个断言 `skill_names() == LLM_PRODUCERS`
   的测试已存在（`tests/test_skills.py:79`）；放进一个目录而不注册会**响亮地失败**，这就够了。
   frontmatter 的 `allowed-tools`：每次运行只有**一份** `cordis.json`（`scan.py:101-103`）被所有
   per-unit 运行时共用（`:576-584`），因此 allow-list = 启用 skill 的 `allowed-tools` 之**并集**，
   `FORBIDDEN_TOOLS` 永远减去。

"放进一个目录就注册"对静态工具要到 §3.2 的协议落地后才成立。在那之前它是愿景，不是事实。

---

## 5. Finding Schema — EXTEND（追加）；`recommendation` / `status` 是 CONFLICTS

### 5.1 规范的 schema 逐字段对照

| 规范字段 | 现状 | 判定 |
|---|---|---|
| `id: "FIND-001"` | `fingerprint`（sha256，`review.py:1135`，含 `tool`） | `fingerprint` 仍是身份；`FIND-nnn` 是展示序号；稳定的人类可读 id 属于 audit candidate（`MEM-014` 式） |
| `source` | `tool` / `producer`（`review.py:84`） | EXISTS |
| `agent` | — | OVERREACH：`producer` 已是唯一轴，LLM scanner 名本身就标识了 agent |
| `category` | LLM 行有；静态行由 `_finding_category()`（`review.py:1239`）即时推导 | EXTEND：静态行可物化该字段 |
| `severity` | 已两次归一化且版本化：`severity` + `severity_mapping_version`（`review.py:1031`）、`review_level`（NXP 参考分级，`grading.py`） | EXISTS；规范的 Aggregator"再归一化一次"是 OVERREACH，且违反 README "native severities retained" |
| `confidence` | LLM 行有 | EXISTS |
| `file` | `file` + `canonical_path` | EXISTS |
| `line_start` / `line_end` | `line` 为 **str**，且在 dedup 键（`review.py:1120`）和 fingerprint 内；LLM 行另有 `line_range` | **追加** int 键，不改 `line`。静态行无 end → `line_end == line_start` 并注明 |
| `function` | LLM 行有 `symbol` | EXTEND：静态行可由索引反查 |
| `title` | — | NEW：LLM 行由 scanner 产出；静态行用 `rule_id` |
| `description` | LLM 行在 `findings.json` 已有，未进 review 行 | EXTEND：拷入（~2 行 + `_scrub_host_paths`） |
| `evidence`（源码原文） | **已在** `FINDING_SCHEMA`（`harness/schema.py:95`），每个 SKILL.md 都要求它，`parse_findings` 保留它（`:295`）；而 `findings.json` **总是导出**（`sanitize.py:32 _SESSION_EXPORTED`） | **CONFLICTS，且方向与初稿相反**（评审订正）：源码原文**今天就已经在共享 ZIP 里**。化解：`evidence` 进 review 行（私有目录内完整，保证 `recover-report` 可复现），由 **redactor 在导出时从 `findings.json` 与 `review/summary.json` 同时剥除**，除非 `[llm] export_sessions = true`。review 行的内容**不得**依赖导出设置 |
| `recommendation` | — | **CONFLICTS** README:9-11 "does not suggest fixes" |
| `status: unverified/validated` | — | **CONFLICTS** README:9-11 "does not decide false positive" |

### 5.2 化解：两个 schema，两层

规范的 schema 是**展示层** schema。本仓库已有的是**证据层** schema。它们不是同一个东西：

```
证据层 review/summary.json  每个 producer 自己的行，永不合并。追加 description / line_start /
                            line_end / function / title，不改既有字段。
意见层 audit/assessment.json candidate = 规范的"统一 Finding"：
                            id, category, origin, sources, member_fingerprints, detected_by,
                            verdict{label, confidence, rationale_artifact}, recommendation
                            "authority": "non-authoritative-derived-opinion"
```

用户已决定（D1，时点后改为 P1，**已于 P1 完成**）：修订 README:9-11，措辞改为"证据层永不合并、永不判误报；
可选的审计层可以提出关联、置信标签与修复提示，明确非权威，不改变也不删除任何证据行，
不影响退出码"。`recommendation` 做，但只在 candidate 上。

### 5.3 规范的四态是两个轴

规范要求区分 Detected / Correlated / Validated / Potential False Positive。
这是**两个正交轴**，不是一个枚举：

| 轴 | 取值 | 来源 |
|---|---|---|
| `origin` | `static-only` / `llm-only` / `both` | Correlator（§11） |
| `verdict.label` | `CONFIRMED` / `LIKELY` / `UNCERTAIN` / `FALSE_POSITIVE` / 无 | Validator（§12） |

合成一个枚举会让"被 3 个 producer 关联到 **且** 判为 FALSE_POSITIVE"无法表示——
而这正是规范自己"不能仅因多个 Scanner 报告同一问题就认定真实"所需要的状态。
四个展示词从两轴派生：Detected = 有 review 行；Correlated = `origin == both`；
Validated = `CONFIRMED`；Potential FP = `FALSE_POSITIVE`。

---

## 6. Event Schema — EXTEND；运行级事件日志是 NEW ✅ 已交付（P1）

### 6.1 现状

```python
# analysis.py:25
@dataclass(frozen=True)
class AnalysisEvent:
    phase: str          # discovery / tool / unit / output / stability / review / export / analysis / progress
    status: str
    message: str
    tool: str | None
    unit: str | None
    progress: float | None
    timestamp: float
    stream: str | None  # stdout / stderr
```

发射点：`runner.py:55-67` 的 `event()` 闭包；`llm/scan.py` 的 `_forward` 与心跳。
消费者：**只有 TUI**（`tui.py:620 _analysis_event`，经 `run_analysis`）。CLI 的 `analyze`
走 `runner.analyze`（`runner.py:38-40`），只传 `display.emit`，**不传 `event_sink`**；
`ProgressDisplay` 消费的是进度**字符串**，不是 `AnalysisEvent`。
（评审订正：初稿把 CLI 列为事件消费者。）`EventSink = Callable[[AnalysisEvent], None]`
（`analysis.py:58`）是接入缝，但 CLI 路径今天够不到它——见 §6.3。

LLM 单元级别已有 `llm/sessions/**/events.jsonl`。**运行级**没有——只有 `logs/runner.log` 文本。

### 6.2 规范的事件字段对照

| 规范字段 | 现状 | 判定 |
|---|---|---|
| 当前阶段 / agent / tool / 文件 | `phase` / `tool` / `unit` | EXISTS |
| Tool command | unit 记录的 `process.argv`（`process.py:67 ProcessResult`）在 manifest 里，不在事件里 | EXTEND：事件加 `argv` |
| 执行时间 | `timestamp`；duration 在 manifest | EXISTS |
| 已发现 finding 数 | LLM unit 完成时可知；静态工具只有报告解析后才知 | EXTEND：LLM 实时、静态事后 |
| Token usage | **本项目的** `RunOutcome`（`harness/runtime.py:80-88`）无计数字段；`scan.py:54 TOKEN_ACCOUNTING` 是估算。**上游运行时是否在 notification 中携带 usage 未验证**（评审订正：初稿断言"SDK 不报"，其实只验证了本项目侧） | P1 显示估算并**永远附带**说明；P3 验证上游 notification 是否带 usage，带则改为实测。加一条结构化 budget 事件（今天只在心跳散文里，`scan.py:614-617`） |
| stdout / stderr | `stream` 字段 + 增量行转发 | EXISTS |
| Error / Retry | error 有；**仓库零重试逻辑** | `retries` 字段永远是 0，OVERREACH |
| Pending / Running / Success / Failed | 状态梯子有 10 个词（7 个在 `status.py:15-40`，3 个在 `runner.py`），`partial ⇒ exit 10` | UI 侧投影函数；**绝不持久化规范的 4 态枚举**。梯子加一个**非终态**词 `running`：`runner.py:202` 后写占位并 `_save_manifest`。评审订正的两个细节：占位必须同时把 `requested` 翻为 `True`（`runner.py:146` 把每个工具先种为 `_not_requested`）；`_finish_interrupted`（`:402`）只改写 `not_requested`，需一并处理 `running` |

### 6.3 运行级 `events.jsonl`（P1）

在 `analysis.py:61 run_analysis()` 的 `events=` 缝上挂一个 JSONL sink，写到
`<run_dir>/events.jsonl`。每行一个 `AnalysisEvent` 的 JSON。

三个评审指出的必须先定的决策：

- **CLI 路径**：给 `runner.analyze()`（`runner.py:38`）加 `event_sink` 参数并由 `cli.py` 传入，
  而**不是**把 CLI 切到 `run_analysis`——后者会把 `progress` 字符串再发一遍成 `phase="progress"` 事件。
- **运行目录尚不存在时的事件**：`run_dir` 在 `runner.py:113-119` 才创建，之前已有 `analysis started`
  与 `discovery started`。sink 在内存缓冲，目录创建后一次性刷出；`--events-file` 可指定别处。
- **`serve` 的进程模型**（§13）：`serve REPORT_DIR` 是**只读查看器**，尾随另一个进程写的文件；
  `POST /cancel` 在该模式下**不可用**（`CancellationToken` 是 `threading.Event`，必须与分析同进程）。
  `serve --analyze SOURCE …` 在同一进程内用线程跑 `run_analysis`，此时才有 cancel。

规则：

- 经 `progress.single_line()` 过滤，与终端输出同源
- 加入 `sanitize.py:322 _export_files` 的排除表（它含路径与工具输出）
- 标注非权威：它是进度日志，不是证据；证据是 manifest 与各 producer 的原生报告
- **静态工具心跳**：cppcheck 以 `--quiet` 跑最长 7200s（`cppcheck.py:69`，`config.py:84`）
  **没有心跳**，flawfinder 同。按 `splint.py:128` 的 `heartbeat=` 传法加上（~6 行）。
  这是"一切实时可观察"没人列出的前置条件。

---

### 6.4 已交付的补充：`data`、`control`、`decision`、`logs/runner.log`

- `AnalysisEvent.data`：每类事件的结构化事实（工具的 argv/cwd/exit_code/错误摘录、
  单元的 index/total/attempt/failure_class、LLM 会话的 step/tok_s/eta、修补循环的
  before/after）。`events.py:clean_data` 保证它可序列化且有界。
- `control/*`（paused/resumed/skipped/jobs/retry_requested）与 `decision/*`
  （requested/decided）：操作者在 TUI、`serve` 或 CLI 上的每一次干预都是事件，
  由 `RunControl` 的监听器发出。
- `logs/runner.log`：`runlog.RunLogger` 从同一事件流投影出的人读日志，一行一个事实，
  级别由事件语义决定（失败/超时 WARN，致命 ERROR），argv 与 cwd 每工具打印一次。
  它不是第二个数据源：`events.jsonl` 才是。

## 7. Context 管理策略 — EXISTS；跨文件依赖是 NEW

规范的流程与现状逐段对照：

| 规范阶段 | 现状 | 位置 |
|---|---|---|
| Repository Mapper | 文件清单 + 哈希 | `inventory.py:34` |
| File Classification | 扩展名语言 + 风险分级 | `inventory.py`、`llm/risk.py:104` |
| Dependency Analysis | **近似**调用图（`\bident\s*\(` 正则）；**无** include 图解析、**无** `.c/.h` 配对 | `llm/index.py:188 build_index`，五遍 stdlib 解析器 |
| Relevant Context Selection | 被调者/调用者**只给签名与一行摘要**，不给函数体；按 tier 配预算 | `llm/context.py:52 build_unit_prompt`、`:33 TIER_BUDGETS` |
| Code Chunk | 按函数切；**每字节恰好落入一个 unit** | `llm/units.py:51 build_plan` |

规范的例子——分析 `process_packet()` 时自动带入 `parse_header()`、`validate_packet()`、
相关 struct、宏、header、caller/callee——现状**已做到**：unit 的 `types` / `macros` / `globals`
按**项目级**符号表解析（`units.py:312-314` 查 `index["types"]`，由 `index.py:236-238`
`_definition_table(files, …)` 跨文件构建），所以一个 `.c` 的 unit 已能带上 inventory 内头文件里的 struct。
（评审订正：初稿说"只解析同一文件内的符号"，不对。）

真正缺的两处 NEW：
1. **include 图的作用域**：同名符号在多个头文件里冲突时，今天没有按 `#include` 关系挑选；
   `_symbol_table` 会把同名函数按名字合并（`index.py:829` `_insert(prefer=True)`）。
   接入点 `index.py:227,494-510,798-812`。
2. **调用图的路径限定**：调用图的键**已经**是 `path::name`（`index.py:803`）；丢掉路径的是
   `units.py:347`（`key.rpartition("::")[2]`）。修一行，不是新建。

规范说"按 call graph 切分"是 OVERREACH：多函数 unit 会破坏"每字节恰好一次"不变量
（`units.py:3-11`），覆盖率失真。调用图留作**上下文**输入，不是切分依据。

真正的精度升级路径是 LSP/clangd（既有设计附录 A2，未解决），它能复用已有的
`compile_commands.json` 处理。

---

## 8. Agent 执行模型 — EXISTS

```
llm/scan.py:60 run()
  ├─ build_plan (units.py:51)            字节稳定
  ├─ 写 llm/index.json + llm/units/*.json
  ├─ cordis_document → llm/cordis.json   工具 allow-list、skill root、fs scope
  └─ _Phase.execute_all (scan.py:381)
       ├─ ThreadPoolExecutor(jobs)        splint.py:165 同款
       ├─ 预算：_reserve (scan.py:549)    prompt 估算 + completion 预留，不足 → unscheduled
       ├─ 缓存：键 = 渲染后 prompt 哈希    scan.py:255-283
       ├─ 心跳、取消 Event
       └─ 每 unit：harness/session.py:73 run_unit
            → HarnessRuntime.run (runtime.py:185)
            → 四个证据文件 events.jsonl / request.json / response.json / findings.json / meta.json
            → _provider_stop (scan.py:663)：provider abort 降级为单元结果，不取消阶段，不进缓存
```

规范要求的隔离。**评审订正：下表区分静态 adapter 路径与 LLM agent 路径，初稿把前者的保证误记给了后者。**
`harness/runtime.py` 与 `session.py` **零次**引用 `process.py` / `subprocess`：dsh 运行时由 SDK 自己
spawn（`runtime.py:323`），本项目只透传 `request_timeout_seconds` / `shutdown_timeout_seconds`
（`:263-266`）。既有设计 §2.2 承诺复用 `process.py:82`，实现**没有**做到；这是一项未兑现的设计。

| 项 | 静态 adapter 路径 | LLM agent 路径 |
|---|---|---|
| subprocess isolation | EXISTS：进程组、`shell=False`、`stdin=DEVNULL`（`process.py:82`） | **NEW**：由 SDK spawn，本项目不控制进程组 |
| timeout | EXISTS：TERM → grace → KILL，有界 | PARTIAL：只有 SDK 的两个超时参数；无进程组清理 |
| resource limit | ✅ 已交付：**两级输出字节上限** | `preexec_fn` 在线程池下（`splint.py:165`、`scan.py:440`）不安全；Docker 违反 README:9 "does not install tools"。落地为：`run_process` 的单次调用上限（每流 256 MiB）**加上** `OutputBudget` 的整轮上限（2 GiB，跨 adapter 共享、可并发扣减）——只有前者时，splint 每个 translation unit 调一次，500 个文件仍可一个个把磁盘写满。`truncated_bytes` 进 `ProcessResult` 并进入 unit 的 `reason`：截断成为可读的证据，而不是一个无人解释的解析失败 |
| working directory isolation | EXISTS：`cwd` 限定 | **NOT EXISTS**：`cwd` 对 agent **不是**边界——`runtime.py:251-253` 引用上游原话 "a resolution default, NOT a containment boundary"；`cordis.py:21-28` 记录没有任何上游包限制**读取**；证据文件如实盖章 `"confinement": "unenforced-upstream"`（`cordis.py:80`）。今天真正保证 scanner 对静态结果盲的是 `runner.py:81` 的 `output_root` 不得在被扫描树内——且它**只在 `[llm] enabled` 时**生效 |
| output size limit | 无 | 同上，P3 |
| Docker | 无 | 路线图：作为 `run_process` 的替代后端，返回同一个 `ProcessResult` |

---

## 9. 动态规划与重规划 — NEW，有界 ✅ 已交付（P4）

### 9.1 冲突

规范要 Plan → Execute → Observe → Re-plan。本仓库三条契约与之相撞：

| 契约 | 位置 | 会被什么打破 |
|---|---|---|
| 单元计划字节稳定 | `tests/test_llm_index.py:287 test_plan_is_byte_stable` | 模型进 `build_plan` 直接失败 |
| 离线零模型重建 | `recovery.py:21,68 analyzers_invoked = False`；`tests/test_llm_pipeline.py:527` | 重建需要重放规划决策 |
| LLM 不改退出码 | `status.py:43 overall()` 只遍历 `manifest["tools"]` | 重规划失败若进 `tools` 就会 |

### 9.2 机制：第 0 轮确定性，后续轮次有界，计划即证据

```
第 0 轮        units.py:51 build_plan 不动。永远确定性。

rounds 循环    scan.py:119 已是 "records = state.execute_all(_tasks(units, scanners))" 的形状。
               包一层 for round in range(1 + max_replan_rounds)。

观察           每轮结束后的结构化信号：
               {category: count}, {severity: count}, {tier: {planned, scanned, unscheduled}},
               budget_remaining。不含任何 finding 自由文本（§2.3）。

决策           决策者 = deterministic（规则表）或 model（显式开启）。
               动作来自可枚举词汇表：
                 escalate_tier(paths, to_tier)      把某些文件提到更高 tier 重扫
                 rescan(unit_ids, scanners)         对指定 unit 追加 scanner
                 extend_deadline(seconds ≤ 操作者上限)
                 stop_producer(name)                预算告急时停掉某 scanner
                 mark_for_validation(candidate_ids) 交给 assess
               模型输出按 harness/schema.py 的"宽松解析 + 严格校验"处理；
               未知动作、未知 unit_id 一律丢弃并计 malformed。

证据           llm/plan.json，与 llm/index.json 并列：
               rounds[{round, decided_by, observation, action, targets, rationale,
                       budget_before, budget_after}]

配置           [llm] max_replan_rounds = 0（默认）、planner_max_tokens
               四个配置改动点：config.py:17 DEFAULTS / :117 FIELD_REGISTRY /
               :361 _validate_llm / :442 effective_toml 的固定段表。
               （评审订正：_ALLOWED["llm"] 由 DEFAULTS 自动派生（:197），不是改动点。）
               tests/test_tui.py:49 强制每个叶子有 FieldSpec。

预算           planner 的调用走同一个 _reserve (scan.py:549) 和同一个阶段 deadline。

硬规则         review.py / recovery.py 永不读 plan.json。
               它是"为什么这样扫"的证据，不是 review 的输入。

重放           --plan FILE 免费得到：缓存按渲染后的 prompt 做键，重放同一计划
               = 全部命中 = 零模型调用。recover-report 语义不变。
```

**证据路径必须包含轮次**（评审指出的 P4 设计缺口）：`unit_id` 刻意不含 tier
（`units.py:324-336`），session 目录按 `(producer, unit_id)` 定位（`session.py:47-49`）。
`escalate_tier` / `rescan` 对同一 producer 会**覆盖第 0 轮的盲扫证据**。因此 ≥1 轮的证据
写到 `llm/sessions/<producer>/<unit_id>/r<round>/`，`coverage_report`（`units.py:155-168`）
按 `(unit_id, round)` 记账，finding 的 `round` 字段由目录推出。

规范的升级例子——"cppcheck 报 `memcpy` 越界 → 调 Memory Agent 确认"——**不是重规划，
是 Validator**（§12）。第一轮 scanner 对静态结果盲（既有设计 §0.2 #1）；一个被静态结果
提示过的 agent 是第二轮角色。若按规范的框架做，`llm_only` 指标失去意义，
`by_scanner` 覆盖率会混入盲扫与提示扫。每条 finding 打 `round` 标记，
LLM-only 指标只数第 0 轮。

用户已决定（D2）：默认全确定性，`max_replan_rounds = 0`。

**已交付（`code_analyzer/llm/replan.py` + `llm/scan.py` 的 rounds 循环）**，与上面的设计
一致，另有两处实现层面的收紧：

1. **观察只能看到计数。** unit record 里本来就没有 finding 文本，只有 `finding_count`；
   为了让规则表能按类别/严重度决策，`_parse_report` 增加 `finding_mix`（两张计数表）。
   这是刻意的边界：finding 的 message 是模型对不可信源码的输出，把它喂回规划提示词就是
   本项目在别处都关掉的那条注入路径。
2. **确定性规则表只有三条**，每条都写明它凭什么触发：低 tier 文件出了 high/critical →
   `escalate_tier`（每个文件只升一次）；预算恢复后补扫 `unscheduled`；某 producer 全部
   失败 → `stop_producer`。都不触发就记一条 `stop` 并结束。

---

## 10. 并行执行策略 — EXISTS / EXTEND

### 10.1 现状

| 层 | 并行 | 位置 |
|---|---|---|
| splint 内部 | `ThreadPoolExecutor(jobs)` | `splint.py:165` |
| cppcheck 内部 | `-j min(4, cpu)` | `cppcheck.py:33,69` |
| LLM 阶段内部 | `ThreadPoolExecutor(jobs)` | `scan.py:427-467` |
| **三个静态工具之间** | **串行** | `runner.py:318` `run_static()` 内的循环 |
| **静态 ∥ LLM** | **已并行（P3）** | `runner.py:123 _run_together`；`:437` 调度点 |

### 10.2 只有静态 ∥ LLM 值得做

cppcheck 与 splint 都吃 CPU，cppcheck 已经 `-j`；两者并行只是争抢。
LLM 阶段是网络绑定的，与静态并行几乎白赚壁钟。
把 `tools.splint.jobs` 默认从 1 提高（`config.py:92`）是更便宜的静态侧提速。

### 10.3 并发窗口：工作量比例式 progress

固定梯子（按工具索引分段 + LLM 固定 0.80–0.84）在两个阶段同时上报时必然乱序，
所以并发窗口内的 progress 改成**工作量比例**（`runner.py:59-78`、`_Window` 在 `:81`）：

```
value = WINDOW_START + (WINDOW_END - WINDOW_START) × (w_static × f_static + w_llm × f_llm)
       = 0.10       + 0.75                          × (0.5 × f_static + 0.5 × f_llm)
```

- `f_static = (已完成工具数 + 当前工具内单元进度) / 请求工具数`；`f_llm` 由 `scan.py` 上报的
  `index / total` 直接给出。两者各自单调不减，加权和因此单调不减。
- **权重相等**：静态成本随文件数走、LLM 成本随模型时延走，运行时无从预知谁占主导；
  要知道就得计时，而计时正是这个模型排除的输入。各占一半等于不作任何断言。
- **绝不用壁钟推导 progress**：`events.jsonl` 的 progress 列是"做了多少活"的陈述，
  不是计时测量，否则同一棵树两次运行的事件日志无法比较。
- `[llm] enabled = false` 时权重塌缩成 `(1.0, 0.0)`，静态独占整个窗口，
  最后一个工具正好落在 `WINDOW_END`，即并发之前的形状。
- 窗口终点 `0.85` 与稳定性复扫的起点重合，其后的梯子（review 0.86–0.92、export 0.93+）未动。

**历史订正：单调性在并行之前就已经是坏的。** `[llm] enabled` 时 LLM 阶段以 0.84 结束，稳定性复扫
紧接着发 0.8；另外 `0.8 + 0.04 × 1.0` 在浮点下是 `0.8400000000000001`，高于字面量 0.84。
既有测试只在静态模式下跑所以一直绿。**已在 `1a3a370` 修复**并补了 LLM 模式下的单调性测试。

### 10.4 并发下被序列化的三样东西

| 共享物 | 锁 | 为什么 |
|---|---|---|
| `manifest` + `_save_manifest` | `manifest_lock`（`RLock`，`runner.py:309`） | 静态侧只写 `manifest["tools"]`、LLM 侧只写 `manifest["llm"]`，但序列化会遍历整棵树；锁覆盖 mutate+save 整段，否则会落盘一份撕裂的快照 |
| `progress` 的取值与发射 | `_Window` 自带的锁 | 两个线程各自算完再发，仍可能倒序发出；算值和发事件必须在同一把锁里 |
| `EventSink` 扇出 | `fan_out` 的锁（`events.py:86`） | 一条事件到达所有 sink 之后下一条才开始，否则 JSONL 文件与 TUI 会对事件顺序各执一词。`JsonlEventSink` 自己的锁只保证单行不撕裂 |

cancel 是共享的：两侧都拿 `cancellation.is_cancelled`；主线程收到 `KeyboardInterrupt`
时 `_run_together` 主动 `cancel()`，否则 join 会等满一整轮 LLM 扫描。
任一侧抛异常都先让另一侧写完自己那半份 manifest 再上抛（`runner.py:123-157`）。

**并发反而加强了盲扫不变量**：第 0 轮 scanner 运行期间 `tools/*/report.*` 尚未写出，
根本无可偷看。`output_root` 不得在被扫描树内的硬门（`runner.py:211`）原样保留——
盲扫不能变成依赖竞态。

### 10.5 证据字节不变的证明方式

`CONCURRENT_PHASES`（`runner.py:78`）保留串行代码路径，不进配置——运维没有理由选，
差异只可能是 bug。`tests/test_concurrency.py` 对同一棵树跑两次串行 + 一次并发：
两次串行的差集定义了"任何重跑都会变"的叶子（run id / 运行目录 / 时刻 / 时长 /
嵌了这些的文件的 sha256），该差集必须逐条通过 `_per_run` 的白名单，
然后三份 manifest 与三份 `review/summary.json` 在抹掉这些叶子后**字节相等**。

源码稳定性复扫（`runner.py:447`）是后置条件，放在全部阶段之后；并发反而缩短窗口。

---

## 11. 聚合与去重策略 — EXISTS（证据层）/ NEW（意见层）✅ 已交付（P1）

### 11.1 证据层的三个冻结点

| 函数 | 行为 | 为什么冻结 |
|---|---|---|
| `_deduplicate`（`review.py:1120`） | 键含 `tool`，严格 producer 内去重 | 不变量 1；`tests/test_producers.py` 钉死"相同 finding 来自不同 producer 不合并" |
| `_fingerprint`（`review.py:1135`） | 摘要含 `tool` | 跨 producer 身份**结构上不可能相等**——这是刻意的 |
| `_build_overlap_groups`（`review.py:1270`） | 只认 `TOOL_NAMES`；≥2 原生工具、同类别、3 行内成组；**不合并不删除** | `tests/test_producers.py:30` 字节钉死对纯静态语料的输出 |

规范的 Aggregator 要合并、要过滤误报、要再归一化 severity——三件事都落在冻结点上。

### 11.2 意见层的 Correlator（P1）

从 `_build_overlap_groups` 抽出共享原语：

```python
def group_nearby(findings, key_fn, distance) -> list[list[dict]]
```

两个消费者：冻结的 `overlap_groups`（`key_fn` 只认原生 `tool`，输出字节不变，测试钉死）；
新的 Correlator（`key_fn` 认 `producer`，**恒定产出**，不要求 ≥2 来源，因为
`static-only` / `llm-only` 本身就是要统计的对象）。

Correlator 用**另一套身份键**：`(canonical_path, category, line_span)`，不碰 `fingerprint`。

类别：静态行走原来的路径（`review.py:1239 _finding_category` 的静态分支，字节不变）；
Correlator 用一个**变体**同时应用到两个 engine 做分组。**评审订正的关键细节**：该变体必须
对静态行**先查 `_CWE_CATEGORIES`（`review.py:1181`）再走关键词规则**。否则 flawfinder 的
`CWE-190` + "integer overflow" 消息会被静态关键词表的 `buffer` 规则（`:1203`）先截住
（已实测：今天它归类为 `buffer`），而 `_LLM_KEYWORD_CATEGORIES` 以同一张静态表开头
（`:1212`），所以"把 LLM 词汇应用到两个 engine"本身并不能让 `CWE-190` 对上 `integer-overflow`。

**实现期实测补充（2026-08-24，升级 cppcheck 之后）**：LLM 行的类别解析必须对**同一个缺陷
的两种叫法都成立**。scanner 的 token 选择在不同运行之间会变——同一类 alloc.c 泄漏，一次
实测报 `error-path`，另一次报 `resource-leak`，两个都在该 skill 的声明集合里。原实现对
LLM 行直接返回声明类别、不看 CWE：报 `resource-leak` 时能和 cppcheck 的 `memleak`
（CWE-401）对上，报 `error-path` 时对不上，于是同一个缺陷是否被算作跨引擎一致，取决于模型
挑了哪个词。

解析顺序因此定为三段，**顺序本身是实测定出来的**：

1. 声明类别经别名表归一后**若已在静态词汇表内**（`buffer`、`resource-leak`…），用它。
   这一步不能省：`llm-memory-safety` 在 `src/frame.c:19` 报 `out-of-bounds`（→`buffer`）
   却带 CWE-129，而 cppcheck 同几行报 CWE-788（→`buffer`）；先查 CWE 会把前者归到
   `input-validation`，**拆掉一个本来正确的关联**——这正是本次修复的第一版造成的回归，
   由这次实跑发现。
2. 否则查两个 engine 共用的 CWE 表：`error-path` + CWE-401 → `resource-leak`，与 cppcheck 相遇。
3. 都不命中时保留 scanner 自己的词（`state-machine`、`dead-code`），
   logic scanner 的闭合 token 集因此不会在进入 audit 层时被抹平。

**对实测数字的订正**：这次改动在本次实跑的语料上**一条 candidate 都没有改变**（scanner 恰好
选了 `resource-leak`）。真正改变 `llm_only_confirmed` 的是**升级 cppcheck 本身**：在 cppcheck
不可用的那次运行里，alloc.c 的两处泄漏被记为 `llm-only`；cppcheck 恢复工作后，同一语料上它们
是 `both`。

输出 `audit/assessment.json` 的 candidate：

```json
{
  "id": "MEM-014",
  "canonical_path": "src/parser.c",
  "line_start": 118, "line_end": 121,
  "category": "buffer",
  "origin": "both",
  "sources": ["cppcheck", "flawfinder", "llm-memory-safety"],
  "member_fingerprints": ["a1b2…", "c3d4…", "e5f6…"],
  "detected_by": {"static_tools": ["cppcheck", "flawfinder"],
                  "llm_scanners": ["llm-memory-safety"],
                  "validators": []},
  "verdict": null
}
```

candidate `id` 的规则：`<类别前缀>-<运行内序号>`，前缀由类别映射（buffer→MEM、trust-boundary→SEC、
race→FW …）。**它在一次运行内稳定，跨运行不稳定**——跨运行身份用 `(canonical_path, category,
line_span)` 键。没有行号的 finding（splint 的 `<Location unknown>`）不参与关联，计入
`metrics.uncorrelated`，仍以 `origin` 单独计数。

规范的 "Finding #12 — Potential Buffer Overflow — Detected by ✓ cppcheck ✓ flawfinder ✓ AI Memory Agent"
就是这条 candidate 的渲染。`review/` 的三行原样保留，作为它的 provenance 列表。

规范列给 Aggregator 的职责逐项落位：

| 职责 | 落位 |
|---|---|
| 去重 | 证据层 producer 内（已有）；跨 producer 是**关联**不是去重 |
| 合并证据 | candidate 的 `member_fingerprints` |
| Severity normalization | 已有两套版本化映射，**不再加第三套** |
| Confidence evaluation | `verdict.confidence`（§12） |
| Finding correlation | Correlator |
| False positive filtering | `verdict.label == FALSE_POSITIVE` 是**标签**，不删除 |
| Sorting / organization | 展示层 |

---

## 12. 验证策略 — NEW（既有设计 §7 已设计）✅ 已交付（P2，`assess`）

| 项 | 设计 |
|---|---|
| 角色 | 第二层，与 scanner 严格分离。只有它能同时看到源码 + 静态 findings + LLM findings + 调用关系 |
| 入口 | `code-analyzer assess REPORT_DIR`，独立命令，显式调用（D2） |
| 实现 | `_Phase`（`scan.py:381`）的另一种消费者：任务 = candidate 而非 unit；`VERDICT_SCHEMA` 作为 `FINDING_SCHEMA` 的兄弟；证据落 `llm/sessions/validator/<candidate_id>/` |
| 输出 | `verdict{label, confidence, rationale_artifact, model, skill_version, validator_saw_static: true}` 写回 candidate |
| 上限 | `[audit] validation_max_candidates`（`config.py:81`），按 severity × origin 排序优先验证 HIGH/CRITICAL（既有设计 §7.2 写的是"按风险排序"，本文细化为 severity × origin） |
| 偏置 | validator 看得到静态结果，所以 `llm_only_confirmed` 的准确含义是"被第二个角色佐证"，不是"独立确认"。`metrics.caveats` 机器可读，dashboard 上**紧挨数字**渲染 |
| 不做 | 盲验（validator 不看静态结果）会让已经昂贵的流程翻倍，收益不抵成本——写明这个取舍 |

指标（既有设计 §9.4）：`by_origin`、`by_verdict`、`by_origin_verdict`、
**`llm_only_confirmed`**——LLM 层存在的理由。

---

## 13. Backend 架构 — EXISTS / NEW

```
已有
  cli.py:21 parser()          argparse 子命令：analyze / tui / doctor / compile-db /
                              rebuild-dashboard / recover-report
  analysis.py:61 run_analysis 无头服务边界：AnalysisRequest → AnalysisResult + EventSink
  runner.py:43 _analyze       确定性主干；manifest.json 经 _save_manifest（runner.py:460）在 12 处原子重写
  persist.py:14 json_bytes    唯一 JSON 编码器，字节稳定

新增（P1）
  serve.py                    stdlib ThreadingHTTPServer，绑定 127.0.0.1
      GET  /                  实时页（单文件 HTML，内联 JS）
      GET  /events            text/event-stream，尾随 <run_dir>/events.jsonl
      GET  /graph             graph(manifest) → {nodes, edges}
      GET  /manifest          manifest.json
      POST /cancel            CancellationToken.cancel()（analysis.py:36）——仅 serve --analyze 模式
  serve REPORT_DIR            只读查看器，尾随另一进程写的 events.jsonl；无 cancel
  serve --analyze SOURCE …    同进程线程内跑 run_analysis，有 cancel；参数同 analyze
  /cancel 只接受 127.0.0.1 且校验 Origin 头，防止本机其它页面跨源取消
  events sink                 JSONL EventSink，挂在 analysis.py:61 的 events= 参数

新增（P2）
  assess 子命令               §12

新增（P4）
  --plan FILE                 §9
```

用户已决定（D3）：stdlib SSE，**零新依赖**。FastAPI/WebSocket 各带 5–20 个传递依赖，
需要 doctor/preflight 的配套检查，而 WebSocket 对只读展示没有任何增益。

**不用 dsh 自带的 Web UI**：它违反四文件隔离（既有设计 §2.3），看不到静态工具，
且每个 unit 一个运行时（`scan.py:576-584`），没有"一次运行"的概念。
（评审订正：初稿写的端口号来自上游 README，未在本仓库或已安装运行时中核实，已删。）

---

## 14. UI 架构（两个前端共享一套节点词汇） — EXISTS（离线）/ NEW（实时）✅ 已交付（P1，`serve`）

### 14.1 离线 dashboard：五条契约冻结，文件可追加

`html_report.py` 有五条被测试钉死的契约：

| 契约 | 测试 |
|---|---|
| 恰好两个可执行 `<script>` | `tests/test_dashboard.py:72` |
| 任何位置无 `http://` / `https://` | `tests/test_v2.py:175` |
| `safeHref` 拒绝含 `:` 的路径（故 `ws://` 结构上不可能） | `html_report.py:496` |
| 重建字节幂等 | `tests/test_dashboard.py:131` |
| 全部经 `textContent` 写入 DOM | `html_report.py:349-353` |

它是**可分享的证据报告**；`file://` 下 CORS 也挡住任何 fetch。把它改成实时页会同时打破五条。
在五条契约内**追加**内容（§17-6 的 origin 面板）是允许的；既有设计 §11.2 要求的
**按 engine 分配嵌入配额**（`MAX_EMBED_FINDINGS` `html_report.py:27`）尚未实现，且 candidate
列表作为第二个嵌入集合也受同一上限约束——P1 一并处理。

### 14.2 实时页（`serve`，P1）

另一个单文件 HTML，由 `serve.py` 提供：

```text
Code Review · run 2026-08-21T13:02:11Z-ab12cd34ef56
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

● 仓库分析          ✓ 318 files · compile-db: 212 TU
● 静态分析          ✓ cppcheck     27 findings      12.4s
                    ● flawfinder   running · shard 3/5
                    ○ splint       pending
● LLM 审查          ✓ llm-memory-safety   8 findings · 41/41 units
                    ● llm-security        unit 17/41 · drivers/spi.c · 00:48
                    ○ llm-firmware-concurrency
                    预算  prompt 38% · completion 21%   (估算：字符/4)
● 源码稳定性        ○
● 报告              ○

[DAG]   Repository ─ Mapper ┬─ cppcheck ✓ ──────┐
                            ├─ flawfinder ● ────┼─ review ○ ─ export ○ ─ index.html ○
                            ├─ splint ○ ────────┤
                            ├─ llm-memory ✓ ────┤
                            ├─ llm-security ● ──┤
                            └─ llm-firmware ○ ──┘
点击节点 → input / argv / prompt 哈希 / stdout / stderr / findings / 时长 / 估算 token
```

- DAG 从 `manifest.json` **派生**（`graph(manifest)`，~60 行）：节点 = `tools[*]` + `llm.scanners[*]` +
  固定阶段；状态 = 已有的 10 词梯子经投影函数映射到 ○●✓✕；边 = 固定拓扑
- 运行结束后页面链接到已写好的 `index.html`
- token 数永远附带 `TOKEN_ACCOUNTING` 说明
- 双语：沿用 `html_report.py:357-486` 的 `I18N` 表结构
- 10 词梯子 → 4 态投影：`completed`→✓；`partial`/`timed_out`/`failed`/`interrupted`→✕（悬停显示原词）；`running`→●；`unscheduled`/`not_requested`/`not_applicable`/`disabled`→○（悬停显示原词）
  （实现期订正：初稿把 `missing`/`incompatible` 归入 ○。实现将其归入 ✕ 且更正确——
  工具缺失或版本不兼容意味着**拿不出证据**，不是还在排队；见 `status.NODE_STATES`）

### 14.3 TUI 实时流程视图

同一张图的第二个前端。§14.2 的原型当初只指派给 `serve`，但需要盯着扫描的人多数
时候就坐在跑扫描的那个终端前。四条实现期决定：

1. **词汇下沉。** `NODE_STATES` / `PHASE_NODES` / 新增的 `STATE_GLYPHS` 移到
   `status.py`（本就是状态梯子模块，只依赖 stdlib），`serve` 再导出。TUI 绝不
   import `serve`——后者在模块导入时就拉起 `http.server`，让终端界面依赖 web
   服务器模块是本末倒置。
2. **TUI 折叠事件，`serve` 投影 manifest。** 不是重复，是必需：运行期
   `manifest.json` 刻意粗粒度——`runner._running_state` 把 `unit_counts` 清零，
   `llm_scan.running()` 的 `scanners` 是空字典，于是 `graph(manifest)` 会把六个
   scanner 塌成一个 `llm` 节点。逐 scanner 的实时视图只能来自事件流。运行结束后
   反过来，所以结果页仍读 manifest。
3. **计数器：分子靠数，分母来自事件的 `data`。** 早先的版本把分母从 `progress`
   文本里刮出来，并因为 `tests/test_events.py` 钉死了 JSONL 键集合而否决了结构化
   字段。这个决定已经**反转**：`AnalysisEvent` 多了一个 `data` 字典（`clean_data`
   限深、限长、限键数），单元事件携带 `index`/`total`/`label`/`argv`/`reason`/
   `failure_class`，`units/planned` 宣布分母，`units/unscheduled` 把成千上万条
   "未调度"合并成一条带 `count` 的事件。理由是去重：同一个事实以前会以 `progress`
   文本、`unit` 事件和 `runner.log` 行三种形态各出现一次，现在 CLI 进度行由 runner
   从同一个事件派生，`events.jsonl` 里不再有 `progress` 行。键集合契约随之升级，
   `serve._event_dict` 原样透传 `data`。
4. **`audit`、`build_context` 入流程图。** runner 现在为审计层发 `audit/*` 事件，为
   构建上下文修补循环发 `build_context/*`（diagnosed → inferred → consulting/consulted
   → probing/probed → awaiting → applying/applied → finished）与 `decision/*`
   事件；`flow.py` 的 `TAIL_NODES` 以"修补"打头，`serve` 页面画同一张图并在有待决策
   项时显示决策条。

模型在 `code_analyzer/flow.py`，纯逻辑、零 UI 依赖，像 `serve.graph` 一样单测
（`tests/test_flow.py` 有一条测试专门断言 import 它不会拉进 textual / rich / http）。
渲染在 `tui.py`：逐段构造的 `rich.text.Text`——**绝不用标记字符串**，因为被扫描文件名
会进入这些行。

**2026-09-03 修订：前端从表单变成对话。** 三段式（表单 → 运行 → 结果）与五个模态屏
删除，`tui.py` 1504 → 876 行。现在是一个滚动记录 + 一个输入框，一次运行是记录里的一个
`Collapsible` 块：折叠是一行活摘要，`Enter` 展开就是上面这张图。四条实现期决定：

1. **一轮一个组件，绝不一事件一个。** 实测（Textual 8.2.8）：挂 60 个 `Collapsible`
   273 ms、活动块重绘 0.54 ms/帧（5 Hz 预算 200 ms）。事件管线原样保留——两个队列、
   state 不丢 / liveness 可丢、5 Hz 折叠、绝不 per-event `call_from_thread`——那是用
   一次一小时 52 万事件的运行换来的。队列条目多带一个 block id，因为现在不止一个
   action 会发事件。
2. **三处「停下来问一句」收敛成一个缝**（`ask.Asker`）：build-context 补丁对话、
   compile-db 的两处 `input_from`。CLI 传 `stdin_asker`，对话界面把问题渲染成一轮，
   测试传脚本。终端输出逐字节不变。
3. **模型的对话与操作员的对话是两个模型**：`chat.Transcript` 折叠 provider 事件、
   一个扫描单元一轮、会淘汰已结束的轮；`dialogue.Dialogue` 持有操作员的块、一小时后
   还要能往上翻。`RunBlock` 组合二者。`Dialogue.apply` 返回**变化的块 id** 而不是
   bool，所以只重绘动了的那个块。
4. **一处定义两个前端**：`actions.py` 是唯一的「操作员能做什么」，`cli.py` 与对话界面
   都是它的薄壳；action 只发事件、不打印，前端决定什么进终端。
5. **2026-09-03 追加：等待也要诚实。** 自由文本成为主路径后，每句话都有二三十秒的窗口。
   `dialogue.ThinkingBlock` 由已有的 1Hz 定时器画秒表与阶段，显示上一次的**测量**耗时，
   **不发明 ETA**。`Ctrl+C` 是脱手不是杀死——`HarnessRuntime` 只在通知回调里轮询取消谓词，
   SDK 无 cancel 句柄，首 token 之前真的打不断——所以界面说明请求可能仍在跑、晚到的回答
   会被丢弃，并用一个 generation 计数把它认出来丢掉。全会话至多一个在飞的 provider 请求。
   期间自由文本排队，`/命令` 不排队。

---

## 15. 推荐项目目录结构 — EXTEND

```text
code_analyzer/
    cli.py  runner.py  analysis.py  status.py  persist.py  ...   （不变）
    tools/
        __init__.py          TOOL_NAMES / LLM_PRODUCERS(→从磁盘派生) / PRODUCER_ORDER
        cppcheck.py  flawfinder.py  splint.py                     （P2 收敛到 Adapter 协议）
        <name>/manifest.toml                                       （P2 新增）
    llm/
        index.py  units.py  risk.py  context.py  skills.py  scan.py（不变）
        profiles.py          provider profile 表
        plan.py              P4：rounds 循环、动作词汇表、plan.json
    harness/
        runtime.py  session.py  schema.py  cordis.py             （不变）
        verdict.py           P2：VERDICT_SCHEMA
    skills/
        llm-memory-safety/SKILL.md
        llm-security/SKILL.md
        llm-firmware-concurrency/SKILL.md
        llm-resource-error/SKILL.md                                （P3）
        llm-undefined-behavior/SKILL.md                            （P3，与 memory-safety 同 commit 重切）
        llm-logic/SKILL.md                                         （P3，闭合 token 集）
        validator/SKILL.md                                         （P2）
    audit.py                 P1：group_nearby 抽取、Correlator、assessment.json 写出；P2：Validator 消费者
    serve.py                 P1：SSE + graph(manifest) + cancel
    sarif.py                 P1：SARIF 2.1.0 导出
    events.py                P1：JSONL EventSink

运行目录
    manifest.json            节点状态唯一来源（不变）
    events.jsonl             P1：进度日志，非证据，不进 ZIP
    review/summary.json      冻结
    review/summary.sarif     P1
    llm/index.json  llm/units/  llm/sessions/  llm/cordis.json     （不变）
    llm/plan.json            P4：重规划决策证据
    audit/assessment.json    P1 candidate（无 verdict）；P2 加 verdict
    index.html               冻结契约
```

---

## 16. 端到端时序图

```text
用户            CLI          runner._analyze        Adapters       LLM _Phase        events.jsonl     serve        audit
 │  analyze .    │                 │                    │                │                 │              │           │
 ├──────────────►│  load_config    │                    │                │                 │              │           │
 │               ├────────────────►│ inventory/compile-db/risk/build_plan（确定性，字节稳定）│              │           │
 │               │                 ├─ manifest v2 ──────┼────────────────┼────────────────►│ discovery    │           │
 │               │                 │                    │                │                 │              │           │
 │               │                 ├─ cppcheck ────────►│ run_process    │                 │              │           │
 │               │                 │   heartbeat ───────┼────────────────┼────────────────►│ tool/unit ──►│ SSE      │
 │               │                 │◄─ 执行记录 ────────┤                │                 │              │           │
 │               │                 ├─ flawfinder / splint（同上）         │                 │              │           │
 │               │                 │                    │                │                 │              │           │
 │               │                 ├─ llm_scan.run ─────┼───────────────►│ 第 0 轮（盲）    │              │           │
 │               │                 │                    │                ├─ run_unit ×N ──►│ unit ───────►│           │
 │               │                 │                    │                │  四个证据文件    │              │           │
 │               │                 │                    │                ├─[P4] observe → plan.json       │           │
 │               │                 │◄─ manifest["llm"] ─┼────────────────┤                 │              │           │
 │               │                 │                    │                │                 │              │           │
 │               │                 ├─ 源码稳定性复扫     │                │                 │              │           │
 │               │                 ├─ build_review → review/summary.json（冻结语义）         │              │           │
 │               │                 ├─ sarif.export → review/summary.sarif                  │              │           │
 │               │                 ├─ audit.correlate → audit/assessment.json（candidate，无 verdict）      ├──────────►│
 │               │                 ├─ export_shareable（排除 events.jsonl / llm/sessions）  │              │           │
 │               │                 ├─ html_report.render → index.html                      │              │           │
 │               │◄─ exit_code, run_dir ───────────────────────────────────────────────────►│ run finished │           │
 │◄──────────────┤                 │                    │                │                 │              │ 链接 index.html
 │               │                 │                    │                │                 │              │           │
 │  assess DIR   │（显式、独立）    │                    │                │                 │              │           │
 ├──────────────►├─────────────────┼────────────────────┼───────────────►│ Validator 消费 candidate ──────┼──────────►│
 │               │                 │                    │                │  看得到全部证据  │              │  verdict  │
 │               │                 │                    │                │  llm/sessions/validator/       │  metrics  │
 │◄──────────────┤ audit/assessment.json 含 verdict 与 llm_only_confirmed（带 caveat）                      │           │
```

---

## 17. MVP 实现范围

**一个竖切片：每次运行都可实时观察、跨 engine 关联、可被机器消费。
零新模型调用、零新依赖、所有字节稳定性钉子不动。**

| # | 内容 | 规模 | 接入缝 |
|---|---|---|---|
| 1 | 运行级 `events.jsonl` sink + `--events-file`；cppcheck/flawfinder 心跳；`running` 占位态 | ~60 行 | `analysis.py:61`、`cppcheck.py:69`、`runner.py:202` |
| 2 | review 行追加 `description`、`evidence`（导出时由 redactor 剥除，见 §5.1）、`line_start`/`line_end`（静态行 `line_end == line_start`，并加 `line_end_known: false`）。**`function` 对静态行不做**：索引只在 `llm_scan.run` 内构建（`scan.py:93`），`build_review` 拿不到，而 `recover-report` 常在无源码树的解压目录上运行——反查会让再派生结果与原始不一致，破坏既有设计 §8.1 | ~20 行 | `review.py:79-100, 824-843` |
| 3 | 抽 `group_nearby`；字节钉死 `overlap_groups`；Correlator + `audit/assessment.json`（candidate，无 verdict，`validation_unscheduled = candidates_total`）。**跑在 `analyze` 内**，紧随 `build_review`；`recover-report` 重生成它；进 `artifact_index`；进 ZIP（不含源码）。类别先 CWE 后关键词（§11.2） | ~300 行 | `review.py:1270-1296`；`runner.py` 的 review 阶段之后 |
| 4 | `code-analyzer serve`：SSE、`graph(manifest)`、10→4 态投影表（§14.2）、`POST /cancel`（仅 `--analyze` 模式，校验 Origin）、链接 `index.html` | ~250 行 | `analysis.py:36,58`；`runner.py:38` 加 `event_sink` |
| 5 | SARIF 2.1.0 导出：经 `persist.json_bytes`；每 producer 一个 `runs[]`；**LLM 行放独立 run**（`gate_eligible: False` 的 CI 语义在消费者侧得以保留）；`line` 为空时无 `region`；`recovery.py` 可重生成；进 `artifact_index`；字节稳定性测试仿 `test_dashboard.py:131`。已定的映射：`level` ← `severity`（critical/high→error，medium→warning，low/info→note，unknown→none）；`ruleId` ← 静态 `rule_id`、LLM `category`；`partialFingerprints.primaryLocationLineHash` ← `fingerprint`；`uriBaseId = SRCROOT`，`uri` ← `canonical_path`。`sanitize.py:373-383` 已处理 `.sarif` | ~200 行 | `review.py` 之后、`sanitize.py` 之前 |
| 6 | dashboard 加 candidate / origin 区。`compPanel`（`html_report.py:761`）**已经**接受 `series` 参数并已用于 engine 轴（`:856-857`）；origin 面板只是第五次调用加一个 `originSeries`。需要的实际改动：`render(manifest, review)`（`:72`）加 `assessment` 参数；`rebuild_dashboard` 与 `export_shareable`（`sanitize.py:224` 会重渲染）读 `audit/assessment.json`；candidate 列表受按 engine 分配的嵌入配额约束；`test_dashboard.py:131` 的 fixture 加 `audit/`；`I18N.zh` / `I18N.en` 各加键 | ~120 行 + i18n | `html_report.py:72, 854-857` |

MVP 交付后即可回答"static-only / llm-only / both 各多少"，即便还没有 verdict。

---

## 18. 后续扩展路线

| 期 | 范围 | 解锁 | 前置 | 状态 |
|---|---|---|---|---|
| **P1 可观察 + 已关联（MVP）** | §17 的 1–6 + **README:9-11 章程修订**（评审订正：`audit/` 在 P1 落地，章程必须同期改，不能让一个版本与 README 自相矛盾） | origin 指标、实时视图、CI 接入 | 无 | ✅ 已交付 |
| **P2 已验证** | Validator `_Phase` 消费者 + `VERDICT_SCHEMA` + `assess` 子命令 + dashboard verdict 区（caveat 紧挨数字）；`Adapter`/`RunContext` 协议重构（消除 4 个崩溃点，字节钉死）；「声明 == 磁盘发现」测试已在；`allowed-tools` 并集接入 `cordis.py`；`recommendation` 上 candidate | **`llm_only_confirmed`**——LLM 层存在的理由 | P1 | ✅ 已交付（§4.2 的元数据表格部分除外） |
| **P3 更快 + 更宽** | 进度模型改为工作量比例后做静态 ∥ LLM（锁、共享 cancel）；输出字节上限；`llm-doctor` 与 `llm-resume`（既有设计 Phase 2 的交付物，尚未存在于 `cli.py`）；验证上游 notification 是否携带 token usage；**三个新 scanner**：Resource/Error（枚举加 token + `_LLM_KEYWORD_CATEGORIES` 一行 + memory-safety 的"错误路径未释放"条款迁入）、UB（与 memory-safety **同一 commit** 按 空间/时间 vs 算术/语义 重切，两份 `skill_version` 同升，跨运行缓存失效）、Logic（**只接受闭合 token 集**：`state-machine` / `inverted-condition` / `dead-code` / `unreachable-branch`；拒绝"找一切逻辑问题"）；`total_*_tokens` 随启用 scanner 数线性缩放（**规则**：仅当用户未显式设置、值仍为 `DEFAULTS` 时，默认值 = 基数 × 启用 scanner 数；显式设置则不缩放；`inputs/effective-config.toml` 记录解析后的数值，`reload` 一致性校验因此不受影响）；include 图 + 头文件配对；`splint.jobs` 默认提高 | 壁钟 ≈ max(静态, LLM)；6 个 scanner；更准的上下文 | P1 | ✅ 已交付 |
| **P4 自适应** | 有界重规划（§9，含按轮次分目录的证据路径）：`llm/plan.json`、rounds 循环、动作词汇表、`--plan` 重放、`max_replan_rounds` 默认 0；可选 NL → config-patch 前端；`@media print`（替代 PDF）；TUI 的 `[llm]` 字段、可选 LLM 门禁、`docs/usage.md` 新章节（既有设计 Phase 4 的交付物） | Plan→Execute→Observe→Re-plan，可复现性不破 | P2 | ✅ 已交付（NL → config-patch 前端除外，规范中即标为可选）：有界重规划（§9，`llm/plan.json` + 轮次目录 + 闭合动作词汇表）、`@media print`、TUI `[llm]` 字段、可选 LLM 门禁（`[review] gate_includes_llm`）、`docs/usage.md` 第 12 章 |

每期独立可 ship、测试全绿、不改前一期的契约。

**实现期间对设计的三处修正**（都由实测推翻了设计时的假设）：

1. **上游确实提供 token usage**（附录 A #11 记为「未验证」）。2026-08-24 对 GPU 主机实测：
   每次模型回复都带 `{"chunk":{"type":"usage","usage":{"inputTokens","outputTokens"}}}`。
   于是 `llm.budget.measured` 记录提供方自己的计数；估算仍是调度依据（预算必须在派发前
   决定），但两者不相等且差异是结构性的，见 `docs/llm-scan-architecture.md` 的 token 账本节。
2. **validator 需要自己的步数上限**。第一次实测 `assess` 时，validator 在 scanner 的
   4 步上限下被截断——它要用文件工具回溯调用者，这正是设计要它做的事。新增
   `[audit] validation_max_steps`（默认 12）后，同一批候选给出了正确的 CONFIRMED 与
   FALSE_POSITIVE。
3. **`llm-logic` 的闭合 token 集需要反例，不只是定义**。首轮实测中它把「缺少 NULL 检查」
   报成了 `dead-code`。skill 升到 1.1.0，显式写明四个 token **不**包含什么。

**与既有设计 §12 分期的对应**（评审指出初稿复用了期号却换了内容）：既有 Phase 0–1 已实现；
既有 Phase 2（三个 Skill、风险图、预算、`llm-resume`、`llm-doctor`）中前三项已实现，后两项归入本文 P3；
既有 Phase 3（Correlator、Validator、audit、README）对应本文 P1 + P2；既有 Phase 4（TUI 字段、
LLM 门禁、usage.md）归入本文 P4。既有设计 §2.2 的 `process.py` 复用承诺未兑现，见 §8。

---

## 附录 A：规范中的过度设计与更便宜的等价物

| # | 规范项 | 为何过度 | 等价物 |
|---|---|---|---|
| 1 | 字面意义的 Main Agent | 在模型里重新实现 `inventory` / `index` / `risk` / `units` / `doctor`；不确定；数千行 | 确定性主干 + ≤3 判断点（§2） |
| 2 | Logic Review 按排除法定义 | 即"找一切问题"，既有设计 §5.1 禁止；按构造就是建议形态 | 闭合 token 集（D4） |
| 3 | FastAPI / WebSocket / dsh UI | 5–20 传递依赖；WebSocket 对只读展示无增益 | stdlib SSE（D3） |
| 4 | Docker / rlimit | README:9；`preexec_fn` 线程池下不安全 | 输出字节上限进 `ProcessResult` |
| 5 | `plan.json`/DAG 作为节点状态源 | `manifest.json` 已原子重写、已是 `rebuild-dashboard` 的输入 | `graph(manifest)` 纯派生 |
| 6 | cppcheck ∥ splint | 都吃 CPU | 提高 `splint.jobs` 默认值 |
| 7 | PDF | 唯一无机器消费者、唯一需要依赖的格式 | `@media print` |
| 8 | Aggregator 再归一化 severity / 评估 confidence | 已两套版本化映射；违反 "native severities retained" | confidence 归 `verdict` |
| 9 | `agent` 独立于 `source`；4 态 status；`retries` | `producer` 是唯一轴；status 是两轴；零重试逻辑 | 全部删除 |
| 10 | 按调用图切 chunk | 破坏"每字节恰好一次" | 调用图作上下文 |
| 11 | 实时 token 表盘 | 本项目侧无 usage 字段；上游是否提供未验证 | P1 估算 + 永远附带说明；P3 验证上游 |
| 12 | "一切实时可观察" | cppcheck/flawfinder 无心跳 | 6 行心跳 |

## 附录 B：用户已锁定的决策

| # | 决策 | 取值 |
|---|---|---|
| D1 | 章程 | 修订 README:9-11；merge / FP / recommendation 全部限在 `audit/`。**时点改为 P1**（评审订正：`audit/` 在 P1 落地，README 必须同期改） |
| D2 | 默认路径 | 全确定性；validator 走 `assess`；`max_replan_rounds = 0` |
| D3 | Web 面 | stdlib SSE 的 `serve` 命令，零新依赖 |
| D4 | Agent 名单 | Resource/Error + UB（重切）+ Logic（闭合 token）全上；预算按 scanner 数自动缩放 |
| D5 | 词汇与 SARIF | Skill / Adapter / Scanner / Producer / Manifest 如 §0；SARIF 中 LLM 行独立 `runs[]` |
| E1 | 快路范围（2026-09-03） | 只有 `/命令` 与裸路径走 0ms 确定性；其余一切自动交给模型，关键词简写表删除 |
| E2 | 自动执行 | 只读的直接跑（`doctor`/`preflight`/`config`）；写入、花钱、阻塞的逐项确认 |
| E3 | 「插件」 | 就是注册表里的 action（当时 12 个，现 14 个），不做用户自定义命令文件 |
| E4 | 等待时的输入 | 可以继续敲，自由文本排队；`/命令` 不排队；`Esc` 清空 |
| E5 | 自动执行集 | 当时恰好三个（`/model` 于 2026-09-04 加入，同一条规则）。`llm-doctor` 不写文件但是一次计费的真实生成：手敲=同意，模型推断=不同意 |
| E6 | 回答通道 | 只路由不回答；模型的自由散文永不上屏 |

## 附录 C：代码锚点索引

| 锚点 | 内容 |
|---|---|
| `tools/__init__.py:4-13` | `TOOL_NAMES` / `LLM_PRODUCERS` / `PRODUCER_ORDER` |
| `tools/cppcheck.py:14`、`flawfinder.py:30`、`splint.py:19` | 三个签名不一致的 `run()` |
| `tools/cppcheck.py:69` | `--quiet`，无心跳 |
| `tools/splint.py:128, 165` | `heartbeat=` 传法；`ThreadPoolExecutor` |
| `analysis.py:25, 36, 58, 61` | `AnalysisEvent` / `CancellationToken` / `EventSink` / `run_analysis` |
| `runner.py:172` | `_analyze` 确定性主干 |
| `runner.py:211` | `output_root` 不得在被扫描树内 |
| `runner.py:59-78, 81` | 并发窗口的常量与权重；`_Window`（progress 的唯一取值处） |
| `runner.py:123` | `_run_together`：静态在调用线程、LLM 在工作线程 |
| `runner.py:78` | `CONCURRENT_PHASES`，串行对照路径（不是配置项） |
| `runner.py:358` | `running` 占位态插入点 |
| `runner.py:704-707` | `_incompatibility` 的字典索引，真正的 `KeyError` 崩溃点 |
| `runner.py:399, 447` | LLM 阶段 `run_llm()`；源码稳定性复扫 |
| `runner.py:184` | `event()` 闭包 |
| `runner.py:318` | `run_static()`：三个静态工具的串行循环 |
| `runner.py:309, 659` | `manifest_lock` / `_save_manifest` |
| `review.py:28, 36, 46` | `_producer_rank` / `build_review` / `parsers`（崩溃点） |
| `review.py:368` | `should_fail` + `gate_eligible` |
| `review.py:783` | `_parse_llm_units` |
| `review.py:893` | `_report_integrity`，validator 作为参数注入 |
| `review.py:1181, 1203` | `_CWE_CATEGORIES`；静态关键词表的 `buffer` 规则 |
| `review.py:1031` | `_normalize_severity` |
| `review.py:1120, 1135` | `_deduplicate` / `_fingerprint`（均含 `tool`） |
| `review.py:1212, 1239` | `_LLM_KEYWORD_CATEGORIES` / `_finding_category` |
| `review.py:1270, 1299` | `_build_overlap_groups`（只认 `TOOL_NAMES`）/ `_emit_overlap` |
| `llm/scan.py:54, 60, 119, 381, 549, 663` | `TOKEN_ACCOUNTING` / `run` / rounds 缝 / `_Phase` / `_reserve` / `_provider_stop` |
| `llm/units.py:51, 140, 312-314, 324-336, 347` | `build_plan`（字节稳定）/ `coverage_report` / 项目级类型解析 / `unit_id` 不含 tier / 调用图键去路径 |
| `llm/index.py:188, 236-238, 803, 829` | `build_index` / 项目级 `_definition_table` / 调用图键 `path::name` / `_symbol_table` 同名合并 |
| `llm/context.py:33, 52` | `TIER_BUDGETS` / `build_unit_prompt` |
| `llm/risk.py:104` | `classify` |
| `llm/skills.py:75, 84` | `skill_names` / `load_skill` |
| `harness/schema.py:26, 75, 95, 121, 295` | `FINDING_CATEGORIES` / `FINDING_SCHEMA` / `evidence` 字段 / `parse_findings` / 保留的键 |
| `harness/session.py:73` | `run_unit` |
| `harness/runtime.py:80-88, 185, 251-253, 263-266, 323` | `RunOutcome`（本项目侧无 usage 字段）/ `HarnessRuntime` / cwd 非边界的上游原话 / 透传的两个超时 / SDK 自行 spawn |
| `harness/cordis.py:21-28, 80, 86, 115, 211-217` | 未验证段的如实记录 / `UNENFORCED_UPSTREAM` / `FORBIDDEN_TOOLS` / `cordis_document` / `includeDefaultRoots: false`（已验证的控制） |
| `process.py:67, 82` | `ProcessResult` / `run_process` |
| `status.py:15-40, 43` | 状态梯子 / `overall` |
| `sanitize.py:32, 224, 309, 322, 373-383` | `_SESSION_EXPORTED`（`findings.json` 总是导出）/ 导出时重渲染 / `_quotes_source` / `_export_files` / `.sarif` 处理 |
| `recovery.py:21, 68` | `recover_report` / `analyzers_invoked = False` |
| `dashboard.py:15` | `rebuild_dashboard` |
| `html_report.py:27, 72, 349-353, 357-486, 496, 761, 854-857` | `MAX_EMBED_FINDINGS` / `render()` / `make()` / `I18N` / `safeHref` / `compPanel` / 四处调用 |
| `config.py:17, 58, 78-81, 117, 191-197, 306, 361, 439-442` | `DEFAULTS` / `scanners` / `audit` / `FIELD_REGISTRY` / `_ALLOWED`（`llm` 段自动派生）/ `validate_config` / `_validate_llm` / `effective_toml` 固定段表 |
| `cli.py:21, 76` | `parser` / `--llm-scanner` |
| `inventory.py:34`、`doctor.py:24`、`preflight.py:32` | 确定性的"项目分析" |
| `persist.py:14` | `json_bytes` |
| `tui.py:620` | TUI 消费事件流 |
| `tests/test_runtime_output.py:200` | progress 单调断言（纯静态） |
| `tests/test_concurrency.py` | 并发窗口：单调、真重叠、证据字节不变、双侧 cancel、事件日志双写 |
| `tests/test_llm_index.py:287` | 单元计划字节稳定 |
| `tests/test_dashboard.py:72, 131` | 两个 `<script>`；重建字节幂等 |
| `tests/test_v2.py:175` | 无 `http://` |
| `tests/test_skills.py:79, 93-103, 105` | Skill 名与 `LLM_PRODUCERS` 一致；注入拒绝条款；类别不相交 |
| `tests/test_tui.py:49` | `FIELD_REGISTRY` 覆盖每个叶子 |
| `tests/test_producers.py:30` | 静态 `overlap_groups` 字节钉死 |
