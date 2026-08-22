# 智能代码审查平台架构：融合版设计

本文档回应「Multi-Agent Code Review Platform」规范的 18 项交付物。
它不是从零设计，而是把规范逐项对照本仓库的现状：哪些已经存在，哪些可以扩展，
哪些与既有契约冲突，哪些是规范自己原则意义上的过度设计。

每一节标注判定并锚定到真实的 `file:line`（基于 HEAD `be723e1`，295 tests，ruff 干净）。

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
| Skill | 静态工具的包装（`cppcheck/SKILL.md + runner.py`） | 给模型看的 Markdown 指令（`llm/skills.py:49`），被挂为 agent 的 skill root（`harness/cordis.py:133-139`） | **仓库用法**。照搬规范会让工具包装文档**可被扫描模型调用**——正是 `cordis.py:136-138` 堵住的注入洞，且炸掉 `tests/test_skills.py:79,93-103` |
| Scanner | 静态工具 + AI agent 的并集 | **只指 LLM**：`summary["scanners"]`、`[llm] scanners`（`config.py:58`）、`--llm-scanner`（`cli.py:76`） | **仓库用法** |
| — | — | `PRODUCER_ORDER`（`tools/__init__.py:13`）= 静态 + LLM 的并集 | **Producer** = 规范的"Scanner" |
| — | — | `tools/__init__.py:1` 自称 "adapters" | **Adapter** = 规范的"Skill"（静态工具包装） |
| — | — | 不存在 | **Producer Manifest** = 新增的声明块 |

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
                          ▼  (独立命令，显式调用)              │
                  ┌── audit 层 ──────────────────┐            │
                  │ Correlator  → candidates     │            │
                  │ Validator   → verdict 标签    │            │
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

可选的自然语言前端（"帮我重点看内存安全和硬件相关问题"）放在 `_analyze` **之外**：
NL → 受约束的 config patch（只能改 `[llm] scanners`、`risk_overrides`、`min_tier`）
→ `validate_config`（`config.py:306`）→ 正常确定性运行。
主干对 NL 前端无感知。

规范的流程 "理解需求 → 分析项目 → 制定计划 → 选择工具 → 执行扫描 → AI 深度审查 →
汇总 → 去重/验证 → 生成报告" 与主干一一对应，只是其中只有"AI 深度审查"和"验证"是模型步骤。

### 2.3 Orchestrator 是新的提示注入面

既有设计 §11.4 已把被扫描源码当作送给持有 `fs` 工具的 agent 的不可信输入。
一个读取中间结果来重规划的 orchestrator 引入**第二个**注入面：finding 的
`message` / `description` 是模型写的文本，可能被源码里的注入内容污染。

硬规则：**重规划决策只消费结构化字段**——各类别计数、severity 分布、tier 分布、
路径、`unscheduled` 数——**永不把 finding 的自由文本喂给规划模型**。

### 2.4 规模

确定性主干留在 `runner.py`；新增的是三个钩子与它们的证据落盘。估算 500–700 行生产代码。

---

## 3. Agent / Tool / Skill 的接口设计 — EXTEND

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
新增一个静态工具今天需要改约 21 处，其中 **4 处是崩溃点**（不改就 `KeyError`/`ValueError`）：
`runner.py:214,220`、`review.py:46`（`parsers` 字典）、`doctor.py:49,140`。

### 3.2 Adapter 协议（P2）

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

`review.py:654 _report_integrity()` 已经把 validator 当作参数注入——它是分析层唯一一处
按值传递 per-tool 行为的地方，是这个协议的雏形。

### 3.3 LLM 侧接口已存在

| 层 | 接口 | 位置 |
|---|---|---|
| 运行时生命周期 | `HarnessRuntime`（上下文管理器、`run()`、取消、超时） | `harness/runtime.py:185` |
| 单元会话 | `run_unit()` → unit 记录 + 四个证据文件 | `harness/session.py:73` |
| 输出契约 | `FINDING_SCHEMA`（`additionalProperties: False`）+ `parse_findings()` 宽松解析/严格校验 | `harness/schema.py:75,121` |
| 工具授予 | `cordis_document()`，allow-list，`FORBIDDEN_TOOLS` 含 `shell` | `harness/cordis.py:115,86` |
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

### 4.2 Producer Manifest（P2）

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
3. **`LLM_PRODUCERS` 从磁盘派生**（扫描 `skills/` 目录），使"放进一个目录就注册"对 LLM
   scanner 成立；frontmatter 的 `allowed-tools` 接到 `cordis.py:139`，成为工具授予的权威来源。

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
| `evidence`（源码原文） | — | **CONFLICTS**：`llm/sessions/**` 正因引用源码才被排除出 ZIP（`sanitize.py:309 _quotes_source`），而 `review/summary.json` 总是导出。按 `[llm] export_sessions` 门控，或在 redactor 剥除 |
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

用户已决定（D1）：**P2 修订 README:9-11**，措辞改为"证据层永不合并、永不判误报；
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

## 6. Event Schema — EXTEND；运行级事件日志是 NEW

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

发射点：`runner.py:185-194` 的闭包；`llm/scan.py` 的 `_forward` 与心跳。
消费者：CLI `ProgressDisplay`、TUI（`tui.py:620 _analysis_event`）。
`EventSink = Callable[[AnalysisEvent], None]`（`analysis.py:58`）是接入缝。

LLM 单元级别已有 `llm/sessions/**/events.jsonl`。**运行级**没有——只有 `logs/runner.log` 文本。

### 6.2 规范的事件字段对照

| 规范字段 | 现状 | 判定 |
|---|---|---|
| 当前阶段 / agent / tool / 文件 | `phase` / `tool` / `unit` | EXISTS |
| Tool command | unit 记录的 `process.argv`（`process.py:67 ProcessResult`）在 manifest 里，不在事件里 | EXTEND：事件加 `argv` |
| 执行时间 | `timestamp`；duration 在 manifest | EXISTS |
| 已发现 finding 数 | LLM unit 完成时可知；静态工具只有报告解析后才知 | EXTEND：LLM 实时、静态事后 |
| Token usage | **SDK 不报 usage**（`harness/runtime.py:80 RunOutcome` 无计数字段）；`scan.py:54 TOKEN_ACCOUNTING` 是估算 | 显示估算并**永远附带**说明；加一条结构化 budget 事件（今天只在心跳散文里，`scan.py:614-617`） |
| stdout / stderr | `stream` 字段 + 增量行转发 | EXISTS |
| Error / Retry | error 有；**仓库零重试逻辑** | `retries` 字段永远是 0，OVERREACH |
| Pending / Running / Success / Failed | 状态梯子有 10 个词（`status.py:15-40`），`partial ⇒ exit 10` | UI 侧投影函数；**绝不持久化 4 态**。真正缺的只有 `running` 过渡态：`runner.py:202` 后加占位并 `_save_manifest`（~10 行） |

### 6.3 运行级 `events.jsonl`（P1）

在 `analysis.py:61 run_analysis()` 的 `events=` 缝上挂一个 JSONL sink，写到
`<run_dir>/events.jsonl`。每行一个 `AnalysisEvent` 的 JSON。规则：

- 经 `progress.single_line()` 过滤，与终端输出同源
- 加入 `sanitize.py:322 _export_files` 的排除表（它含路径与工具输出）
- 标注非权威：它是进度日志，不是证据；证据是 manifest 与各 producer 的原生报告
- **静态工具心跳**：cppcheck 以 `--quiet` 跑最长 7200s（`cppcheck.py:69`，`config.py:84`）
  **没有心跳**，flawfinder 同。按 `splint.py:128` 的 `heartbeat=` 传法加上（~6 行）。
  这是"一切实时可观察"没人列出的前置条件。

---

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
相关 struct、宏、header、caller/callee——现状已做到，**但 header 是近似的**：
`index.py` 不解析 `#include` 指向的文件，只解析同一文件内的符号。

两处 NEW：
1. **include 图 + 头文件配对**（`index.py:227,494-510,798-812` 是接入点）：让一个 `.c` 的
   unit 能带上它 `#include` 的本项目头文件里的 struct/宏定义
2. **路径限定的调用图键**（`units.py:345`）：同名静态函数在不同文件里今天会混淆

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

规范要求的隔离：

| 项 | 现状 | 判定 |
|---|---|---|
| subprocess isolation | 进程组、`shell=False`、`stdin=DEVNULL` | EXISTS `process.py:82` |
| timeout | TERM → grace → KILL，有界 | EXISTS |
| resource limit | 无 | `preexec_fn` 在线程池下（`splint.py:165`、`scan.py:440`）不安全；Docker 违反 README:9 "does not install tools"。**改为输出字节上限**（`process.py:188,202`，~10 行），把 `truncated_bytes` 记进 `ProcessResult`——截断成为证据 |
| working directory isolation | `cwd` 限定；`output_root` 不得在被扫描树内（`runner.py:81`） | EXISTS |
| output size limit | 无 | 同上，P3 |
| Docker | 无 | 路线图：作为 `run_process` 的替代后端，返回同一个 `ProcessResult` |

---

## 9. 动态规划与重规划 — NEW，有界

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
               四个配置改动点（config.py:17 DEFAULTS / :191 _ALLOWED / :117 FIELD_REGISTRY /
               :439 effective_toml）；tests/test_tui.py:49 强制每个叶子有 FieldSpec。

预算           planner 的调用走同一个 _reserve (scan.py:549) 和同一个阶段 deadline。

硬规则         review.py / recovery.py 永不读 plan.json。
               它是"为什么这样扫"的证据，不是 review 的输入。

重放           --plan FILE 免费得到：缓存按渲染后的 prompt 做键，重放同一计划
               = 全部命中 = 零模型调用。recover-report 语义不变。
```

规范的升级例子——"cppcheck 报 `memcpy` 越界 → 调 Memory Agent 确认"——**不是重规划，
是 Validator**（§12）。第一轮 scanner 对静态结果盲（既有设计 §0.2 #1）；一个被静态结果
提示过的 agent 是第二轮角色。若按规范的框架做，`llm_only` 指标失去意义，
`by_scanner` 覆盖率会混入盲扫与提示扫。每条 finding 打 `round` 标记，
LLM-only 指标只数第 0 轮。

用户已决定（D2）：默认全确定性，`max_replan_rounds = 0`。

---

## 10. 并行执行策略 — EXISTS / EXTEND

### 10.1 现状

| 层 | 并行 | 位置 |
|---|---|---|
| splint 内部 | `ThreadPoolExecutor(jobs)` | `splint.py:165` |
| cppcheck 内部 | `-j min(4, cpu)` | `cppcheck.py:33,69` |
| LLM 阶段内部 | `ThreadPoolExecutor(jobs)` | `scan.py:427-467` |
| **三个静态工具之间** | **串行** | `runner.py:400` |
| **静态 vs LLM** | **串行** | `runner.py:249` 在工具循环之后 |

### 10.2 只有静态 ∥ LLM 值得做

cppcheck 与 splint 都吃 CPU，cppcheck 已经 `-j`；两者并行只是争抢。
LLM 阶段是网络绑定的，与静态并行几乎白赚壁钟。
把 `tools.splint.jobs` 默认从 1 提高（`config.py:92`）是更便宜的静态侧提速。

### 10.3 必须先修的前置条件

`tests/test_runtime_output.py:200` 断言 progress **单调**；今天 progress 按工具索引分段
（`runner.py:171-172`），LLM 固定 0.80–0.84（`runner.py:251-270`）。两个阶段并行后这会乱序。

先做：progress = 已完成工作量 / 总工作量，单调，加锁；或由调度器发一条聚合的
`phase="progress"` 事件。再做：共享 cancel `Event`（`splint.py:157-171` 模式）；
`manifest` 的 mutate + `_save_manifest`（`runner.py:236,244,460`）加锁。

源码稳定性复扫（`runner.py:275-293`）是后置条件，放在全部阶段之后；并发反而缩短窗口。

---

## 11. 聚合与去重策略 — EXISTS（证据层）/ NEW（意见层）

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
Correlator 用一个**变体**把完整的 LLM 词汇（`review.py:1212 _LLM_KEYWORD_CATEGORIES`）
同时应用到两个 engine 做分组——否则静态的 `CWE-190` 和 LLM 的 `integer-overflow` 永远对不上。

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

## 12. 验证策略 — NEW（既有设计 §7 已设计）

| 项 | 设计 |
|---|---|
| 角色 | 第二层，与 scanner 严格分离。只有它能同时看到源码 + 静态 findings + LLM findings + 调用关系 |
| 入口 | `code-analyzer assess REPORT_DIR`，独立命令，显式调用（D2） |
| 实现 | `_Phase`（`scan.py:381`）的另一种消费者：任务 = candidate 而非 unit；`VERDICT_SCHEMA` 作为 `FINDING_SCHEMA` 的兄弟；证据落 `llm/sessions/validator/<candidate_id>/` |
| 输出 | `verdict{label, confidence, rationale_artifact, model, skill_version, validator_saw_static: true}` 写回 candidate |
| 上限 | `[audit] validation_max_candidates`（`config.py:78`），按 severity × origin 排序优先验证 HIGH/CRITICAL |
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
  runner.py:43 _analyze       确定性主干；manifest.json 在 10 个检查点原子重写（runner.py:460）
  persist.py:14 json_bytes    唯一 JSON 编码器，字节稳定

新增（P1）
  serve.py                    stdlib ThreadingHTTPServer，绑定 127.0.0.1
      GET  /                  实时页（单文件 HTML，内联 JS）
      GET  /events            text/event-stream，尾随 <run_dir>/events.jsonl
      GET  /graph             graph(manifest) → {nodes, edges}
      GET  /manifest          manifest.json
      POST /cancel            CancellationToken.cancel()（analysis.py:36，~5 行）
  events sink                 JSONL EventSink，挂在 analysis.py:61 的 events= 参数

新增（P2）
  assess 子命令               §12

新增（P4）
  --plan FILE                 §9
```

用户已决定（D3）：stdlib SSE，**零新依赖**。FastAPI/WebSocket 各带 5–20 个传递依赖，
需要 doctor/preflight 的配套检查，而 WebSocket 对只读展示没有任何增益。

**不用 dsh 自带的 :3080 Web UI**：它违反四文件隔离（既有设计 §2.3），看不到静态工具，
且每个 unit 一个运行时（`scan.py:576-584`），没有"一次运行"的概念。

---

## 14. Web UI 架构 — EXISTS（离线）/ NEW（实时）

### 14.1 离线 dashboard 冻结不动

`html_report.py` 有五条被测试钉死的契约：

| 契约 | 测试 |
|---|---|
| 恰好两个可执行 `<script>` | `tests/test_dashboard.py:72` |
| 任何位置无 `http://` / `https://` | `tests/test_v2.py:175` |
| `safeHref` 拒绝含 `:` 的路径（故 `ws://` 结构上不可能） | `html_report.py:496` |
| 重建字节幂等 | `tests/test_dashboard.py:131` |
| 全部经 `textContent` 写入 DOM | `html_report.py:303-307` |

它是**可分享的证据报告**；`file://` 下 CORS 也挡住任何 fetch。把它改成实时页会同时打破五条。

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
- 双语：沿用 `html_report.py:312-426` 的 `I18N` 表结构

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
| 2 | review 行追加 `description`（+门控 `evidence`）、`line_start`/`line_end`、`function` | ~15 行 | `review.py:79-100, 824-843` |
| 3 | 抽 `group_nearby`；字节钉死 `overlap_groups`；Correlator + `audit/assessment.json`（candidate，无 verdict，`validation_unscheduled = candidates_total`） | ~300 行 | `review.py:1270-1296` |
| 4 | `code-analyzer serve`：SSE、`graph(manifest)`、`POST /cancel`、链接 `index.html` | ~250 行 | `analysis.py:36,58` |
| 5 | SARIF 2.1.0 导出：经 `persist.json_bytes`；每 producer 一个 `runs[]`；**LLM 行放独立 run**（`gate_eligible: False` 的 CI 语义在消费者侧得以保留）；`line` 为空时无 `region`；`recovery.py` 可重生成；进 `artifact_index`；字节稳定性测试仿 `test_dashboard.py:131` | ~200 行 | `review.py` 之后、`sanitize.py` 之前 |
| 6 | dashboard 加 candidate / origin 区。`compPanel`（`html_report.py:761`）**已经**接受 `series` 参数并已用于 engine 轴（`:856-857`）；origin 面板只是第五次调用加一个 `originSeries`，不是泛化任务。`I18N.zh` / `I18N.en` 各加键 | ~60 行 + i18n | `html_report.py:854-857` |

MVP 交付后即可回答"static-only / llm-only / both 各多少"，即便还没有 verdict。

---

## 18. 后续扩展路线

| 期 | 范围 | 解锁 | 前置 |
|---|---|---|---|
| **P1 可观察 + 已关联（MVP）** | §17 的 1–6 | origin 指标、实时视图、CI 接入 | 无 |
| **P2 已验证** | Validator `_Phase` 消费者 + `VERDICT_SCHEMA` + `assess` 子命令 + dashboard verdict 区（caveat 紧挨数字）+ **README:9-11 章程修订**；`Adapter`/`RunContext` 协议重构（消除 4 个崩溃点，字节钉死）；`LLM_PRODUCERS` 从磁盘派生；`allowed-tools` 接 `cordis.py:139`；`recommendation` 上 candidate | **`llm_only_confirmed`**——LLM 层存在的理由 | P1 |
| **P3 更快 + 更宽** | 先修进度模型再做静态 ∥ LLM（锁、共享 cancel）；输出字节上限；**三个新 scanner**：Resource/Error（枚举加 token + `_LLM_KEYWORD_CATEGORIES` 一行 + memory-safety 的"错误路径未释放"条款迁入）、UB（与 memory-safety **同一 commit** 按 空间/时间 vs 算术/语义 重切，两份 `skill_version` 同升，跨运行缓存失效）、Logic（**只接受闭合 token 集**：`state-machine` / `inverted-condition` / `dead-code` / `unreachable-branch`；拒绝"找一切逻辑问题"）；`total_*_tokens` 随启用 scanner 数线性缩放；include 图 + 头文件配对；`splint.jobs` 默认提高 | 壁钟 ≈ max(静态, LLM)；6 个 scanner；更准的上下文 | P1 |
| **P4 自适应** | 有界重规划（§9）：`llm/plan.json`、rounds 循环、动作词汇表、`--plan` 重放、`max_replan_rounds` 默认 0；可选 NL → config-patch 前端；`@media print`（替代 PDF） | Plan→Execute→Observe→Re-plan，可复现性不破 | P2 |

每期独立可 ship、测试全绿、不改前一期的契约。

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
| 11 | 实时 token 表盘 | SDK 不报 usage | 估算 + 永远附带说明 |
| 12 | "一切实时可观察" | cppcheck/flawfinder 无心跳 | 6 行心跳 |

## 附录 B：用户已锁定的决策

| # | 决策 | 取值 |
|---|---|---|
| D1 | 章程 | P2 修订 README:9-11；merge / FP / recommendation 全部限在 `audit/` |
| D2 | 默认路径 | 全确定性；validator 走 `assess`；`max_replan_rounds = 0` |
| D3 | Web 面 | stdlib SSE 的 `serve` 命令，零新依赖 |
| D4 | Agent 名单 | Resource/Error + UB（重切）+ Logic（闭合 token）全上；预算按 scanner 数自动缩放 |
| D5 | 词汇与 SARIF | Skill / Adapter / Scanner / Producer / Manifest 如 §0；SARIF 中 LLM 行独立 `runs[]` |

## 附录 C：代码锚点索引

| 锚点 | 内容 |
|---|---|
| `tools/__init__.py:4-13` | `TOOL_NAMES` / `LLM_PRODUCERS` / `PRODUCER_ORDER` |
| `tools/cppcheck.py:14`、`flawfinder.py:30`、`splint.py:19` | 三个签名不一致的 `run()` |
| `tools/cppcheck.py:69` | `--quiet`，无心跳 |
| `tools/splint.py:128, 165` | `heartbeat=` 传法；`ThreadPoolExecutor` |
| `analysis.py:25, 36, 58, 61` | `AnalysisEvent` / `CancellationToken` / `EventSink` / `run_analysis` |
| `runner.py:43` | `_analyze` 确定性主干 |
| `runner.py:81` | `output_root` 不得在被扫描树内 |
| `runner.py:171-172, 251-270` | progress 分段（并发前必须改） |
| `runner.py:202` | `running` 占位态插入点 |
| `runner.py:214, 220` | 硬编码 adapter 分派（崩溃点） |
| `runner.py:249, 275` | LLM 阶段；源码稳定性复扫 |
| `runner.py:460` | `_save_manifest` |
| `review.py:28, 36, 46` | `_producer_rank` / `build_review` / `parsers`（崩溃点） |
| `review.py:368` | `should_fail` + `gate_eligible` |
| `review.py:783` | `_parse_llm_units` |
| `review.py:1031` | `_normalize_severity` |
| `review.py:1120, 1135` | `_deduplicate` / `_fingerprint`（均含 `tool`） |
| `review.py:1212, 1239` | `_LLM_KEYWORD_CATEGORIES` / `_finding_category` |
| `review.py:1270, 1299` | `_build_overlap_groups`（只认 `TOOL_NAMES`）/ `_emit_overlap` |
| `llm/scan.py:54, 60, 119, 381, 549, 663` | `TOKEN_ACCOUNTING` / `run` / rounds 缝 / `_Phase` / `_reserve` / `_provider_stop` |
| `llm/units.py:51, 140` | `build_plan`（字节稳定）/ `coverage_report` |
| `llm/index.py:188` | `build_index` |
| `llm/context.py:33, 52` | `TIER_BUDGETS` / `build_unit_prompt` |
| `llm/risk.py:104` | `classify` |
| `llm/skills.py:75, 84` | `skill_names` / `load_skill` |
| `harness/schema.py:26, 75, 121` | `FINDING_CATEGORIES` / `FINDING_SCHEMA` / `parse_findings` |
| `harness/session.py:73` | `run_unit` |
| `harness/runtime.py:80, 185` | `RunOutcome`（无 usage 字段）/ `HarnessRuntime` |
| `harness/cordis.py:86, 115, 133-139` | `FORBIDDEN_TOOLS` / `cordis_document` / skill root |
| `process.py:67, 82` | `ProcessResult` / `run_process` |
| `status.py:15-40, 43` | 状态梯子 / `overall` |
| `sanitize.py:309, 322` | `_quotes_source` / `_export_files` |
| `recovery.py:21, 68` | `recover_report` / `analyzers_invoked = False` |
| `dashboard.py:15` | `rebuild_dashboard` |
| `html_report.py:27, 303-307, 496, 761` | `MAX_EMBED_FINDINGS` / `make()` / `safeHref` / `compPanel` |
| `config.py:17, 58, 78, 117, 191, 306, 439` | `DEFAULTS` / `scanners` / `audit` / `FIELD_REGISTRY` / `_ALLOWED` / `validate_config` / `effective_toml` |
| `cli.py:21, 76` | `parser` / `--llm-scanner` |
| `inventory.py:34`、`doctor.py:24`、`preflight.py:32` | 确定性的"项目分析" |
| `persist.py:14` | `json_bytes` |
| `tui.py:620` | TUI 消费事件流 |
| `tests/test_runtime_output.py:200` | progress 单调断言 |
| `tests/test_llm_index.py:287` | 单元计划字节稳定 |
| `tests/test_dashboard.py:72, 131` | 两个 `<script>`；重建字节幂等 |
| `tests/test_v2.py:175` | 无 `http://` |
| `tests/test_skills.py:79, 93-103, 105` | Skill 名与 `LLM_PRODUCERS` 一致；注入拒绝条款；类别不相交 |
| `tests/test_tui.py:49` | `FIELD_REGISTRY` 覆盖每个叶子 |
| `tests/test_producers.py:30` | 静态 `overlap_groups` 字节钉死 |
