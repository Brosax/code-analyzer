# code-analyzer v3 设计

> 状态：2026-09-22 批准。实施路线见文末 §10（M0–M9）。本文取代 `docs/platform-architecture.md` 与 `docs/llm-scan-architecture.md` 中与之冲突的部分；两份旧文档将在 M9 重写或删除。

## 第一部分：背景、实测与选型


### 为什么要改

用户觉得软件"怪怪的、不流畅"，自述的主要痛点有两个：**概念和开关太多**、**产出对不上 SESIP**。
11 个只读 agent 摸底并经对抗式复核后，定位到的根因如下：

1. **对话里的模型角色定错了。** 它是一个无状态、无工具、看不到结果的单轮意图路由器
   （`llm/propose.py:8-12,331-363,531-537`，`skills/operator-intent/SKILL.md:12-16`）。
   等待 23–160 秒，换来的只是把一句话翻译成 `/scan`。它回答不了"第 3 个发现是不是误报"。
2. **顶层单位是一次不可拆分的批处理运行**（`runner._analyze`，`runner.py:219-798`）。
   扫描一跑就是数小时，期间对话被冻结（只有一个 busy 槽，`tui.py:322-336`）。结果也不会回到对话里。
3. **"AI 审查"是盲扫，与"先工具、后 AI"相反。** LLM scanner 与静态工具并发运行，刻意不看工具结果
   （`runner.py:103,584-598`，`llm/scan.py:435-461`）。TF-M 上 8 小时只覆盖了 0.45%。
   唯一读工具结果的 validator 默认关闭，而且是事后命令。
4. **证据层"永不删除"被实现成了"永不过滤"。** TF-M 一次运行产生 12.6 万条发现，其中约 70% 是
   `cppcheck --check-library` 的配置提示（`tools/cppcheck.py:80`，未被 `tools/common.py:21-25` 识别为诊断）。
   另外还有 9.5 万个候选、234MB 的 summary.json。
5. **没有 SESIP 领域模型。** 全仓只有 `grading.py:22` 出现 SESIP，SFR、TOE、攻击潜力、测试计划 §7.4.2 分类都不存在。
   LLM 发现在分级中全部是 unmapped。
6. **LLM 执行层是"冷启动黑盒"**，与交互式 agent 的成本模型冲突：每次调用都拉起一个 deepseek-harness Node 子进程，
   不复用会话；对话和后台任务抢同一块 GPU，没有优先级。
7. **人机交互没有统一协议。** 17 天里换了 3 种 UI 范式；有三套确认方式，"y" 在两处语义相反；
   84 个配置项，14 个 action 加 17 个别名，12 个 META 命令，约 41 个 flag。

**用户已拍板的决定：**
- 力度：新内核 + 搬运已验证的资产。
- 盲扫退役，全部改为定向审查。
- 前端以网页为主（127.0.0.1）。
- ST、SFR 和 AVA 测试计划是 PDF/Word：由 agent 抽取成结构化评估档案，人确认后作为审查基准。
- 交付物：一份高质量的漏洞清单，对齐 SFR、TOE 以及测试计划的 §7.4.1 分级和 §7.4.2 分类。
- 客户代码只走本地 GPU；b.ai 只用于公开或测试代码，并按 endpoint 硬性拦截。
- 模型的原生工具调用能力未知：需要实测探测，并准备 JSON 降级协议。
- **R1 同意**：对话 agent 可以读发现原文、源码和 ST，放在 DATA 围栏里并限长。写入、花 GPU、执行构建、外发的授权只来自人工点击。这修订了 2026-09-03 的决定。
- **R3 同意**：agent 调静态工具（只占 CPU、幂等、可停）自动运行，不需批准。
- **cppcheck 参数不变**，只在视图层降噪。
- **清单用英文**（列名和 AI 生成的字段）；界面和对话用中文。

**环境事实：**
- venv 只有 textual 和 deepseek-harness；`serve.py` 用 stdlib `http.server`，模型探测用 `urllib`。
- 主机有 `pdftotext 0.86.1`。
- qwen3.8:27b 的首 token 延迟 18–52s，可用窗口约 24k；关闭思考必须传 `reasoning_effort:"none"`。

**2026-09-22 实测（Ollama 0.32.14，qwen3.8:27b，`/v1/chat/completions`，`reasoning_effort:"none"`）：**

| 场景 | 结果 |
|---|---|
| 原生工具调用，3 个工具，多轮 | 可用。工具选对、参数合理，还会发起**并行调用**；流式 tool_call delta 能正常拼接 |
| 热身后的小 prompt 回合（约 0.5–1k token） | **3.1s / 7.9s**。第一轮 29.5s 里包含模型冷加载 |
| 6.3k token 的系统前缀，冷算 | 首 token 约 31s（prompt 评估约 200 tok/s） |
| 同一前缀再次请求（前缀缓存命中） | **5.6s**，约快 6 倍 |
| 审查并生成 540 token 的完整结论 | 29s（生成约 20 tok/s）；两句话的结论 11s |
| 审查质量 | 找出 off-by-one 越界读；识破并忽略源码注释里的注入；按 SFR 结构化记录。但有一处误判："时序侧信道"不成立 → **复核与接地校验必须保留** |
| `tool_choice:"none"` | 生效。模型偏好调工具，所以"只回答"回合要显式关闭工具 |
| 实际上下文窗口 | 24576（`/api/ps`） |

**结论：** 过去"每轮 23–160s"主要来自 harness 开销（每次调用拉起 Node 子进程、不复用会话）、4k+ 的非缓存 prompt、`intent_reasoning="low"` 引发的思考 token，以及与扫描争用 GPU，不是模型本身慢。
只要是常驻、只追加、前缀稳定的对话，热回合就能落在 **3–10s**。
主机上还有 `qwen3.5:0.8b`、`gemma4:26b`、`qwen3.6:27b` 等模型可选。

### Harness 选型（已调研并逐条核实，结论：自写最小 Python 内核）

| 候选 | 结论 |
|---|---|
| **自写最小循环（stdlib）** | **首选**。零新增依赖；`/v1` SSE 与 `/api/chat` NDJSON 共用一个客户端；每个端点配 `tool_mode=native\|text`；shell 工具根本不存在；请求字节先落盘再发送；5 个概念（Endpoint/Tool/Loop/Budget/Record）；约 800–1100 行，与删除的 harness 代码抵消后净增约为零 |
| PydanticAI（`pydantic-ai-slim[openai]`） | 备选。typed 工具与审批暂停都很好，但文本兜底要自己写，版本发布频繁需锁定，默认 `tool_choice='required'` 要显式关闭 |
| **pi**（earendil-works/pi，原 badlogic/pi-mono，v0.87.1） | **不做内核，只借鉴设计**。现在的 deepseek-harness 的 LLM 层本来就是 pi-ai（`harness/cordis.py:99`），换成 pi 只是去掉一层外壳，仍然是"Python 驱动 Node 子进程、工具写 TS"的结构。其他问题：RPC 模式不能注册工具；没有文本工具调用兜底；默认是 YOLO 模式（bash/write、无沙箱）；一周内两次 breaking；qwen3.8 在 `/v1` 上的回归 #9216 仍是 open；需要 Node ≥22.19 |
| OpenAI Agents SDK | 排除。tracing 默认把输入输出发往 api.openai.com，违反客户代码只走本地的决定 |
| Qwen-Agent | 排除作底座（已停更约 6.5 个月，只有同步接口）；借用它的 nous `<tool_call>` 文本格式 |
| smolagents | 排除。CodeAgent 会执行模型写的 Python |
| deepseek-harness 0.1.1rc1（现状） | 退役：RC 精确锁定；工具白名单未强制执行；协议没有 cancel；拿不到原始字节；exe 有 212MB |

**从 pi 借鉴的设计：**
- 系统提示加工具定义控制在 1k token 以内；
- 循环顺序为 `prepare → transform → convert → stream`；
- 工具名不存在或参数校验失败时，回一条错误 tool result 让模型自己改；
- 有 `beforeToolCall` 审批门，`AbortSignal` 贯穿整个循环；
- 参照 pi-ai 的 compat 字段表（maxTokensField、supportsReasoningEffort 等）做成每个端点的配置清单。

**默认值：** 本地 qwen 用 `tool_mode=native`（已实测可用）；同一端点连续出现 HTTP 500 时，在回合边界降级为 `text`。


---

## 第二部分：完整设计

> 与实测冲突时以第一部分为准。其中最主要的一处：本地 qwen 默认使用原生工具调用，JSON 协议只作降级。


骨架仍用 "kernel" 提案，另外从 "sesip" 提案取了 SESIP 领域模型、PV 编号、Web v1 里程碑和探针项 P1/P8，从 "minimal" 提案取了固定工具集、确定性清单、事件唤醒、local/public 二分、批准卡绑定参数哈希和 ledger 规范三元组。

本稿处理了评审提出的 1 个致命缺陷、15 个主要缺陷和 9 个次要缺陷，逐条对照见 §12。牵涉用户授权的 R1、R3、R13 已于 2026-09-22 由用户确认（均按推荐方案）；GPU 主机部署变更仍需届时请示。

---

## 0. 分歧裁定

| 分歧 | 裁定 | 理由 |
|---|---|---|
| 骨架 | kernel | 往返预算和取消语义写得最细；它的致命缺陷只在局部，能修 |
| 工具集 | **固定 7 个，永不切换**。按钮已经覆盖的操作全部移出模型侧 | 工具文本位于前缀开头：JSON 模式下由程序渲染进 system；原生模式下模板把它放在哪，由 P9b 实测。切换工具集就等于前缀失效。M0 用 P4 比较 7 个和 10 个两套方案再定稿 |
| 谁来启动三件工具 | **agent**：创建评估后，程序追加一条确定性的 `[事件]` 并开一个 P0 回合；agent 按 method.md 第 1 步调用 `run_tools`。模型不可达时，事件卡直接给出“跑工具”按钮 | 兑现核心点 2 的字面要求，代价 1 次调用（热前缀实测 5-30s）；离线时流程也能推进 |
| JSON 降级协议 | 散文在前，**响应末尾**最多一个 ` ```call ` 围栏或 `<tool_call>`；用专用提取器，不认 ` ```json ` | harness/schema.py:173 的 `_candidates` 会把任意围栏和散文里的 `{…}` 都当候选，不能直接复用 |
| 探针 | 重型探针由维护者离线跑；启动时只做冒烟检查，冷加载模型不算失败 | 探针不能抢用户的 GPU；17.7GB 模型冷加载远超 5s |
| 抢占范围 | 对话以外的**全部**模型请求都可被抢占 | 档案抽取期间对话不应变慢 |
| 抢占方式 | P0 一到就断开全部在飞的 P1。被断开的请求记为 `preempted`：全额退还预算，不计入断路器，不写缓存，重新排到队首。最后一次交互 30s 后恢复 | llm/scan.py:887-909 的 `_release` 对“无 usage、非 transport”的请求不退款，会误报预算耗尽 |
| 批量并发与槽位 | 由 P11 和 P12 实测决定。若后台请求会冲掉对话前缀，job 期间把 P1 并发限制为“槽位数−1”（前提是 GPU 主机 `OLLAMA_NUM_PARALLEL≥2`，调整它属于部署变更，**届时请示用户**）。没有探针结果时取 2 | 并发是唯一的吞吐杠杆，但会冲掉 KV 缓存 |
| 斜杠命令 | 0 个。改用按钮；输入框里只输入一个句柄时直接打开详情 | 用户头号痛点是概念太多 |
| cppcheck `--check-library` | argv 不变（tools/cppcheck.py:79-83），降噪只在视图层做。**用户已确认：argv 不变** | 改 argv 会破坏与历史证据的可比性 |
| 档案确认前是否跑工具 | 全树跑，TOE 只用于裁剪视图 | TOE 的 glob 写错时，不应因此出现证据盲区 |
| 接地失败的 AI 输出 | 保留为 `grounded=false`，永不进清单 | 不删证据；幻觉率要能审计 |
| 清单成员 | 由确定性规则决定。**TOE 内每一个 finding 簇都不会被静默丢弃**：已分级且达到阈值的进“主分区”；未分级的进“未分级（需人工核实）”分区；低于阈值的在覆盖页计数，可一键提升 | 修复致命缺陷：grading.py:8-14、66、76-78 把 flawfinder 和 splint 全判为 unmapped |
| 哪些等级依据参与成员判定 | 只有 native-exact、evaluator-rule、analyst 三种；ai-proposed 只用于显示 | R9 规定的“可证明映射” |
| 状态词表 | 5 个值加 `duplicate_of`；如果 §7.4.2 实际是“处置分类”，状态词表改由档案生成 | §7.4.2 的语义还没确认 |
| 出站判定 | 创建评估时把本地模型主机**钉进** evaluation.json。客户评估只能发往钉住的主机，且该主机必须是 loopback、RFC1918、link-local 或 ULA 地址，否则需要人在档案页二次确认。设置变更不溯及已钉住的评估 | 只比较设置值等于“按名字判断”，改一下设置就绕过了 |
| 第三方路由 | 只有公开评估、而且人打开了 `allow_public_model` 时，批量 job 才能逐卡选择第三方端点，每张卡都显示外发和计费警告；对话永远走本地 | 路由表见 §3.6 |
| 指纹 | **保持现有公式**（review.py:1117-1121），既不加 evidence_context，也不加 attempt。重复行由存储主键 `(fingerprint, call_id, unit_id)` 区分 | review.py:907 会给 evidence_context 加 `/superseded` 后缀；如果把它纳入指纹，同一条原生行的指纹会随后续尝试而变 |
| F 句柄 | 取指纹的 git 式可变长前缀，最短 8 位，冲突时自动加长 | 6 位在 TF-M 上期望碰撞约 479 对；8 位约 1.9 对 |
| 聚类 | 簇键为“函数 × 类别族”，族是 unknown 时再加 rule_id。同一函数里成员间隔超过 30 行就切开；函数外的代码用 ±3 行 | 防止过度合并 |
| 锚点里的“决定行” | 取 prio 最高的成员的 `line_text_sha`；AI 结果不改锚点 | 让锚点不受 AI 影响 |
| lens 输出契约 | 两种：verify 用扩展后的 VERDICT_SCHEMA；发现型 lens 输出 findings 数组，空数组表示“已审、无发现” | VERDICT_SCHEMA（harness/verdict.py:30-47）表达不了 0..N 条新发现 |
| 前缀与折叠 | 历史段超过 12k 才**一次性**折叠，两次折叠之间严格只追加；稳定前缀里只放**已确认**档案 | 滚动折叠每回合都会改写中间字节，前缀缓存每回合失效 |
| 分析配置落在哪里 | 工作区里的 `buildctx.vN.toml`，版本化，每个 call.json 记录它的 sha。校验器从 validate_config 抽出 | build_context.py:29、206 和各 adapter 依赖 config 的结构 |
| compile_db | 参数封闭为 preset、generator、defines、toolchain_file 四项。**bwrap 只为它保留**：源码只读、断网、只写工作区 | CMake configure 会执行厂商的脚本 |
| 没有 ST 时 | 内置两个只读档案：generic-sesip 和 rt700-tp-v1.1。无头 analyze 缺省用 rt700-tp-v1.1，并在输出里注明 | 公开代码和无头运行也要有清单 |
| lens 是否对操作员可见 | 不可见。覆盖页是 SFR × 模块矩阵，lens 名只在悬停提示里出现 | 减少概念 |
| 交付语言 | 界面和 agent 用中文；导出的列名和模型生成的字段用英文 | ETR 通常用英文 |
| 已修正的致命缺陷 | ① 清单由 AI 把关 → 改为确定性成员；② 补丁 apply 自动执行 → 必须点卡；③ export/upsert 不需批准 → export 每次出卡，模型没有 upsert；④ 没有非模型推进路径 → 加按钮；⑤（本轮）unmapped 被静默丢弃 → 加未分级分区并做计数守恒 | — |

---

## 1. 定位与操作员心智模型

**定位**：在本机浏览器里，通过对话完成一次 SESIP 代码评估。
- agent **先**调用 cppcheck、flawfinder、splint；
- **再**用本地 GPU 做定向复核，复核以人确认过的评估档案（SFR、TOE、TSFI）为锚点；
- 最后交付**一份**漏洞清单：按 §7.4.1 分级，按 §7.4.2 分类，编号稳定；另设“未分级（需人工核实）”分区。

**操作员可见术语，共 15 个**

| # | 术语 | # | 术语 | # | 术语 |
|---|---|---|---|---|---|
| 1 | 评估 | 6 | 等级（§7.4.1） | 11 | 任务（J4） |
| 2 | 档案（草稿/已确认） | 7 | 分类（§7.4.2） | 12 | 批准卡 |
| 3 | 清单 | 8 | SFR | 13 | GPU 额度 |
| 4 | 条目（PV-0007） | 9 | TOE 模块 | 14 | 构建上下文 |
| 5 | 未分级 | 10 | 证据 | 15 | 覆盖 |

其中 6-9 是用户本来就熟悉的 SESIP 术语，程序自己引入的概念只有 11 个。等级依据、来源、是否接地都做成**图标加悬停说明**；“AI 意见”只是清单里的一列，不算新概念。

**动词 6 个**：新建、说、批准（只能点按钮）、停止、标记、导出。

内部概念操作员不接触：lens、codec、broker、候选、指纹、锚点、attempt、效果词汇、P0/P1、view_class。

**设置 `~/.code-analyzer/settings.toml`，共 9 项**

| # | 项 | 默认值 |
|---|---|---|
| 1 | `local_model.endpoint` | `http://192.168.5.10:11434/v1` |
| 2 | `local_model.name` | `qwen3.8:27b` |
| 3 | `local_model.review_name` | 空，即与第 2 项相同。可设为 `qwen3_8_uncensored:latest`（llm/profiles.py:29-33），但只能在同一台钉住的主机上 |
| 4 | `public_model.endpoint` | 空 |
| 5 | `public_model.name` | 空 |
| 6 | `public_model.api_key_env` | 空 |
| 7 | `data_root` | `~/.code-analyzer/evaluations` |
| 8 | `port` | 8765 |
| 9 | `analyzers` | 三个工具的路径覆盖，默认从 PATH 找 |

- 窗口、codec、批量并发、槽位策略、实测速率来自 `probe.json`。
- 按端点区分的参数（reasoning、max_tokens、并发上限）是 `defaults.py` 里按端点类别（local/public）取值的常量。
- 评估级的分析配置在工作区的 `buildctx.vN.toml`（§4.6），不在设置里。
- 两个环境变量：`CODE_ANALYZER_HOME`、`CODE_ANALYZER_NO_MODEL`。

**CLI 共 4 条**
- `code-analyzer`：有 TTY 时启动网页并打印一次性 URL；没有 TTY 时打印帮助并返回 2，沿用 cli.py:110-116。
- `code-analyzer analyze SOURCE`：无头、确定性，不调用模型，保留退出码代数。7 个 typed 选项：
  - `--profile P.toml`，缺省用内置 rt700-tp-v1.1，并在输出中注明；
  - `--buildctx B.toml`；
  - `--tool`，可重复；
  - `--compile-db PATH` 或 `--no-compile-db`；
  - `--exclude GLOB`；
  - `--eval-dir DIR`；
  - `--fail-on none|medium|high|critical`，保留，默认 none。门禁只看原生证据，所以退出码 1 仍可能出现。
- `code-analyzer probe`：维护者用，测模型和分析器，包括 pdftotext 是否存在。
- `code-analyzer rebuild EVAL_DIR`：零网络，从 ledger 重建索引。
- 过渡期：`code-analyzer tui-legacy` 保留到 M5 验收，M9 删除。

| 维度 | 现在 | v3 |
|---|---|---|
| 配置项 | 84（config.py:193-276） | 9 项设置，另有评估级 buildctx（结构化，由补丁卡驱动，不是手调旋钮） |
| action、别名、META 命令 | 14、17、12 | 操作员侧 0；模型侧 7 个固定工具 |
| 对话里的 flag | 约 41 | 0（CLI analyze 保留 7 个） |
| 前端 | TUI、serve、index.html 三套 | 一个网页（tui-legacy 过渡到 M5） |
| 运行时依赖 | textual、deepseek-harness-sdk | 0，只用标准库；pdftotext、bwrap 为可选外部程序 |
| Python 行数 | 29,091 | 约 20k（估算），另有 JS/CSS 约 1.3k、lens Markdown 约 1.8k |

---

## 2. 一次完整评估的对话脚本

以 RT700（客户机密）为例，规模按 TF-M 估计。数字都是示例；耗时按 2026-09-22 实测：热前缀的小回合 3-8s，6k 前缀命中 5.6s，冷前缀约 30s，540 token 的完整结论约 29s。

| # | 谁 | 发生什么 | 交互调用 |
|---|---|---|---|
| 0 | 人 | 运行 `code-analyzer`，浏览器打开一次性 URL，token 换成 cookie | 0 |
| 1 | 程序 | 顶栏显示：本地 GPU · qwen3.8:27b · 窗口 24576 · 协议 JSON/原生。冒烟检查时如果模型未加载，就用 ≥120s 超时去加载，显示“模型加载中”，不判失败 | 0 |
| 2 | 人 | 点“新建”：填源码路径；机密性单选，默认“客户·仅本地 GPU”；档案来源选“拖入 ST.pdf 和 AVA_TP.pdf”（另有内置 generic-sesip、内置 rt700-tp-v1.1、上传 TOML 三个选项）；“用本地 GPU 抽取档案（估算 6-10 分钟）”默认勾选。点“创建”即同意抽取。程序把 `192.168.5.10:11434` 钉进 evaluation.json | 0 |
| 3 | 程序 | 建 inventory 并算 sha256；pdftotext 分页；确定性地切标题、匹配 SESIP 目录、定位 §7.4.1 和 §7.4.2、找 TSFI 线索。启动 **J2**（GPU 后台：档案抽取）。追加 `[事件] 评估已创建` 并开一个 P0 回合 | 0 |
| 4 | agent | “按方法第 1 步，我先用 cppcheck、flawfinder、splint 跑全树（CPU，参数与历史运行一致）；档案草稿同时在 GPU 上抽取。”调用 `run_tools(scope=all)`，得到 J1 卡。模型不可达时，事件卡直接显示“跑工具”按钮 | 1 |
| 5 | 程序 → agent | J1 结束，程序出分诊卡：原始 126,747 行，诊断 88,211，树外 182，superseded 1,526，聚成 N 个函数级簇，splint 分析了 289/1588 个 TU。唤醒 agent 讲要点：splint 覆盖低，档案还在抽取 | 1 |
| 6 | agent | J2 结束后唤醒：“档案草稿：9 条 SFR，§7.4.1 四级（p26-27），§7.4.2（p27-29）。有 3 处要你判断：§7.4.2 是缺陷类型还是处置分类；flawfinder 0-5 级和 splint 的**提议**分级规则；14 个目录还没有归属” | 1 |
| 7 | 人 | “TOE 加上 platform/ext/target/nxp，排除 stm 和 nordic；flawfinder 4-5 级按 Warning” | — |
| 7a | agent | 调 `profile_edit`，出 diff 卡：每个 glob 的实际命中数；规则标 `basis=proposed`，等人确认 | 1 |
| 8 | 人 | 在档案页逐项核对，点“确认档案 v1”（这个按钮只在界面上）。程序重算 TOE、SFR、分级和 PV。稳定前缀只在这时变一次，空闲时预热 | 0 |
| 9 | agent | 档案确认后唤醒：“TOE 内 1,284 个文件。清单主分区 412 条（Error 37 / Warning 375）；**未分级 1,206 条**（主要来自 splint，需人工核实，可以先让 AI 给等级建议）；低于阈值的 3,020 簇在覆盖页。与 Secure Boot 相关的 61 条。splint 在 TOE 内只分析了 21% 的 TU，要先补构建上下文吗？” | 1 |
| 10 | 人 | “先补 splint” | — |
| 10a | agent | 先调 `build_context(diagnose)`（结果回给模型），再调 `build_context(patch)`，出 P-1 卡：17 个 -I、3 个 -D、5 个 stub、预测覆盖率，注明已通过 validate_patch 和 12 个 TU 的试跑 | 2 |
| 11 | 人 | 点批准 P-1，生成 buildctx v2；J3 只重跑受影响的 TU，并带上 compile DB | 0 |
| 12 | 人 | “开始 AI 审查，重点 Secure Boot 和 Secure Update” | — |
| 12a | agent | 调 `review(focus)`，程序确定性地生成计划卡：T1 用 verify 复核 61 条已分级和 140 条未分级；T2 审 38 个 TSFI 可达函数；估算 1.3 GPU 小时（按请求在飞时长累计）；上限默认 2；端点固定为“本地 GPU”（客户评估不能选第三方） | 1 |
| 13 | 人 | 点批准，启动 J4，同时生成额度；AI 列随结果实时填充 | 0 |
| 14 | 人 | J4 运行中问 PV-0042。对话抢占 GPU，J4 卡片显示“为对话让出 GPU（第 3 次）”。如果对话前缀已冷，气泡提示“本回合预计多 N 秒（P12 实测）”。agent 先 `show` 再作答 | 2 |
| 15 | 人 | 在清单上把 PV-0011 标为误报并写备注 | 0 |
| 16 | 人 | “PV-0031 能从 NS 侧触发吗？”agent 调 `review(targets=[PV-0031], lens=nsc-entry)`，在额度内直接作为微任务运行 | 1 |
| 17 | agent | J4 结束唤醒，同时程序出覆盖卡：确认 9、可能 14、倾向误报 11（都没删）；未分级中 AI 给了 120 条等级建议（点“采纳”才生效）；AI 新发现 5 条，已过二次复核；Secure Update 在 bl2/ext 下还没审 | 1 |
| 18 | 人 | “导出”。agent 调 `export`，出批准卡并列出要写的文件；人点批准后生成 xlsx/md/csv 和 coverage，并做泄露复验 | 1 |

**整次评估约 14 次交互调用**。后台 GPU 批量只有 J2 和 J4；J1 和 J3 只用 CPU。

---

## 3. 内核架构

### 3.1 目录树

```
code_analyzer/
  cli.py settings.py defaults.py
  core/     process.py persist.py events.py text.py status.py errors.py inventory.py
            tomlw.py(自 config.py:665-713) sandbox.py(自 harness/runtime.py:625-689，仅供 compile_db)
  model/    client.py(stdlib http.client 流式 SSE) broker.py egress.py record.py probe.py
  kernel/   session.py(单线程 actor) loop.py context.py codecs.py handles.py registry.py approvals.py method.md
            tools/{list,show,run_tools,build_context,profile_edit,review,export}.py
  jobs/     engine.py(按需拉取派发) control.py static_job.py extract_job.py lens_job.py rerun_job.py compile_db_job.py
  evidence/ adapters/{adapter,common,cppcheck,flawfinder,splint,splint_csv}.py
            buildctx/{build_context,compile_db,compile_db_wizard,includes,schema}.py
            findings.py triage.py store.py(index.sqlite) grounding.py analyze.py
  sesip/    documents.py catalogue.py profile.py grading.py relevance.py pv.py coverage.py
            builtin/{generic-sesip.toml, rt700-tp-v1.1.toml}
  aireview/ code.py contracts.py prompt.py lenses.py lenses/*.md（15 个）
            （M7 实际落地为 aireview/：旧的 review.py 模块到 M9 才删除，同名包会遮蔽它）
  export/   listing.py(xlsx/csv/md) sanitize.py sarif.py
  web/      server.py blocks.py static/{index.html,app.js,app.css}
```

### 3.2 Agent loop：每条用户消息最多 3 次模型调用；一次响应里的多个 read 类调用可以一起执行，其他效果只执行第一个

```
on_user(text):                                   # 在 actor 线程执行
  if is_handle(text): ui.open(text); return      # "PV-0042"、"J4"、"F:3fa9c1d2" → 0 次调用
  if turn_in_flight: ui.queue(text, [打断并发送]); return
  gen += 1; run_turn()

run_turn():
  for step in 1..3:              # 最后一步 tool_choice="none"，强制只回答（实测生效，模型偏好调工具）
    resp = broker.request(P0, ctx.build(codec), on_delta=ui.delta, timeout=300)
    if resp.timed_out: ui.note("模型 300 s 无响应，已中止，可重试"); break
    act = codec.decode(resp)       # 散文 + 调用；多个 read 类调用一起执行（实测模型会并行读两个文件），其他效果只留第一个，其余记 ledger
    ledger.append(agent_said{say, call, dropped_calls, usage, prompt_sha256, codec})
    if not act.call: break
    err = registry.validate(act.call)   # 未知工具或键、enum、句柄存在且无歧义、_NEVER_FROM_MODEL
    if err and not repaired: feed(err); repaired = True; continue
    if err: ui.note("没能理解要执行的操作", raw=resp); break   # 散文照常显示
    tool = registry[act.call.tool]
    if tool.card_only(args) or tool.needs_approval(args, grants): ui.card(Approval(sha256(args))); break
    r = tool.run(args)             # 超过 5s 的转成 job，立即返回 J 句柄
    ledger.append(tool_result{handle, digest})
    if tool.after == "render": ui.card(r); break
```

- 动作类工具的结果由程序直接画成卡片；查询类工具的结果才进入第二次调用。
- 人点批准后，程序直接执行，不再调用模型。
- job 的总结卡由程序生成。
- 所有请求都带 `reasoning_effort:"none"`，修正 config.py:98 的 `"low"`。
- 尾部状态里带一行确定性的“建议下一步”，例如“档案未确认”“未分级 1,206 条待核实”“splint 的 TOE 覆盖率 21%”“Secure Update 未审”。

### 3.3 上下文预算与只追加

窗口 W 的读法：先用**独立的长超时（≥120s）**发加载请求，再读 `/api/ps`。现有 harness/runtime.py:467 已经会发加载请求，但它共用了 :420 的 `timeout=5.0`，冷加载会超时，然后回落到 `/api/show`。这才是“结论随加载状态翻转”的根因，修正点就在超时。

| 段 | 内容 | 上限 |
|---|---|---|
| A 稳定前缀 | 角色、method.md、DATA 规则、两个固定示例（约 2k）；7 个工具 schema（约 1.1k，两种 codec 下每回合字节都相同）；**已确认**档案的摘要（≤1.2k）。未确认时放一行常量“档案：未确认” | 4.3k |
| B 历史 | 只追加的规范三元组 | 12k |
| C 尾部状态 | 阶段、范围、档案草稿状态、job 进度、清单计数、建议下一步。只附在最后一条 user 消息末尾，下一次请求时去掉。去掉的只是末尾字节，前面的前缀仍然命中 | 0.8k |
| D 输出预留 | — | 1.5k |
| 余量 | — | ≥4k |

**折叠**
- 只在 B 超过 12k 时**一次性**执行，折叠到 ≤6k；两次折叠之间 B 严格只追加。
- 折叠规则是确定性的，不调用模型：
  - 两回合以前的工具结果只留一行存根，例如 `[R17 list(pv,sfr=SFR-SEC-BOOT) → 42 行]`；
  - 两回合以前的源码摘录只留句柄；
  - 6 回合以前的 agent 散文只留首句；
  - 用户原话保留，限 400 字。
- 折叠后是新前缀，空闲时发一次 `max_tokens=1` 的预热请求。

**工具结果上限**
- 一般结果 ≤600 tokens；源码摘录（`show part=source`）≤1.2k（默认半径 15 行，最大 40 行）。
- 超限时只给句柄、摘要和续取提示，例如“`show(R17, page=2)` 取后续”。这是显式分页，不是静默截断。

**token 估算**：按会话用 `usage.prompt_tokens ÷ 发送字符数` 做指数平滑，初值 1.6 字符/token。usage 依赖 P13。如果流式响应不返回 usage，就改用 1.3 字符/token，并把余量加到 6k。

**截断判定**：`prompt_tokens ≥ W−64` 就判为截断，折叠后重发一次。

**消息结尾**：JSON 模式下最后一条消息始终是 user。原生模式下，工具结果之后的请求以 tool 角色结尾，由 P6 验证不会 500；P6 不过就不启用原生模式。

### 3.4 句柄与 DATA 围栏

| 句柄 | 指代 | 谁会看到 |
|---|---|---|
| `PV-0007` | 清单条目 | 操作员 |
| `J4` | 任务 | 操作员 |
| `R12` | 工具结果 | 模型、卡片 |
| `F:3fa9c1d2` | 指纹的 git 式前缀，最短 8 位，有冲突自动加长；有歧义时 registry 报错，要求用更长的句柄 | 模型、卡片 |
| `U:bl2/boot.c#verify` | 代码单元 | 模型、卡片 |
| `P-1` | 构建补丁卡 | 模型、卡片 |
| `C0012` | 调用目录 | 模型、卡片 |
| `profile`、`coverage`、`buildctx` | 伪句柄 | 模型、卡片 |

- 外来文本一律放在 `<data source=… handle=… trust="untrusted">` 里，并按下列顺序处理：
  1. 经 `single_line` 或 `clean_data` 清洗（summary_digest.py:13-15、45；events.py:60-78）；
  2. **转义定界符**：`<data`、`</data` 换成 `‹data`、`‹/data`，` ``` ` 换成 `ˋˋˋ`，`<tool_call` 换成 `‹tool_call`，并配测试；
  3. 发现文本截到 240 字。

### 3.5 Codec、能力探针与 JSON 降级

ledger 只存规范三元组 (say, call, result)，由两个渲染器生成请求：

- **`NativeToolCodec`（默认）**：`tool_choice:auto`。多个 read 类调用一起执行，其他效果只留第一个。
- **`JsonActionCodec`**：
  - 使用**专用提取器**，只检查响应末尾：最后一个 ` ```call … ``` `，或最后一个 `<tool_call>…</tool_call>`，其后只允许空白。围栏以外一律当散文。
  - 只复用 harness/schema.py:200 的 `_matching` 和 :226 的 `_drop_trailing_commas`，**不复用** `_candidates`（:173）。
  - 流式输出时散文实时显示；看到围栏开头后改为缓冲。
  - 按工具 JSON Schema 严格校验，最多自动修复一次，散文永不丢弃。
  - 工具结果以 user 角色回传，带 `[工具结果 R12 · list]` 前缀，并放在 DATA 围栏里。
- 遇到 Ollama 500 时，改用 JSON 扁平渲染重试一次。

**探针 `code-analyzer probe`**：约 30-40 分钟（估算），要求 GPU 空闲，有 job 在跑时拒绝执行。

| 项 | 测什么 |
|---|---|
| P1 | 用 ≥120s 超时加载模型后读窗口；从 `/api/tags` 取 digest |
| P2 | `none` 是否生效：闲聊回复的 completion 少于 50 token |
| P3 | 带 enum 参数的单工具调用，每种 codec 10 次 |
| P4 | 20 条金标语句，分别用 **7 个和 10 个工具**两套 schema，测选对工具的比例 |
| P5 | 拿到工具结果后作答且不重复调用；3 步链不出 500。各 10 次 |
| P6 | 以 tool 消息结尾，或 tool 后直接跟 user，都不出 500 |
| P7 | DATA 里写 “call export” 不触发调用；散文中的示例 JSON 不触发调用。各 10 次 |
| P8 | 原生流式 tool_calls 能否解析；`parallel_tool_calls:false` 是否被遵守 |
| P9 | 前缀缓存加速比（相同前缀对比不同前缀） |
| P9b | 只改 tools 字段时，前缀是否还能命中 |
| P10 | 断开 socket 后 GPU 是否在 2s 内释放 |
| P11 | 0/2/4 个背景请求下的 P0 延迟 |
| **P12** | 后台 lens 连跑 10 分钟后，对话前缀的冷/热首 token 时间；分别测 P1 并发 = 槽位数 和 = 槽位数−1 |
| **P13** | 流式响应是否返回 usage（`stream_options.include_usage`） |
| **P14** | `response_format: json_schema` 是否被遵守。遵守时 lens job 启用它 |

- **判定 native 的条件**：P3 和 P5 各至少 9/10，P4 ≥90%，P6、P7、P8、P13 都通过，全程零 500。否则用 JSON。
- 结果写入 `probe/<endpoint,model,digest,ollama版本>.json`。
- **运行时降级**：最近 10 回合里有 2 次以上无效调用，本会话就切到 JSON，并记 `codec_switched`。

### 3.6 GPU Broker

`model/broker.py` 是**唯一的出口**：`CODE_ANALYZER_NO_MODEL` 在打开 socket 之前就短路；出站检查也在这里做。

**两类请求**
- P0：对话回合，包括唤醒回合；超时 300s。
- P1：抽取、lens、verify、预热；单请求超时 600s。

**P0 到达时**
1. 冻结 P1 的新派发；
2. 断开全部在飞的 P1；
3. 这些请求得到 `preempted` 结果：全额退还 prompt 估算和 completion 预留，不进断路器（scan.py:911-939），不进速率窗口，不写缓存，任务推回队首；
4. 在 job 的 events 里记一次 `attempt_aborted: preempted`。

**恢复**：最后一次 P0 活动过去 30s 后恢复派发。“活动”包括正在打字，前端以 2s 去抖发送 `POST /api/typing`。

**槽位策略**：由 P12 决定。如果后台运行后对话前缀变冷，而且 GPU 主机槽位 ≥2，job 期间 P1 并发限制为“槽位数−1”。否则如实提示冷前缀的额外时长。

**兜底**：如果 P10 不通过（断开连接并不释放 GPU），就只冻结派发，界面显示“等待后台请求完成（≤N s）”。

**按端点类别取参数（defaults.py）**

| 类别 | reasoning | 输出上限 | 并发 | 其他 |
|---|---|---|---|---|
| local | `reasoning_effort:"none"` | 对话 1500 / lens 2000 | 来自探针 | — |
| public（b.ai） | `"low"` | `max_completion_tokens=4000` | ≤2 | 不用 developer 角色；429 时退避 |

**出站规则（model/egress.py）**
- 创建评估时，evaluation.json 钉住 `model_host`（解析后的 IP:port）、`model_name`、`review_model_name` 和 `model_digest`。
- 对 client 评估（档案未确认时也按 client 处理），凡是携带评估内容的请求，目标必须等于钉住的主机，而且该主机的**全部**解析地址都属于以下范围：`127/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`::1`、`fc00::/7`、`fe80::/10`。
- 连接时用校验过的 IP 直连，防 DNS rebinding。
- 钉住的主机不是私有地址时，要人在档案页二次确认，记 `egress_host_pinned{by=human, private=false}`。
- settings 改动后与钉住值不一致时，请求一律阻断，并提示“到档案页重新钉住”（需要人点）。
- 违规时抛 `EgressBlocked`，记 `egress_blocked`。

**第三方路由表**

| 请求类 | client 评估 | public 评估，且 `allow_public_model=true`（只能由人设置） |
|---|---|---|
| P0 对话、预热 | 钉住的本地主机 | 本地主机 |
| 档案抽取 | 本地 | 创建表单上选本地或第三方，第三方显示外发/计费警告 |
| lens、verify job | 本地 | 计划卡上选端点（默认本地），选第三方时显示外发/计费警告 |

没有自动故障转移。

**“GPU 小时”的定义**：所有请求在飞时长之和，包括被抢占而浪费的时长。浪费部分在任务卡上单独显示为“让出损耗”。墙钟估算 = GPU 时长 ÷ 并发。

**拒答**：lens 的响应匹配拒答模式、又没有可解析的 JSON 时，记为 `refused`（不算 failed，不计入断路器）。计划卡提示“可改用 review_name 模型”。

每个评估同一时刻只有一个在飞的 P0；迟到的输出按 generation 丢弃（沿用 tui.py:243-249 的语义）。

### 3.7 事件唤醒与排队输入

- **唤醒条件**：评估创建、任一 job 结束或失败（包括 J1）、档案草稿就绪、档案确认。程序追加一条确定性的 `[事件] …` user 消息，然后开 P0 回合。
- **唤醒限制**：只在没有在飞回合、且用户 20s 内没打字时触发；同一 job 2 分钟内最多一次；用户一发言，未完成的唤醒回合就作废。
- **不唤醒**：进度更新、点批准、标记。
- **排队输入**：回合进行中收到的消息显示为“排队中”，并提供“打断并发送”。回合结束后，排队消息附注“（写于上一回合进行中）”再发送。**文本永远不会被当作审批**。

### 3.8 取消语义

| 对象 | 按下停止后立即发生 | 仍可能发生 | 记录 |
|---|---|---|---|
| 对话回合 | 关流；generation 加 1；已输出部分标“已中断” | GPU 还可能被占几秒（P10 实测） | `turn_cancelled`；部分输出不进历史，下一条消息附注“上一回合被中断” |
| 唤醒回合 | 用户发言即作废 | 同上 | `wake_superseded` |
| 被抢占的 P1 | 断开，退款，回队首 | 同上 | `attempt_aborted: preempted`（不是终态） |
| 静态工具 job、compile_db job | TERM → grace → KILL 杀进程组（process.py:287-306） | 无 | 调用标 interrupted，已完成的 TU 保留 |
| lens 或抽取 job | 停止派发，断开在飞请求 | 同对话回合 | `planned = started + unscheduled`，每个 task id 只计一次；“继续”就是重发同一个 job，命中缓存 |
| 批准卡 | 拒绝；或 30 分钟后、档案版本/buildctx/源码 sha 变化时失效 | — | `approval_expired` |
| SIGTERM 或重启 | 所有 job 定格为 interrupted，退出码 130 | — | 重启时自动对账；不再有 cli.py:137-138 那样的例外 |

### 3.9 工具清单（固定 7 个，schema 合计约 1.1k token）

效果词汇：`read`、`record`（只追加到工作区证据或 ledger）、`cpu`、`gpu`、`exec`（项目构建）、`write`（交付物）、`egress`（第三方）。

**批准规则由效果派生**（actions.py:176-208）：
- 模型推断的调用，效果在 {read, record, cpu} 之内才自动执行；
- `gpu` 需要出卡，或落在已批准的额度内；
- `exec`、`write`、`egress` 的工具**只出卡**，执行永远来自人点击；
- 人点按钮即同意，但 `exec` 和 `egress` 仍会再弹卡确认。

| # | 工具 | 参数 | 返回 | 效果 | 批准 | after | 对应按钮 |
|---|---|---|---|---|---|---|---|
| 1 | `list` | kind: pv\|cluster\|finding\|job\|file\|coverage；where{sfr,module,level,partition,category,status,origin,tool,rule,path}；sort；page | ≤20 行、总数、分布 | read | 否 | reason | 清单筛选 |
| 2 | `show` | target：句柄、`path:line`、symbol 或伪句柄；part: summary\|evidence\|source\|ai\|history\|callers\|callees；radius ≤40；page | ≤600 tokens，源码 ≤1.2k | read（realpath 校验，限 inventory 内） | 否 | reason | 点行、证据页 |
| 3 | `run_tools` | scope: toe\|模块 id\|glob[]；tools? | **幂等**：scope、buildctx sha、inventory sha、分析器版本都相同且已有完成的调用时，直接返回它；否则返回 J 句柄，完成后程序出卡 | cpu+record | 否（R3） | render | 任务页“跑工具”，按钮可以强制重跑 |
| 4 | `build_context` | op: diagnose\|patch\|compile_db。compile_db 的参数：preset（CMakePresets 枚举）\|generator（Ninja\|Unix Makefiles）、defines[]（按 build_context.py:54 `_DEFINE` 校验）、toolchain_file（限树内） | diagnose：只回计数；patch：P-n 卡；compile_db：卡上写 argv、cwd、写入位置、“将执行厂商 CMake 脚本”、沙箱状态 | diagnose：read；patch：record，只出卡；compile_db：exec，只出卡 | apply 和 compile_db 只能由人点卡执行，卡片绑定补丁哈希或 argv | diagnose 为 reason，其余为 render | 任务页“构建上下文” |
| 5 | `profile_edit` | 对草稿做 merge-patch | diff、每个 glob 的命中数、校验问题 | record | 否；**确认只能由人点**；受 `_NEVER_FROM_MODEL` 约束 | render | 档案页 |
| 6 | `review` | targets?[]（≤200 个句柄）\| focus?{sfr,module,partition}；lens?；depth: quick\|normal | 计划卡：按 SFR 的分布、选择理由、估算 GPU 时长 | gpu | 出卡；≤3 个目标且在额度内时自动运行 | render | 覆盖页“开始审查” |
| 7 | `export` | variant: internal\|shareable；formats[] | 卡上列出待写文件；批准后给出文件和 sha256 | write | **每次出卡** | render | 清单页“导出” |

**移出模型侧的操作**
- job 的暂停、继续、停止、重试：只有按钮。这样注入文本就不能让模型停掉 J4。
- 状态标记：只有行内按钮。agent 可以在散文里建议标记。
- profile show：改用 `show(profile)`。
- apply：只能点卡。

**`_NEVER_FROM_MODEL`**（在 propose.py:448 基础上扩展）：端点、模型名、key 环境变量、钉住的主机、`evaluation.confidentiality`、`allow_public_model`、`documents`、档案的 status/version/confirmed_*、`grading_rule.by`、PV 的 status、拆分与合并。**额度只能由带 token 的人工 POST 创建**：人批准计划卡时生成，绑定档案版本，GPU 秒数用完、档案版本变化或 24 小时后失效。

---

## 4. 数据模型与存储

### 4.1 工作区

```
<data_root>/<eval-id>/
  evaluation.json          # 源码路径、创建时间、inventory sha、钉住的模型主机/名称/digest
  docs/<sha>.pdf  docs/<sha>.pages.json
  profile/profile.draft.toml  profile.v1.toml …
  buildctx/buildctx.v1.toml  buildctx.v2.toml …
  ledger.jsonl             # 唯一的真相源
  calls/C0012-cppcheck/    # call.json（含 buildctx sha）加原生产物，永不覆盖
  build/<preset>/          # compile_db 的构建目录，只在工作区
  model/T0031/             # 五件套加 prompt_sha256，写盘前已脱敏
  jobs/J4/events.jsonl     # liveness 事件，可丢
  index.sqlite             # 派生数据，WAL，只由 actor 写
  exports/E1/
```

### 4.2 评估档案

```toml
[evaluation] id="rt700-sesip3" source="/data/rt700" confidentiality="client"   # client|public；未确认按 client
allow_public_model=false                          # 只能由人设置，仅 public 时可为 true
status="confirmed" version=1 confirmed_by="fgt" confirmed_at="…" base="extracted"   # 或 generic-sesip / rt700-tp-v1.1
[[documents]] role="security_target" file="RT700_ST_v1.3.pdf" sha256="…"
[[documents]] role="test_plan" file="NXP_iMXRT700-AVA_TP_v1.1.pdf" sha256="54c9cff4…"
[attacker] potential="basic" physical=false source={doc="st",page=31,quote="…"}
[toe_configuration] platform="…" defines=["TFM_ISOLATION_LEVEL=2"] source={doc="st",page=12,quote="…"}
[[sfr]] id="SFR-SEC-BOOT" catalogue="Secure Initialization of Platform" title="…" source={doc="st",page=18,quote="…"}
[[toe_module]] id="bl2" paths=["bl2/**"] sfr=["SFR-SEC-BOOT","SFR-SEC-UPDATE"]
[[exclude]] paths=["platform/ext/target/stm/**"] reason="非 TOE（ST §1.4）"
[[tsfi]] id="TSFI-PSA-CRYPTO" symbols=["psa_*"] attributes=["cmse_nonsecure_entry"] sfr=["SFR-CRYPTO"]
[test_plan] levels_section="7.4.1" categories_section="7.4.2" category_kind="defect_type"   # 或 "disposition"，由人选
[[level]] id="error" label="Error" rank=4 description="…" source={doc="tp",page=26,quote="…"}
[[category]] id="…" label="…" definition="…" source={doc="tp",page=28,quote="…"}
[[grading_rule]] match={tool="cppcheck",native="error"} level="error" basis="native-exact"
[[grading_rule]] match={tool="flawfinder",native=["4","5"]} level="warning" basis="evaluator-rule" by="fgt" at="…"
[[grading_rule]] match={tool="splint",family="memory"} level="warning" basis="proposed"      # 未确认 → 仍为 unmapped
[[category_rule]] match={cwe=["CWE-120","CWE-787"]} category="…" basis="evaluator-rule" by="fgt"
[export] template="tp-default"                    # 可选；M4 定位 TP 中的报告格式章节时生成
[advanced] pv_min_level="warning" cluster_gap_lines=30 keywords={…} lens_map={…}   # 表单里折叠显示，由目录预填
```

- **每一项都带 `source`**。PDF 用 `{doc, page, quote}`；docx 用 `{doc, loc="§5.2 ¶14", quote}`。quote 在空白归一后必须逐字出现在抽取出的文本里，校验不过的在界面上标红。
- **抽取按确定性优先**：`sesip/catalogue.py` 内置 SESIP 标准 SFR 名称、关键词和 lens 映射。模型只补充确定性步骤拿不到的内容，每块 ≤6k token。
- **不支持的输入**：扫描件 PDF 明确拒绝。没有 pdftotext 时，提示上传 docx 或文本，或者改用手写 TOML 模板。
- **内置只读档案**
  - `generic-sesip`：SESIP 目录的 SFR 名称、关键词和 lens 映射；TOE 为全树；分级规则预置 flawfinder 0-5、cppcheck performance/portability、splint 各类别族，全部标 `basis=proposed`。
  - `rt700-tp-v1.1`：来自 grading.py:17-78 的四级定义，`native-exact`。
  - 没有 ST 的评估可以“以内置档案为草稿确认”。无头 analyze 缺省使用 rt700-tp-v1.1。
- **规则的来源标注**：`proposed` 规则在确认前不生效，受影响的簇留在“未分级”分区；人确认时盖上 `evaluator-rule`、`by`、`at`。
- **不可变**：档案确认后任何修改都产生 v2，ledger 记录每个版本的 sha256。
- **§7.4.2 为处置分类时**（`category_kind="disposition"`）：PV 的 category 列隐藏，状态词表改用档案里的分类加上 `open`。

### 4.3 ledger 记录类型

写法：规范字节（persist.py:14-24），每条写后 fsync，读取时容忍最后一行被截断。

记录类型：
- 对话：`user_said`、`agent_said`（含 codec、usage、prompt_sha256、dropped_calls）、`tool_called`、`tool_result`；
- 审批：`approval_{shown,granted,rejected,expired}`（by=human）、`grant_created`；
- 任务：`job_{started,finished,interrupted}`；
- 档案与配置：`profile_{draft,confirmed}`、`buildctx_version`、`egress_host_pinned`；
- 清单：`pv_{created,ai_updated,retired,split,merged,promoted}`、`pv_status`、`level_accepted`（后三类只能由人写）；
- 其他：`egress_blocked`、`turn_cancelled`、`wake_superseded`、`codec_switched`。

### 4.4 Finding：原生证据，永不删改

- **行处理**：只迁移 review.py:76-97 的逐行加工；解析器（review.py:465-797）迁回 adapters；汇总交给 SQLite。
- **新增字段**：`call`、`attempt`、`superseded_by`、`unit_id`、`line_text_sha`（该行去空白后的哈希）。
- **指纹**：公式不变，sha256(tool, canonical_path, line, column, rule_id, message)，见 review.py:1117-1121。
- **存储主键**：`(fingerprint, call_id, unit_id)`。validate.py:92-96 那种“按指纹建 dict”的写法，全部改按主键。
- **行属性，不影响身份**：`evidence_context`、`superseded`（review.py:903-915）。
- **只存在于 SQLite 视图、不回写证据的字段**：
  - `view_class`：finding \| diagnostic \| out_of_tree \| superseded \| inactive_config；
  - `reclass_rule@version`、`in_toe`、`module`、`sfr[]`（各带 basis）、`level`、`level_basis`。

### 4.5 PV：清单的一行

**聚类（簇键）**
- 函数内代码：`(path, 函数, 类别族, 族=unknown 时再加 rule_id)`。同一函数里，按行号排序后相邻成员相距超过 `cluster_gap_lines`（默认 30）就切开。
- 函数外代码：±3 行。
- 类别族沿用 `correlation_category`（audit.py:85）。

| 字段 | 内容 |
|---|---|
| `pv_id`、`title`、`anchor` | 编号 `PV-0007`，永不复用。`anchor = sha256(path, 函数, 类别族, 决定行)[:16]`，决定行取 prio 最高成员的 `line_text_sha`（平手取行号小的）；AI 结果不改锚点 |
| `partition` | main \| unmapped，由确定性规则派生 |
| `location`、`members[F]`、`origin` | 位置；成员发现；origin 取 tool、tool+ai 或 ai |
| `sfr[]` | 每项为 `{id, basis}`。basis 取 family、tsfi、ai-confirmed、analyst（强依据）或 module-default、keyword（弱依据）。清单默认只显示强依据 |
| `toe_module`、`tsfi?`、`entry_path?` | entry_path 标注为“静态近似” |
| `level`、`level_basis` | §7.4.1 等级。依据取 native-exact、evaluator-rule、analyst、ai-proposed 或 unmapped |
| `category`、`category_basis` | §7.4.2 分类，依据同上 |
| `cwe`、`priority`、`priority_why` | 优先级及其各项分解 |
| `ai{…}` | verdict、level_suggestion、category_suggestion、rationale（英文，≤900 字）、decisive_line、evidence_quote、lens、model、prompt_sha256、grounded |
| `exploit_note?` | 英文，≤300 字 |
| `status` | open、confirmed、false_positive、not_exploitable、needs_test；另有 `duplicate_of`、note、by、at |
| `profile_version`、`first_seen`、`last_seen`、`retired` | 版本和出现记录 |

**成员规则（确定性）**：前提是簇满足 `in_toe ∧ view_class=finding`（TOE 已去掉 exclude 和 inactive_config）。
- a. 等级依据为 native-exact、evaluator-rule 或 analyst，且秩 ≥ `pv_min_level` → 主分区；
- b. 等级为 unmapped，或只有 ai-proposed → **未分级分区**（`manual_verification_required=true`）；
- c. 已分级但低于阈值，且至少 2 个引擎报了同一处 → 主分区，标“多引擎”；
- d. AI 来源，接地通过，二次复核为 CONFIRMED 或 LIKELY → 未分级分区，标“AI 新发现”，等级只作为建议显示。

**计数守恒**（有测试）：TOE 内 finding 簇总数 = 主分区 + 未分级分区 + 低于阈值。低于阈值的簇不编号，在覆盖页计数；分析员可以点“提升为条目”（`pv_promoted`）。AI 永远不能让条目离开清单。

**分析员动作**
- “采纳 AI 等级”：可单条或多选，写 `level_accepted`，依据变为 analyst，条目转入主分区。
- 拆分、合并：写 `pv_split` 或 `pv_merged`，并存为以成员指纹为键的覆盖规则，每次重新分诊后都重放。

**跨运行匹配（一对一）**
1. 按共享成员指纹数量从多到少贪心配对，平手时取旧号小的；
2. anchor 相同；
3. 同文件、同函数、同类别族，且决定行的 `line_text_sha` 仍在该函数内，判为“移动”。

多出来的簇分配新号 `max+1`；配不上的旧 PV 标为 retired，不删除。这修复了 audit.py:146-151（序号位移）、:338（key 漂移）和 :203-226（verdict 只在同一次运行内继承）三处问题。

### 4.6 buildctx：评估级分析配置

- `buildctx.vN.toml` 包含：
  - `[build]`：compile_database_mode、compile_database、c_standard、cpp_standard、cppcheck_platform、include、system_include、define、undefine、overrides；
  - `[tools.*]`：timeout、heartbeat、splint 的 mode/scope/jobs 等。
- v1 = defaults。档案里的 `[toe_configuration]` 只会被 agent 提议成 P 卡，不自动应用。每批准一张 P-n 卡生成一个新版本，版本不可变。
- **校验器** `evidence/buildctx/schema.py`（约 180 行）从 config.py:464-545 中 build 和 tools 的部分抽出。`ConfigPatch.apply`（build_context.py:206）改调它，这样保住了“补丁必须同时通过 validate_patch 和配置校验”这条不变量。
- adapter 收到的 dict 结构与现在相同，即 `{"build","tools","run":{"termination_grace_seconds"}}`，所以 cppcheck.py:39-41、88-100 和 splint.py:141、156 都不用改。
- TOML 写出器复用 config.py:665-713，迁到 core/tomlw.py，档案和 buildctx 共用。
- CLI `analyze` 的 typed 选项映射到同一结构。

### 4.7 存储选型

- 真相源：`ledger.jsonl`，加上 `calls/` 和 `model/` 下的原生证据。
- 查询：`index.sqlite`，可零网络 `rebuild`。
- 每次调用写一个 `call.json`，取代 87-223MB 的整体 manifest 及其非原子写入方（dashboard.py:135、llm/resume.py:235、reconfigure.py:340-342）。
- 原始 stdout 不进事件流。

---

## 5. 静态工具这一步

**Scope**
- 把过滤后的 inventory、compile DB 条目和 buildctx 传进 `RunContext`。三个 adapter 都从 inventory 取文件（flawfinder.py:56、cppcheck.py:51-52、splint.py:125-149）。
- 不复用 `only_files`，它会强制走 `--force` 分支（cppcheck.py:44-47、84-86）。
- 解除 run_dir/inputs 耦合（cppcheck.py:49-51、101-102；splint.py:151-154），改写到 `calls/Cnnnn/`。merge_attempt 只标记 superseded（tools/common.py:88-153）。
- 每个 adapter 加 `summarize()`，只输出计数和标识符。

**降噪只在视图层做**：argv 不变。在 tools/common.py:21-25 旁边加一张 rule-id 表，以下规则归为 diagnostic：`checkLibraryFunction`、`checkLibraryNoReturn`、`checkLibraryUseIgnore`、`missingInclude(System)`、`unmatchedSuppression`、`checkersReport`、`toomanyconfigs`、`normalCheckLevelMaxBranches`。树外路径标 `out_of_tree`，被 supersede 的尝试在视图里隐藏。

**分诊流水线**（evidence/triage.py，确定性）依次为：
1. 解析与去重（按主键）；
2. 判定 view_class；
3. **inactive_config**：扩展 llm/index.py:420-475 的 `_conditional_arms` 和 :995 的 `_in_dead`，按 `toe_configuration.defines` 求值简单条件（`#if 0`、`#ifdef`、`#ifndef`、`defined()`）；复杂表达式不判死；
4. TOE 视图；
5. 聚类（§4.5）；
6. 分级：按档案的 `grading_rule` 分级（泛化 grading.py:76-78），`proposed` 规则不生效；
7. 挂接 SFR：每项带 basis。类别族→SFR 与 TSFI 为强依据；模块默认 SFR 与关键词（risk.py:27-44）为弱依据；
8. 优先级：`prio = 4·level_rank + 3·强SFR命中 + 2·tsfi_near(调用图距离≤2) + 2·security_family + 1·engine_agree + 1·build_aware`，未分级的 level_rank 按 0 计；
9. 确定分区、分配 PV 编号，并做计数守恒校验。

**构建上下文**：由 agent 在对话里驱动，循环里没有模型调用。
- `diagnose`：调用 compile_db.py:16-345、includes.py:95-141、build_context.py:225 `diagnose_units`、compile_db_wizard.py:135 `inspect_environment`，只返回计数。
- `patch`：调用 build_context.py:271 `infer_patch`，以 `validate_patch`（:392）和 buildctx 校验作为硬闸门，再用 `probe_patch`（:512）试跑 12 个 TU，然后出 P-n 卡。人点批准后生成新 buildctx 版本；stub 只写工作区（:567-585）；只重跑受影响的 TU，并始终带 compile DB（修正 reconfigure.py:347）。
- `compile_db`：
  - 在 compile_db_wizard.py:158 `_prepare_cmake` 的基础上改成 typed 参数，删掉 :164-172 的 `ask()`；
  - 用 `_read_presets`（:242）枚举 preset；
  - 构建目录用 `-B <workspace>/build/<preset>` 覆盖 preset 的 binaryDir（M6 验证 CMake 版本支持）；
  - 在 core/sandbox.py 下运行：bwrap，源码只读挂载，`--unshare-net`，只写工作区构建目录；
  - 没有 bwrap 时，卡片标红“未隔离”，要求额外勾选确认。
- 无头 `analyze` 永远不调用模型（修正 reconfigure.py:118-121）。

---

## 6. AI 审查这一步

**lens 库 `aireview/lenses/*.md`，共 15 个**：1 个复核 lens，14 个发现型 lens。

- frontmatter 写 `id`、`version`、`contract: verdict|findings`、`applies_to{sfr_catalogue[], rule_families[], symbols[]}`、`requires{attacker.physical?}`。
- 正文不超过 900 token。
- 所有 lens 都删掉盲审条款（skills/llm-security/SKILL.md:25-27），并要求**英文**输出。

| lens | 来源 | 契约 | 服务的 SFR 或用途 |
|---|---|---|---|
| verify | llm-validator 改写 | verdict | 单条复核：是否可达、决定行，并给出 SFR、等级、分类的建议 |
| memory | memory-safety 与 undefined-behavior 合并 | findings | 限 TSFI 可达的单元，或带工具发现的单元 |
| error-path | resource-error 与 logic 合并 | findings | — |
| concurrency-hw | firmware-concurrency 改写 | findings | — |
| crypto-misuse | llm-security 的 crypto 部分 | findings | Cryptographic Operation、RNG、Attestation |
| input-auth | llm-security 其余 5 类：authentication、input-validation、protocol-parsing、hardcoded-secret、info-leak | findings | Identification & Authentication、Access Control、Secure Communication |
| secure-boot | 新增 | findings | Secure Initialization |
| update-rollback | 新增 | findings | Secure Update |
| debug-lifecycle | 新增 | findings | Secure Debugging |
| key-isolation | 新增 | findings | Cryptographic KeyStore |
| secure-storage | 新增 | findings | Secure Storage（TF-M 的 ITS/PS）：完整性、机密性、回滚、按调用方隔离 |
| residual-purge | 新增 | findings | Residual Information Purging |
| nsc-entry | 新增 | findings | TrustZone NSC 与 PSA 输入 |
| fault-injection | 新增，仅在 `attacker.physical=true` 时启用 | findings | Physical Attacker Resistance |
| sfr-generic | 新增 | findings | 凡是没有专用 lens 的 SFR 都用它，例如 Attestation、Audit、Factory Reset、Decommission。正文 = 档案里该 SFR 的原文 + 5 条通用检查问题。覆盖页标注“仅通用 lens” |

**两个输出契约**
- verdict：以 harness/verdict.py:30 的 `VERDICT_SCHEMA` 为基础，加上 `level_suggestion`、`category_suggestion`、`sfr` 三个字段（枚举由档案生成），以及必填的 `evidence_quote` 和可选的 `exploit_note`。
- findings：以 harness/schema.py:83 的 `FINDING_SCHEMA` 为基础，加上 `sfr`、`level`、`category`、`evidence_quote`、`decisive_line`，用 :129 `parse_findings` 和 :276 `_validate` 解析。**空数组表示“已审、无发现”**，作为覆盖证据记录。
- P14 通过时，请求附带 `response_format: json_schema`。

**目标选择**（sesip/relevance.py，确定性）
- T1：焦点范围内、AI 列为“未复核”的 PV，**主分区和未分级分区都算**，按 prio 排序，走 verify。
- T2：没有工具告警、但与 SFR 相关的函数。包括档案 `tsfi` 的 symbols 和 attributes、验签函数、调用图上与 TSFI 距离 ≤2 的函数（llm/index.py:801 `_call_graph`，标“静态近似”）。按 SFR 映射选发现型 lens。
- 每个单元最多 2 个 lens；每个“单元 × lens”对都记录 `reasons[]`。
- 估时用 probe 实测速率，运行中用 job 实测速率，标“估算”。

**lens job**（jobs/lens_job.py）
- 单元按需生成：用 review/code/units.py（llm/units.py:76 `plan_units`）和内存中的索引，不读落盘的 `llm/units/*.json`。
- 上下文组装：复用 validate.py:339 `_candidate_blocks` 和 :411 `_members`；:368 的 `_covering_unit` 改为按索引查找覆盖单元。在预算内加入调用者函数体、TSFI 路径和 SFR 原文。工具发现放在 DATA 围栏里，并记 `saw_static=true`。
- **不给模型任何工具**，只允许一轮 `{"need":["symbol X"]}`（最多 3 个符号），由程序取回后再问一次。
- prompt 顺序：`[lens][SFR 原文 + 攻击者][契约]` 在前作为共享前缀，`[单元 + 调用者][工具发现 DATA][问题]` 在后。派发时按 (lens, SFR) 分组，以命中前缀缓存。
- 每个任务的结果立即追加到 ledger。

**接地校验**（evidence/grounding.py），任一项不过就 `grounded=false`：
- 路径在 inventory 和 scope 内；
- 行号在展示范围内；
- `evidence_quote` 空白归一后是展示行的子串；
- `decisive_line` 在展示范围内；
- symbol 与覆盖该行的函数一致；
- sfr、level、category 都属于档案枚举。

接地失败的输出保留，但**不能创建或修改 PV**；每个 lens 的接地失败率在覆盖页公示。

**升级规则**
- 工具来源的 PV：AI 只填 `ai` 列。
- 发现型 lens 的新发现：接地通过后自动排进 verify。结果为 CONFIRMED 或 LIKELY 时，生成 `origin=ai` 的 PV（未分级分区，`generated`、`gate_eligible=False`）；其余留在覆盖页的“AI 候选”里。
- UNCERTAIN：状态保持 open，归入“需人工判断”筛选。

**批量引擎**（jobs/engine.py，约 700 行，从 llm/scan.py 抽出并改造）
- **保留**：`_Phase` 的预留与退款（:865-909）、断路器（:911-939）、`rate`（:941）、`_Cache`（:493-603）。缓存 key 补上 lens 版本、档案 sha、模型 digest、reasoning、上下文哈希和输入发现哈希（修正 :513-540）。
- **改造**：`execute_all`（:716-758）一次性提交全部 future，改成 worker 从 deque 按需拉取，每次派发前向 broker 申请槽位。结果类新增 `preempted` 和 `refused`。计账按 task id 去重，`preempted` 不是终态，任务结束时满足 `planned = started + unscheduled`。
- **删除**：全量扇出（:435-461）、replan（:274-434）、prompt 冻结落盘（:464-490）、每个任务一个 HarnessRuntime（:1019-1028）。

---

## 7. 网页前端

**布局**
- **顶栏**：评估名、源码路径、档案状态（v1✓ 或“草稿”）、机密性徽标、“模型主机 192.168.5.10（已钉住）”、`qwen3.8:27b · JSON/原生 · 24576`、当前 GPU 占用者、只做显示的进度条（档案 → 工具 → AI 审查 → 清单）。
- **左侧对话，占 40%**：
  - 流式消息。首 token 前显示实测计时；前缀已冷时显示额外时长的估算。
  - 工具卡、任务卡（实测速率、标“估算”的 ETA、让出次数、让出损耗、停止/暂停/继续/重试按钮）、批准卡（待定、已批、已失效三态，显示参数哈希和将写入的文件）、事件卡、排队消息。
- **右侧 5 个页签**：
  - **清单**：主分区和“未分级（需人工核实）”分区上下排列。列有 PV、标题、模块、SFR（强依据）、等级（依据图标）、分类、AI 意见、状态、prio。可筛选（AI 新发现、需人工判断、多引擎），可行内或多选标记、采纳 AI 等级，也可拆分、合并；有“导出”按钮。
  - **证据**：源码高亮、发现标记、工具原文、AI 推理、历史。
  - **档案**：逐项表单，带引文和页码，未接地的标红；有草稿 diff、内置档案或 TOML 模板、“确认”按钮、“重新钉住模型主机”，以及公开评估才出现的 `allow_public_model` 开关。
  - **覆盖**：**SFR × 模块**矩阵（lens 名只在悬停里出现）、未审列表及原因、低于阈值计数（可提升）、inactive_config 计数、TOE 内未分级且未审计数、接地失败率，以及“开始审查”按钮。
  - **任务**：“跑工具”（可强制重跑）、“构建上下文”、暂停、继续、停止、重试。
- **离线时**：输入框提示“模型不可达，按钮仍可用”。除对话和 AI 审查外，整条流程只靠按钮也能走完。

**只保留一套对话渲染**
- `web/blocks.py` 用纯 Python 把 ledger 投影成 `{id, kind, fields}`，由 pytest 覆盖。
- `app.js` 约 600 行（估算），只按 kind 渲染，不含状态逻辑。
- 删除 serve.py:460-699 的 JS 版 Transcript。

**实时更新**
- `GET /api/stream` 走 SSE，事件有 block、delta（≤10Hz）、toast 三种。
- 支持 `Last-Event-ID` 断线续传；刷新时先 `GET /api/blocks` 取快照。

**安全边界**
- 只绑定 127.0.0.1。
- 一次性 token 换成 HttpOnly、SameSite=Strict 的 cookie；**所有**请求都校验 cookie，并校验 `Host ∈ {127.0.0.1:port, localhost:port}`。
- POST 还要求同源 Origin（serve.py:283-287），并且必须是 `application/json`。
- CSP 设为 `default-src 'self'`；不可信文本一律经 `textContent` 输出。
- `/api/source` 做 realpath 包含检查。
- 上传只收 pdf/docx，≤64MB，校验文件头魔数。docx 另加 zip 限额：解压总量 ≤200MB、单个 part ≤50MB、条目 ≤2000、压缩比 ≤100。
- 远程查看只用 `ssh -L`。

**导出规格**

| 项 | 规格 |
|---|---|
| xlsx 工作表 | ① `PV List`：状态不属于 {false_positive, not_exploitable, duplicate} 的条目，先主分区后未分级分区，各自按等级秩降序、prio 降序排列；② `Dispositioned`：已处置条目及分析员备注；③ `Coverage`：SFR×模块审查状态、未分级、低于阈值、inactive_config 计数、接地失败率；④ `Profile`：档案版本、文档 sha256、分级规则及依据 |
| PV List 的列（英文） | PV ID、Title、Partition、TOE Module、SFR、TSFI、Location、Function、Level (§7.4.1)、Level Basis、Category (§7.4.2)、CWE、Engines、AI Opinion、AI Level Suggestion、AI Rationale、Exploit Note、Analyst Status、Analyst Note、Priority、First Seen、Profile Version |
| AI 倾向误报但人未标记的条目 | 留在 PV List，AI Opinion 列写 `FALSE_POSITIVE (AI, unreviewed)` |
| md、csv | md 按 SFR 分节，内容同 PV List；csv 只含 PV List |
| 语言 | 列名和模型生成的字段用英文；分析员备注保持原样；档案里的 `[export] template` 可以覆盖列的顺序和标签 |
| shareable 变体 | 扣留 evidence_quote、源码摘录、rationale、exploit_note（`EXCERPT_FIELDS` 扩展）；全树泄露复验覆盖 xlsx/md/csv 以及 xlsx 内部的 XML |

---

## 8. 资产处置表

| 处置 | 现有文件（行数） | 去向与说明 |
|---|---|---|
| **保留，只搬位置** | process.py 306、persist.py 39、errors.py、status.py 98、inventory.py 519 | 搬到 core/；persist 增加 ledger 的追加、fsync 和容错读；inventory 增加按 scope 过滤 |
| 保留 | tools/*（共 1,819） | 搬到 evidence/adapters/；接收 buildctx 结构的 dict；增加 `summarize()`；解除 run_dir 耦合；接收迁回的解析器 |
| 保留 | includes.py 141、compile_db.py 345、build_context.py 655 | 搬到 evidence/buildctx/；:29 的导入改为 buildctx.schema |
| 缩减 | compile_db_wizard.py 376 → 约 220 | 删掉 stdin 交互（:164-172、:364-376）；改为 typed 参数；构建目录放工作区；在沙箱里运行 |
| 抽取 | config.py 809 → settings.py 与 defaults.py 约 150、buildctx/schema.py 约 180、core/tomlw.py 约 50 | build/tools 校验来自 :464-545；写出器来自 :665-713；删除 `llm.lsp` |
| 抽取 | harness/runtime.py 625-689 → core/sandbox.py 约 90 | bwrap 只给 compile_db 用 |
| 保留 | llm/index.py 1065、llm/units.py 389、llm/context.py 335 | 搬到 review/code/；`_conditional_arms`/`_in_dead` 扩展为按 TOE defines 求值 |
| 保留 | harness/schema.py 389、harness/verdict.py 120 | 搬到 review/；两个契约各自扩展 SESIP 字段；`_matching` 和 `_drop_trailing_commas` 供 JsonActionCodec 使用 |
| 保留 | sarif.py 166 | 搬到 export/；指纹不变，partialFingerprints 语义不变 |
| 修正后保留 | summary_digest.py 144 | 修正 :130、:133 读错的字段 |
| 泛化 | grading.py 78 → sesip/grading.py 约 220 | 改为按档案加载；RT700 参考转成内置档案 rt700-tp-v1.1 |
| **重写或抽取** | review.py 1335 → evidence/findings.py 约 450 | 只迁 :76-97 的逐行加工、:465-797 的解析器（迁到 adapters）、:903 `_evidence_context`（作为属性）、:1102 `_deduplicate`、:1117 `_fingerprint`（公式不变）；汇总交给 SQLite |
| | audit.py 350 → triage.py 与 sesip/pv.py，约 550 | 保留 `correlation_category`（:85）；序号 id、key、carry_verdicts 换成锚点、一对一匹配、拆分与合并 |
| | validate.py 524 → jobs/lens_job.py 约 250 | 保留 :339 和 :411；:368 改为按索引查找 |
| | llm/scan.py 1321 → jobs/engine.py 约 700 | 见 §6 |
| | llm/risk.py 203 → sesip/relevance.py 约 280 | 关键词表降为弱依据 |
| | llm/skills.py 188 与 skills/llm-*（7 个）→ review/lenses.py 约 120 加 15 个 lens md | — |
| | harness/runtime.py 872 → model/client.py 约 350 | 保留 `api_key` 315、`redact_credential` 353、`finish_status` 412、`endpoint_context_length` 420（加载请求改用独立长超时）；重写 `measured_usage` 和 `provider_failure`；删除 HarnessRuntime |
| | harness/session.py 545 → model/record.py 约 250 | 泛化五件套（316-472） |
| | llm/profiles.py 94 → model/egress.py 约 150 | 钉住主机、校验私有地址、路由表；`LOCAL_PROFILES`（:47）作废；gpu-host-uncensored 改为 `review_name` 设置 |
| | llm/doctor.py、doctor.py、preflight.py → model/probe.py 约 380 | P1-P14 加分析器、pdftotext、bwrap 的 canary |
| | actions.py 622 → kernel/registry.py 约 250 | 从效果派生批准（176-208） |
| | ask.py、control.py → kernel/approvals.py 约 150 与 jobs/control.py 约 250 | 保留 RunControl（122-258）；超时语义改为卡片失效 |
| | llm/propose.py 642 → 约 60 | 只留 NO_MODEL gate（137-213）和 `_NEVER_FROM_MODEL`（448，扩展） |
| | cli.py 437、argv.py 269 → cli.py 约 220 | 4 条命令，加过渡期的 tui-legacy |
| | runner.py 1021 → evidence/analyze.py 约 250 | 保留中断处理（599-609、801-844）和稳定性比对（614-656） |
| | dialogue.py → web/blocks.py 约 300；serve.py → web/server.py 约 400 | — |
| | events.py → core/events.py 约 100；sanitize.py → export/sanitize.py 约 320；recovery.py → rebuild 约 100 | 同上一稿 |
| **拆散后删除（M9）** | analysis.py、progress.py、runlog.py、report_presentation.py | 被引用的符号先迁到 core/text.py、core/events.py、export/listing.py |
| **删除（M9）** | tui.py、flow.py、chat.py、html_report.py、dashboard.py、journal.py、intent.py、llm/replan.py、llm/configure.py、reconfigure.py（`_unit_files` 263-275 的逻辑并入 rerun_job）、llm/resume.py、llm/recover.py、llm/summarize.py、harness/cordis.py、harness/__init__.py、skills/operator-intent、skills/build-context-configurator、skills/run-summary | 旧模块之间互相引用，**全部在 M9 统一删除**；M2-M7 只保证新路径不再调用它们 |

**测试处置**：共 58 项。旧测试文件与被测模块一起在 M9 删除；新测试在对应里程碑落地；每个里程碑的发布门槛都是全绿。

| 旧测试文件 | 处置 | 新测试落地 |
|---|---|---|
| test_adapters、test_splint_evidence、test_source_scope、test_core、test_events、test_gitignore、test_scheduling、test_live_tools、test_sarif | 迁移 | M2 |
| test_producers、test_report_layer（findings 部分）、test_v2（compile_db 部分）、test_runtime_output（process 部分）、test_progress/test_runlog（text 部分） | 改写为 test_findings、test_process、test_text | M1-M2 |
| test_audit | 改写为 test_pv（含计数守恒、一对一匹配、拆分与合并） | M2 |
| test_serve、test_dashboard_origin、test_report_layer（sanitize 部分） | 改写为 test_web_security、test_export | M3 |
| test_harness_layer、test_fake_harness、fake_harness.py、test_llm_config、test_llm_doctor、test_doctor_preflight、test_live_llm | 由 test_client、test_record、test_settings、test_egress、test_probe 与 FakeTransport 取代 | M0 |
| test_actions、test_propose | 改写为 test_registry、test_injection（R1 的三条测试） | M5 |
| test_compile_db、test_build_context、test_include_graph、test_tools_resume | 迁移，并新增 test_buildctx_schema、test_rerun_job、test_sandbox | M6 |
| test_llm_index、test_validate、test_verdict、test_skills、test_skill_contract、test_control、test_llm_reliability、test_concurrency | 改写为 test_lens_job、test_lenses、test_engine（preempted/refused/退款）、test_r2（R2 的三条不变量） | M7 |
| test_tui、test_flow、test_chat、test_dialogue、test_intent、test_replan、test_configure、test_reconfigure、test_summarize、test_resume、test_partial_recovery、test_llm_recover、test_llm_pipeline、test_dashboard、test_report_presentation，以及上面各行里旧文件的剩余部分 | 删除 | M9 |

conftest 从 M0 起同时设置 `CODE_ANALYZER_NO_MODEL` 和 `CODE_ANALYZER_HOME`。

**合计（估算）**：新增 Python 约 8k 行（kernel 1.6k、model 1.1k、jobs 1.3k、sesip 1.6k、evidence 新增 1.2k、web 0.8k），另有 JS/CSS 1.3k。Python 最终约 20k 行。工作量 15-19 人周。

---

## 9. 不变量

**原样保住**
- 退出码代数（status.py:7-12、69-98），只用于 CLI `analyze`；`fail_on` 保留，AI 永不参与门禁。
- 证据层不合并、不删除、不判误报，保留 original_severity。
- AI 产出一律 `generated`、`gate_eligible=False`。
- 原生证据永不覆盖；artifact 按 sha256 建索引；JSON 用规范字节；原子写入；所有中断路径都定格为 interrupted/130。
- inventory 逐文件 sha256，分析前后做稳定性比对。
- 不安装工具；未经同意不执行项目构建；分析器只接受封闭的 typed 选项；补丁必须通过 validate_patch 和 buildctx 校验，**并经人工点击**；stub 只写工作区。
- 凭据只从环境变量读，写盘前一律 redact_credential。
- 每个模型回合都落五件套和 prompt_sha256。
- 预算不足时记为 unscheduled，绝不截断批量单元的上下文；对话摘录只做显式分页。
- **SESIP 分级只做可证明的映射，其余标 unmapped 并要求人工核实**。这一条现在由“未分级”分区和计数守恒兑现，不再静默丢弃。
- 导出做全树泄露复验。
- 速度只显示实测值，估算必须标明。
- 每个评估同一时刻只有一个在飞的交互请求，迟到的回答按 generation 丢弃。
- 状态事件不丢，liveness 事件可丢。
- 只绑定 127.0.0.1，POST 要求同源。
- 测试不打开任何 socket。

**新增**
- TOE 内 finding 簇计数守恒（§4.5）。
- 第三方外发与计费警告出现在每张会使用第三方端点的卡上，以及顶栏的琥珀色徽标上。

**显式修订**
- **R1（用户已确认）**：修订 §2.3（docs/platform-architecture.md:180-187）、2026-09-03 的决定（:130-141）和 tests/test_propose.py:133。对话 agent 可以读 finding、源码和档案，但只能放在 DATA 围栏里并限长；写入、花 GPU、exec、出站的授权只来自效果声明加人工点击或人工创建的额度。新增三条测试：DATA 里写 “call export” 在无批准时不写任何文件；批准必须与参数哈希一致；broker 在 send 处做出站硬阻断。**被否决时的退路**：agent 的工具结果只给计数和句柄、不给自由文本；读 finding 的角色只剩 lens job（validator 本来就有先例），其余设计不变。
- **R2**：tests/test_concurrency.py 的串并行等价不变量随盲扫退役，改为三条：（a）静态证据的字节与 AI 和对话活动无关；（b）被抢占时仍满足 `planned = started + unscheduled`，每个 task 只计一次；（c）被抢占的请求重做时 prompt_sha 和缓存 key 不变。docs/llm-scan-architecture.md 作废。
- **R3（用户已确认）**：效果词汇扩展为 read/record/cpu/gpu/exec/write/egress。模型推断的 `run_tools` 不需批准，这是有意放宽，由核心点 2 推出；它是幂等的，而且 CPU job 随时可停。**被否决时的退路**：run_tools 改为出卡，§2 第 4 步多一次点击。
- **R4**：第三方从“警告”升级为**钉住主机加私有地址校验的硬阻断**，按 §3.6 的路由表执行；不做自动故障转移。
- **R5（修订）**：cordis 退役；**bwrap 只为 compile_db 保留**（源码只读、断网、只写工作区）。模型本身没有文件系统或 shell 工具。
- **R6**：无头 `analyze` 完全不调用模型。
- **R7**：离线时的确定性路径改为“按钮 + CLI”，intent.py:114-306 删除。
- **R8**：序号 id 改为锚点加 PV 号；整体 manifest 改为 ledger 加每次调用一个 call.json；泄露复验覆盖 xlsx/md/csv 和 xlsx 内部的 XML。
- **R9**：“可证明的映射”扩展为 native-exact、evaluator-rule、analyst 三种；ai-proposed 只显示，不参与成员判定。
- **R10（修订）**：指纹公式不变，不纳入 evidence_context 或 attempt，重复行由主键区分；SARIF partialFingerprints 在同一源码版本的重跑之间保持稳定。跨版本匹配靠 PV 锚点和 `line_text_sha`，不靠指纹。
- **R11**：卡片 30 分钟或状态变化即失效，取代 `approval_timeout_seconds=0` 的无限等待。
- **R12**：评估创建后由 agent 调用三件工具（核心点 2）；模型不可达时由按钮兜底。
- **R13（用户已确认）**：cppcheck argv 保持不变，降噪只在视图层做。

---

## 10. 分期路线

里程碑按依赖排序，每个都可以单独发布、测试全绿。旧 `analyze` 在 M2 被新实现替换；tui-legacy 用到 M5 验收；旧模块在 M9 统一删除。

| 里程碑 | 内容 | 验收（测试） | 验收（真机） |
|---|---|---|---|
| M0 客户端与探针 | client、broker 骨架（NO_MODEL、egress 钉住与私有校验）、probe P1-P14 | FakeTransport 覆盖两种 codec、专用提取器（散文示例 JSON 不触发调用）、500 时扁平重试、截断判定；客户评估下 b.ai 在打开 socket 前被拒；把本地端点设成公网地址时要求二次确认 | 对 qwen3.8:27b 产出 probe.json，定下 codec、批量并发和槽位策略；记录 P10、P12、P13、P14 的结果 |
| M1 离线分诊 | findings store（主键、指纹不变）、view_class、聚类（含间隔切分）；只读导入已有运行 | 规范化 dump（按主键排序导出）在 rebuild 前后一致 | TF-M `20260904T003653Z-dba84a4f3780`：≥88,211 条归为诊断，182 条标为树外，**主键零重复**，同一原生行跨尝试共享指纹；报告簇数（不设减少比例目标）；**抽样 50 簇，人工判定属于同一缺陷的 ≥90%**；分页查询 p95 <200ms |
| M2 工作区与确定性清单 | ledger、calls/、buildctx 与其校验器、scope、static_job、档案式分级、内置两个档案、PV 分区与编号、计数守恒、新 `analyze` | Juliet 上退出码和逐单元证据与旧 runner 一致；守恒测试；SIGTERM 后对账正确 | TF-M 同一棵树重跑，PV 编号 100% 稳定；在 5 个文件上游各插入 20 行后，≥95% 稳定；报告未分级分区的规模 |
| M3 Web v1（不含 agent） | server 安全、blocks，清单（两个分区）、证据、档案（手工表单、内置档案、模板）、任务页；**只放已交付功能的按钮**：新建、跑工具、标记、采纳、提升、导出；md/csv/xlsx 导出；tui-legacy 保留 | 不带 cookie 访问返回 403；Host 和 Origin 校验；docx zip 限额；xlsx 通过泄露复验 | GPU 关机时，用 generic-sesip 走完一次 Juliet 评估；xlsx 能在 LibreOffice 打开 |
| M4 档案抽取 | documents、catalogue、extract_job、引文校验、确认、定位 TP 中的报告格式章节 | 文本 fixture 和现场生成的 docx：引文 100% 通过校验或标红 | 用实验室提供的 RT700 AVA TP：§7.4.1 四级与 grading.py 一致；§7.4.2 每个分类都有页码和引文；category_kind 由人选定；ST 的 SFR 召回 ≥90% |
| M5 Agent 内核 | loop、两种 codec、上下文与折叠、句柄、7 个工具、批准与额度、唤醒（含创建和 J1）、排队、抢占；此后 tui-legacy 标为废弃 | 两种 codec 的脚本化对话测试；注入回归测试（含围栏转义）；排队输入永不当作审批；折叠之间严格只追加 | 在 TF-M 上跑 20 条脚本化意图：选对工具 ≥90%（7 与 10 工具对比的结果入档），平均每个意图 ≤1.6 次调用，空闲热前缀 p50 ≤20s（实测基线 3-11s），3 步链零 500 |
| M6 对话化构建上下文 | build_context 工具、compile_db（typed 参数加沙箱）、rerun_job；新路径不再调用 configurator 和 reconfigure | 未经批准不执行任何项目命令；沙箱里写源码树失败；compile_db 不接受任意 argv | TF-M 的 TOE 内 splint TU 数 ≥ 基线 289/1588（目标是 TOE TU 的 60%）；循环中零模型调用 |
| M7 定向 AI 审查 | 15 个 lens、两个契约、relevance（T1 含未分级）、拉取式 engine（preempted/refused）、接地、升级、覆盖 | 伪造的行号或引文 100% 被拒；`planned=started+unscheduled`（含抢占场景）；AI 判 FALSE_POSITIVE 后条目仍在；空 findings 记为已审 | Juliet 的 CWE121/401/457 都成为已接地的 PV；TF-M 上 2 个 SFR、60 分钟额度的 job 账目对得上；**job 运行期间对话 p50 的目标按 P12 设定**：槽位隔离可行时 ≤1.3×空闲，不可行时 ≤ P12 冷前缀首 token 时间 + 空闲生成时间；停止后续跑命中缓存；评估员抽审前 30 条，值得看的 ≥50% |
| M8 公开通道与复评 | public_model 路由、`allow_public_model`、版本 diff | 客户评估下，即使配置了 public_model、即使注入了指令，也抛 `EgressBlocked` | Juliet 标为 public 后，经卡片走 b.ai；TF-M 两个 tag 之间的 diff |
| M9 清理 | 删除 §8 列出的模块和测试；重写文档；依赖降为 0 | NO_MODEL 下全绿；全新安装不拉取 textual 和 dsh | 在 TF-M 上完整走一遍 §2，记录每一步的时长 |

---

## 11. 主要风险与缓解

1. **27B 工具调用在长会话中退化**：默认原生 codec（2026-09-22 实测可用），运行时按失败率降级到 JSON；只有 7 个工具、以 enum 参数为主；每次响应 1 个调用、最多自动修复 1 次；尾部给出“建议下一步”；按钮兜底；P4 决定最终工具集。
2. **延迟**：每条消息 ≤3 次调用；卡片即回答；关闭思考；只追加，折叠罕见；抢占全部后台请求；P0 超时 300s；首 token 前显示实测计时。
3. **后台 job 冲掉 KV 缓存**：P12 实测；可行时用“槽位数−1”隔离（需要用户同意调整 GPU 主机）；否则如实提示冷前缀的额外时长，M7 目标按实测设定。
4. **Ollama 静默截断**：用长超时加载后读窗口；用 usage 校准估算（依赖 P13，不支持时加大余量）；接近窗口就折叠重发。
5. **档案抽取出错**：确定性优先；引文可校验；由人确认；§7.4.2 语义由人选；提供内置档案和手写模板；没有 pdftotext 时明确退路。
6. **未分级分区过大**（splint 在 TF-M 上约 2.4 万原始行）：先按函数聚类；内置提议规则由人一次确认即批量转为已分级；AI 等级建议加多选采纳；覆盖页公示数量；M2 报告实际规模，再决定是否调整预置规则。
7. **AI 幻觉进入清单**：接地校验；二次复核；AI 新发现只进未分级分区；公示接地失败率。
8. **提示注入与外泄**：DATA 围栏加定界符转义；模型侧没有 job 控制、没有执行类工具；run_tools 幂等；broker 唯一出口，钉住主机并校验私有地址；网页三重校验；docx 限额。
9. **构建脚本不可信**：compile_db 参数封闭；bwrap 断网、源码只读；没有 bwrap 时显式标红并要求额外确认。
10. **GPU 被他人占用**：如实显示排队时间和当前占用者。
11. **重写风险**：M1 只读；M2 用 Juliet 对拍；M3 先交付不含 agent 的确定性评估；tui-legacy 过渡到 M5；旧模块到 M9 统一删除。

---

## 12. 对评审意见的处理

| # | 评审缺口（级别） | 处理 | 位置 |
|---|---|---|---|
| 1 | unmapped 静默丢弃（致命） | **采纳**。新增“未分级（需人工核实）”分区；TOE 内 finding 簇计数守恒；T1 覆盖未分级；内置档案预置 flawfinder 0-5、cppcheck performance/portability、splint 各族的 proposed 规则；覆盖页公示“TOE 内未分级、未审 N 条” | §0、§4.2、§4.5、§6、§9 |
| 2 | AI 先调工具（主要） | **采纳方案 (a)**：创建评估时追加确定性事件，agent 第一回合调 run_tools；另加 J1 结束即唤醒，不等 J2；离线时按钮兜底 | §2 第 3-5 步、§3.7、R12 |
| 3 | 出站按 host（主要） | **采纳**。钉住主机加私有地址校验、防 DNS rebinding；非私有需二次确认；设置变更不溯及；第三方路由表；按端点类别取 reasoning、max_tokens、并发 | §3.6、§4.1、R4 |
| 4 | 指纹可变（主要） | **采纳**。指纹公式保持不变；重复行由主键 (fingerprint, call_id, unit_id) 区分；M1 验收改为主键零重复 | §4.4、R10、M1 |
| 5 | F 句柄碰撞（主要） | **采纳**。git 式前缀最短 8 位，冲突自动加长，歧义报错 | §3.4 |
| 6 | config 缩减破坏 buildctx（主要） | **采纳**。新增 buildctx.vN.toml；校验器从 config.py:464-545 抽出；adapter 收到的 dict 结构不变；复用 TOML 写出器 | §4.6、§8 |
| 7 | `_candidates` 误识别（主要） | **采纳**。专用提取器只看响应末尾；只复用 `_matching` 和 `_drop_trailing_commas`；P7 增加用例 | §3.5 |
| 8 | lens 输出契约（主要） | **采纳**。verdict 与 findings 两个契约，空数组表示已审 | §6 |
| 9 | 抢占退款与重排（主要） | **采纳**。新增 `preempted` 结果类；engine 改为按需拉取；按 task id 计账；engine 估算上调到约 700 行 | §3.6、§6、R2 |
| 10 | KV 缓存被冲（主要） | **采纳**。新增 P12；“槽位数−1”策略（部署变更需用户同意）；M7 目标按实测设定；界面提示冷前缀 | §0、§3.5、§3.6、M7 |
| 11 | 只追加与折叠（主要） | **采纳**。超过 12k 才一次性折叠；A 段只放已确认档案；源码摘录上限 1.2k，超限时显式分页 | §3.3 |
| 12 | compile_db 参数与沙箱（主要） | **采纳**。参数封闭为 preset/generator/defines/toolchain_file；bwrap 只为它保留；R5 修订 | §3.9、§5、R5 |
| 13 | 没有 ST 时的默认档案（主要） | **采纳**。内置 generic-sesip 和 rt700-tp-v1.1；analyze 缺省用后者并在输出中注明 | §1、§4.2 |
| 14 | lens 覆盖不足（主要） | **采纳**。新增 sfr-generic、input-auth（承接 llm-security 其余 5 类）、secure-storage；覆盖页标注“仅通用 lens” | §6 |
| 15 | PV 粒度、锚点、匹配（主要） | **采纳**。unknown 族加 rule_id；超过 30 行间隔切开；决定行定义为 prio 最高成员的 line_text_sha；一对一匹配；拆分与合并；M1 人工抽样 50 簇 | §4.5、M1 |
| 16 | 概念数与工具面（主要） | **采纳**。列出 15 个操作员术语；basis、origin、grounded 改为图标；模型侧工具减到 7 个；P4 对比 7 个与 10 个 | §1、§3.9、§3.5 |
| 17 | 成员边界（次要） | **采纳**。所有条件都与 in_toe、view_class=finding 取合取；ai-proposed 只显示 | §4.5、R9 |
| 18 | SFR 归属精度（次要） | **采纳**。sfr[] 每项带 basis，prio 只计强依据 | §4.5、§5 |
| 19 | 导出语义（次要） | **采纳**。给出导出规格表（工作表、列、排序、AI 标注、语言、档案模板） | §7 |
| 20 | 里程碑与测试（次要） | **采纳**。tui-legacy 保留到 M5；M1 改为规范化 dump 一致；M3 只放已交付功能的按钮；58 项测试逐一处置。**调整**：旧模块统一在 M9 删除，因为它们互相引用，分批删会打断旧 CLI 和旧测试 | §8、§10 |
| 21 | 探针缺项与窗口探测（次要） | **采纳**。新增 P13、P14；加载请求用长超时；更正归因：runtime.py:467 已经在加载，问题出在 :420 的 5s 超时 | §3.3、§3.5 |
| 22 | 注入细节（次要） | **采纳**。围栏定界符转义；job 控制移出模型侧；run_tools 幂等；docx zip 限额 | §3.4、§3.9、§7 |
| 23 | TOE 构建配置（次要） | **采纳**。档案加 `[toe_configuration]`，与 buildctx 联动；新增 view_class=inactive_config，只求值简单条件 | §4.2、§5 |
| 24 | 复用描述失真（次要） | **采纳**。单元用 plan_units 按需生成；findings 只迁移逐行加工；LOCAL_PROFILES 更正为 :47；“最后一条是 user”只对 JSON 模式成立；原生模式只保留第一个 tool_call | §3.3、§3.5、§6、§8 |
| 25 | 未定义的运行参数（次要） | **采纳**。定义 GPU 小时；P0 超时 300s；列出 analyze 的 7 个选项，fail_on 保留；无 TTY 时返回 2；拒答记为 refused；新增 review_name 设置 | §1、§3.6 |
| — | 未核实：R1、R3 是否得到用户授权 | 2026-09-22 用户已确认 | §9 |
| — | 未核实：cppcheck argv 的方法学判断 | 用户已确认不改（R13） | §0、§9 |
| — | 未核实：Qwen 模板把 tools 放在哪 | 新增 P9b 实测；固定工具集的理由改为“无论模板细节，工具文本都在前缀开头” | §0、§3.5 |
| — | 未核实：TF-M 各项计数、并发吞吐、6 倍加速 | 保留作为 M1 和 M0 的验收对照，由真机重测 | §10 |
| — | 未核实：各项工期和行数估算 | 统一标为“估算”；工作量上调为 15-19 人周 | §1、§8 |
| — | 未核实：实验室机器是否有 pdftotext | probe 检查；没有时退回 docx、文本或手写模板 | §4.2 |
| — | 未核实：§7.4.2 的语义 | 由 `category_kind` 让人选定；M4 用实验室提供的 PDF 验收 | §4.2、M4 |
| — | 未核实：M5 的量化目标在 27B Q4 上能否达到 | 保留为目标；按 M0 探针结果校准 | §10 |

---

### Critical Files for Implementation
- /home/ubuntu/workspace/code-analyzer/code_analyzer/llm/scan.py（`_Phase` 的预留与退款 :865-909、`execute_all` :716-758 改为拉取式、断路器、`_Cache` :493-603，抽到 jobs/engine.py）
- /home/ubuntu/workspace/code-analyzer/code_analyzer/review.py 与 /home/ubuntu/workspace/code-analyzer/code_analyzer/audit.py（逐行加工 :76-97、`_evidence_context` :903、`_fingerprint` :1117、`correlation_category` :85，改成 evidence/findings.py、triage.py、sesip/pv.py）
- /home/ubuntu/workspace/code-analyzer/code_analyzer/config.py 与 /home/ubuntu/workspace/code-analyzer/code_analyzer/build_context.py（buildctx 校验器 :464-545、TOML 写出器 :665-713、`ConfigPatch.apply` :206、`validate_patch` :392）
- /home/ubuntu/workspace/code-analyzer/code_analyzer/harness/runtime.py 与 /home/ubuntu/workspace/code-analyzer/code_analyzer/harness/schema.py（`endpoint_context_length` :420-494、bwrap :625-689、`_matching` :200、`_drop_trailing_commas` :226、`parse_findings` :129）
- /home/ubuntu/workspace/code-analyzer/code_analyzer/grading.py 与 /home/ubuntu/workspace/code-analyzer/code_analyzer/actions.py（内置档案 rt700-tp-v1.1 的来源；从效果派生批准 :176-208，演化为 kernel/registry.py）
---

## 实施记录（as built，2026-09-23）

| 期 | 提交 | 真机验收（实测） |
|---|---|---|
| M0 | 3b2921d | 探针：codec native、批量并发 1、断开不释放 GPU（Ollama 0.32.14）；前缀缓存快 5.7 倍；json_schema 5/5 |
| M1 | 6f25c5d | TF-M：88,233 行诊断、182 行树外、主键零重复、22,747 簇、重建字节一致；查询 p95 60 ms；抽样聚类判定 100% |
| M2 | 70e8b3a | Juliet 与旧 runner 退出码、逐单元状态、(指纹, 单元) 集合一致；TF-M 重跑编号 100% 保持，上游插 20 行 99.32% |
| M3–M6 | 3dcbd6d | 网页只靠按钮走完 Juliet；合成 ST 抽取 55 s、引文全部核实；对话冷 16 s / 热 4–8 s 首字；打字“批准”不生效；TF-M splint 进入分析 123→173→256→282→295/1588（4 个确定性补丁，基线 289） |
| M7 | 2df5f01 | Juliet T1 48/48 已核实、接地失败 0%、10 分 44 秒 GPU；T2 点名 bad 函数 32 任务、14 条晋升，CWE121/401/457/476 全部成为已接地条目；TF-M 两个 SFR、60 分钟额度见下 |
| M8 | c6f2169 | 公开通道、沿用构建上下文、版本对比（Juliet 两个评估 48 保留）；b.ai 真机待用户提供新 key |
| M9 | 分支 m9-cleanup | 删除旧程序 −44k 行、运行时依赖 0、四条命令；旧 runner 对照 Juliet 一致后删除；等用户试用网页后合并 |

与设计的偏差（均已落地并有测试）：

- **包名**：AI 审查放在 `aireview/`，不是 `review/`——旧的 `review.py` 到 M9 才删除，同名包会遮蔽它。
- **lens 的检查项决定它能发现什么**：Juliet 第一次 T2 漏掉 CWE401，因为没有一个 lens 写了“正常路径上分配了却不释放”。error-path 1.1.0 补上后两例都找到。
- **二次复核按“单元 × 类别”一组一次**，晋升只取离复核决定行最近的那条：逐条复核会给铺垫行盖章（第一次 45 条晋升、891 s；改后 14 条、442 s，每条都在出错的那一行）。
- **T2 的排除更窄**：函数只有在工具已经报过“这个 lens 负责的缺陷族”时才被这个 lens 跳过；无关的告警不再挡住 SFR 相关代码。评估员也可以点名函数（`path::function`、`path:line`），默认用 memory 与 error-path 两个 lens。
- **焦点可以是多个 SFR**（逗号分隔）。
- **模型主机钉住**加了按钮：无头 `evaluate` 建的评估原本没有钉住的主机，页面上却没有入口。
- **旧索引**在打开评估或做版本对比时后台重建，不再要求“先打开一次”。
- **沙箱**：bwrap 的私有 /tmp 会遮住放在 /tmp 下的源码树，改为之后再只读绑定回来。
- **打包**：`kernel/method.md`（agent 的系统提示）原先不在 package-data 里，非可编辑安装会缺；`settings.toml [analyzers]` 原先读了不用。两处都已修复并有测试。
