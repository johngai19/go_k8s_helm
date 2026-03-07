# 多 Agent 系统与长上下文最佳实践

---

## 一、为什么需要多 Agent？

单个 Agent 的核心瓶颈：
- **Context 窗口有限**：200K tokens 看起来多，复杂项目很快耗尽
- **注意力稀释**：上下文越长，模型对早期内容的"注意力"越弱
- **串行瓶颈**：复杂任务必须并行才够快
- **专业化需求**：通才不如专才，专用 Agent 更精准

---

## 二、多 Agent 的核心模式

### 模式 1：Orchestrator + Workers（最常用）

```
用户请求
    ↓
Orchestrator (Claude Opus/Sonnet)
    ├── 分解任务
    ├── 分配给 Worker
    └── 整合结果

Worker A          Worker B          Worker C
(代码生成)        (测试编写)        (文档撰写)
Claude Haiku      Claude Haiku      Claude Haiku
```

**关键原则：**
- Orchestrator 用强模型（Sonnet/Opus），Workers 用快速模型（Haiku）
- 任务分解要明确边界，避免 Worker 间依赖
- Orchestrator 持有全局状态，Worker 只处理局部

**实现示例（Python + Anthropic SDK）：**
```python
import anthropic
from concurrent.futures import ThreadPoolExecutor

client = anthropic.Anthropic()

def run_worker(task: dict) -> str:
    """Worker: 使用 Haiku 快速完成子任务"""
    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=2000,
        system=task["system_prompt"],
        messages=[{"role": "user", "content": task["task"]}]
    )
    return response.content[0].text

def orchestrate(user_request: str) -> str:
    """Orchestrator: 用 Sonnet 分解和整合"""
    # 1. 分解任务
    decompose_response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        messages=[{
            "role": "user",
            "content": f"将以下任务分解为3-5个独立子任务，返回JSON数组：\n{user_request}"
        }]
    )
    tasks = parse_tasks(decompose_response.content[0].text)

    # 2. 并行执行
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(run_worker, tasks))

    # 3. 整合结果
    synthesis = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=3000,
        messages=[{
            "role": "user",
            "content": f"整合以下子任务结果：\n{results}"
        }]
    )
    return synthesis.content[0].text
```

---

### 模式 2：Pipeline（流水线）

```
输入 → Agent A → Agent B → Agent C → 输出
      (提取)    (分析)    (生成报告)
```

**适用场景：** 数据处理、内容生产流水线
**优势：** 每步专注，结果可检验，失败可重试

---

### 模式 3：Debate / Critic（辩论/批评模式）

```
         ┌──────────┐
         │ Proposer │ → 生成方案
         └────┬─────┘
              ↓
         ┌──────────┐
         │  Critic  │ → 找出漏洞
         └────┬─────┘
              ↓
         ┌──────────┐
         │ Refiner  │ → 综合改进
         └──────────┘
```

**适用场景：** 代码审查、方案设计、重要决策
**效果：** 比单 Agent 质量显著提升，类似人类的"红蓝队"

---

### 模式 4：Swarm（蜂群，动态）

Agent 根据对话上下文动态"交接"控制权：
```python
# OpenAI Swarm 风格，适用于客服、复杂路由场景
def transfer_to_billing_agent():
    """当用户询问账单问题时，转交给账单专员"""
    return billing_agent

def transfer_to_technical_agent():
    """当用户询问技术问题时，转交给技术专员"""
    return technical_agent
```

---

## 三、长上下文最佳实践

### 3.1 上下文分层架构

```
┌─────────────────────────────────────┐
│         System Prompt (不变)         │  ← 角色定义、规则、工具说明
├─────────────────────────────────────┤
│        Working Memory (会话)         │  ← 当前任务状态、最近交互
├─────────────────────────────────────┤
│      Retrieved Context (按需)        │  ← RAG 检索出的相关内容
├─────────────────────────────────────┤
│        Long-term Memory (外部)       │  ← 数据库/文件存储的历史
└─────────────────────────────────────┘
```

### 3.2 上下文压缩技术

**技术 1：滚动摘要（Rolling Summary）**
```python
def compress_history(messages: list, threshold: int = 50000) -> list:
    """当历史超过阈值时，压缩早期对话"""
    if token_count(messages) < threshold:
        return messages

    # 保留最近 N 轮对话
    recent = messages[-10:]
    older = messages[:-10]

    # 用 Haiku 生成摘要（便宜快速）
    summary = client.messages.create(
        model="claude-haiku-4-5-20251001",
        messages=[{
            "role": "user",
            "content": f"用200字总结以下对话要点：\n{older}"
        }]
    ).content[0].text

    return [
        {"role": "system", "content": f"[对话历史摘要]\n{summary}"},
        *recent
    ]
```

**技术 2：分块处理大文档**
```python
def process_large_document(doc: str, question: str) -> str:
    """分块处理超长文档"""
    chunks = split_into_chunks(doc, chunk_size=50000, overlap=2000)

    # 并行处理每个块
    chunk_answers = []
    for chunk in chunks:
        answer = client.messages.create(
            model="claude-haiku-4-5-20251001",
            messages=[{
                "role": "user",
                "content": f"基于以下内容回答问题：\n问题：{question}\n内容：{chunk}"
            }]
        ).content[0].text
        chunk_answers.append(answer)

    # 最终整合
    return synthesize(chunk_answers, question)
```

**技术 3：关键信息置顶（Primacy Effect）**

Claude（和所有 LLM）对上下文开头和结尾的内容记忆更好：
```
System Prompt
├── 最重要的规则和约束 ← 放最前面
├── 工具说明
└── 角色定义

对话中间（注意力最弱区域）
├── 背景信息
├── 历史对话

最后（用户最新消息）← 放最后，紧跟用户需求
└── 当前任务 + 关键约束重申
```

### 3.3 Claude 长上下文特有技巧

**技巧 1：XML 标签分隔内容**
```xml
<documents>
  <document index="1">
    <title>需求文档</title>
    <content>...</content>
  </document>
  <document index="2">
    <title>现有代码</title>
    <content>...</content>
  </document>
</documents>

<task>
基于以上文档，实现用户登录功能
</task>
```

**技巧 2：引用机制**

在提示词中要求 Claude 引用来源：
```
请回答问题，并用[文档X, 第Y段]格式标注信息来源。
```

**技巧 3：渐进式细化（Progressive Refinement）**
```
第一轮：给高层概述（Claude 扫描全文）
第二轮：聚焦某个具体部分深入分析
第三轮：针对具体问题精确回答
```

---

## 四、跨工具 Agent 最佳实践

### 4.1 工具调用的黄金规则

```python
# ✅ 好的工具设计
@tool
def search_and_summarize(query: str, max_results: int = 5) -> str:
    """搜索并返回摘要，不返回原始内容"""
    results = search(query, max_results)
    return summarize(results)  # 压缩后返回

# ❌ 糟糕的工具设计
@tool
def search(query: str) -> str:
    """返回原始搜索结果"""
    return raw_html_results  # 浪费大量 context
```

### 4.2 工具调用错误恢复

```python
def robust_tool_call(tool_fn, args, max_retries=3):
    """带重试和错误处理的工具调用"""
    for attempt in range(max_retries):
        try:
            result = tool_fn(**args)
            return result
        except RateLimitError:
            time.sleep(2 ** attempt)
        except ToolError as e:
            # 让 Claude 自己决定如何处理错误
            return f"工具执行失败: {e}。请考虑替代方案。"
    return "工具调用多次失败，请人工介入"
```

### 4.3 工具调用顺序优化

```
并行（无依赖）：         串行（有依赖）：
搜索A ──┐               读文件
搜索B ──┼→ 整合          ↓
搜索C ──┘               分析内容
                         ↓
                        生成报告
```

---

## 五、Agent 间通信协议设计

```python
# 统一的 Agent 消息格式
class AgentMessage:
    task_id: str          # 任务唯一 ID
    sender: str           # 发送方 Agent 名
    receiver: str         # 接收方 Agent 名
    task_type: str        # 任务类型
    payload: dict         # 任务内容
    context: dict         # 共享上下文
    priority: int         # 优先级 1-5
    timeout: int          # 超时秒数
    callback: str         # 完成后回调地址

# Agent 注册中心
class AgentRegistry:
    def register(self, agent_name: str, capabilities: list[str]):
        """注册 Agent 及其能力"""

    def find_agent(self, required_capability: str) -> str:
        """根据所需能力找到合适的 Agent"""

    def route_task(self, task: AgentMessage) -> str:
        """自动路由任务到最合适的 Agent"""
```

---

## 六、实际案例：代码审查多 Agent 系统

```python
AGENTS = {
    "security_reviewer": {
        "model": "claude-haiku-4-5-20251001",
        "system": "你是安全专家，专门找SQL注入、XSS、认证漏洞",
        "focus": "security"
    },
    "performance_reviewer": {
        "model": "claude-haiku-4-5-20251001",
        "system": "你是性能专家，专门找N+1查询、内存泄漏、算法复杂度问题",
        "focus": "performance"
    },
    "style_reviewer": {
        "model": "claude-haiku-4-5-20251001",
        "system": "你是代码规范专家，检查命名、注释、架构合理性",
        "focus": "style"
    },
    "synthesizer": {
        "model": "claude-sonnet-4-6",
        "system": "你是技术主管，整合所有审查意见，给出优先级排序的改进建议",
        "focus": "synthesis"
    }
}

def review_code(code: str) -> str:
    # 并行运行三个专业审查员
    with ThreadPoolExecutor() as executor:
        reviews = {
            name: executor.submit(run_agent, agent_config, code)
            for name, agent_config in AGENTS.items()
            if agent_config["focus"] != "synthesis"
        }

    # 整合结果
    all_reviews = {name: f.result() for name, f in reviews.items()}
    return run_agent(AGENTS["synthesizer"], json.dumps(all_reviews))
```

---

*参考框架：LangGraph, CrewAI, AutoGen, Claude Agent SDK*
