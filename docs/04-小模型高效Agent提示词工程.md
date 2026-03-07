# 小模型 + 提示词工程：打造高效专用 Agent

> 核心洞见：一个配置精良的 Haiku，在特定任务上能超越配置糟糕的 Opus

---

## 一、模型选择策略

### 不同模型的定位

| 模型 | 速度 | 价格 | 适用场景 |
|------|------|------|---------|
| Claude Opus 4.6 | 慢 | 高 | 复杂推理、关键决策、架构设计 |
| Claude Sonnet 4.6 | 中 | 中 | 日常编程、分析、协调任务 |
| Claude Haiku 4.5 | 快 | 低 | 分类、提取、简单生成、高频调用 |
| 开源小模型(Qwen/Llama) | 极快 | 极低 | 本地部署、隐私数据、流量削峰 |

### 成本对比（实际数字参考）

```
处理 1000 个客服请求：
- 全用 Opus:   ~$15-30
- 全用 Haiku:  ~$0.5-1
- 混合策略:    ~$1-3（效果接近全 Sonnet）

混合策略：Haiku 处理 80% 简单请求，Sonnet 处理 15%，Opus 处理 5% 复杂案例
```

---

## 二、提示词工程核心技术

### 2.1 结构化提示词模板

```
Claude 的最佳提示词结构（XML 风格）：

<role>
你是一个{专业领域}专家，具备{具体能力}
</role>

<context>
{背景信息}
</context>

<instructions>
1. {具体步骤1}
2. {具体步骤2}
3. {具体步骤3}
</instructions>

<constraints>
- {约束条件1}
- {约束条件2}
</constraints>

<output_format>
{输出格式要求，最好给例子}
</output_format>

<input>
{实际输入}
</input>
```

**为什么用 XML 标签？**
- Claude 在训练中大量接触 XML，天然擅长解析
- 结构清晰，减少歧义
- 容易程序化生成和修改

---

### 2.2 Chain-of-Thought（思维链）提示词

**普通提示（效果一般）：**
```
判断这段代码是否有安全问题：{code}
```

**CoT 提示（效果显著提升）：**
```
分析以下代码的安全性。

请按照这个步骤思考：
1. 识别所有外部输入点（用户输入、文件、网络）
2. 追踪每个输入的数据流
3. 检查是否有 SQL/命令注入、XSS、越权访问等风险
4. 评估每个风险的严重程度

逐步分析，然后给出结论。

代码：
{code}
```

**效果：** 即使是 Haiku 这样的小模型，加上 CoT 后准确率大幅提升。

---

### 2.3 Few-shot（示例学习）

```python
FEW_SHOT_PROMPT = """
将用户反馈分类为：正面/负面/中性/功能请求

示例：
用户说："这个功能太棒了，帮我节省了很多时间"
分类：正面
原因：明确表达喜爱和价值

用户说："登录按钮点不了"
分类：负面
原因：描述了功能异常

用户说："能不能加个夜间模式？"
分类：功能请求
原因：提出新功能需求

用户说："收到了"
分类：中性
原因：无情感倾向

现在分类：
用户说："{user_feedback}"
分类：
"""
```

**关键原则：**
- 示例要覆盖边缘情况
- 示例格式要和期望输出完全一致
- 3-5 个示例通常够用，太多会浪费 tokens

---

### 2.4 输出格式强制（结构化输出）

```python
# 让小模型输出可解析的 JSON
JSON_PROMPT = """
分析以下代码，返回 JSON 格式结果：

{
  "has_bugs": true/false,
  "bugs": [
    {
      "line": 行号,
      "severity": "critical/high/medium/low",
      "type": "bug类型",
      "description": "描述",
      "fix": "修复建议"
    }
  ],
  "overall_quality": 0-10,
  "summary": "总结"
}

不要输出任何 JSON 以外的内容。

代码：
```{language}
{code}
```
"""

# 使用 Anthropic API 的结构化输出（更可靠）
response = client.messages.create(
    model="claude-haiku-4-5-20251001",
    max_tokens=1000,
    messages=[{"role": "user", "content": JSON_PROMPT}],
    # 在 Assistant 轮次预填充，强制以 { 开头
)
# 或使用 tool_use 模式强制结构化
```

---

### 2.5 提示词压缩（节省 Tokens）

```python
# 糟糕的提示词（冗余）
BAD_PROMPT = """
你好！我希望你能帮助我完成一个任务。这个任务是关于分析用户反馈的。
我想让你仔细阅读用户的反馈内容，然后认真分析一下这些反馈属于什么类别。
请你给出你的判断，告诉我这条反馈是正面的还是负面的还是中性的。
谢谢你的帮助！

用户反馈：{feedback}
"""

# 好的提示词（简洁）
GOOD_PROMPT = """
分类用户反馈为：正面/负面/中性/功能请求
只输出分类名称。

反馈：{feedback}
"""

# Token 对比：Bad=75 tokens, Good=25 tokens
# 1000 次调用省 50,000 tokens → 节省 ~$0.025（看起来少，但高频场景积累很多）
```

---

## 三、专用 Agent 的"技能专精"设计

### 核心思想：一个 Agent 只做一件事，做到极致

```python
# 专精代码审查的 Agent（而不是"通用助手"）
CODE_REVIEW_AGENT_PROMPT = """
你是一个代码安全审查专家。

专长：
- SQL 注入、XSS、CSRF、SSRF 等安全漏洞
- 认证和授权缺陷
- 加密和密钥管理问题
- 依赖包安全风险

输出格式（严格遵守）：
## 安全问题
[每个问题单独列出：严重程度 | 文件:行号 | 描述 | 修复建议]

## 整体评估
[一句话总结]

规则：
- 只报告安全问题，不评论代码风格
- 无安全问题时直接说"未发现安全漏洞"
- 不解释你是谁或你如何工作
"""
```

### 为什么专精比通用好？

1. **更短的提示词** → 更多 context 留给实际内容
2. **更少歧义** → 模型不需要猜测你想要什么
3. **更可预测** → 输出格式稳定，便于程序处理
4. **更容易调优** → 针对具体场景收集反馈和改进

---

## 四、提示词即代码（Prompt as Code）

用软件工程的方式管理提示词：

```python
# prompts/code_review.py
from dataclasses import dataclass
from typing import Optional

@dataclass
class PromptTemplate:
    """提示词模板，版本管理"""
    name: str
    version: str
    template: str
    model: str
    max_tokens: int
    description: str

    def render(self, **kwargs) -> str:
        return self.template.format(**kwargs)

# 版本化管理
CODE_REVIEW_V1 = PromptTemplate(
    name="code_review",
    version="1.0",
    model="claude-haiku-4-5-20251001",
    max_tokens=1500,
    description="基础代码安全审查",
    template="""
    审查以下{language}代码的安全问题：
    {code}
    """
)

CODE_REVIEW_V2 = PromptTemplate(
    name="code_review",
    version="2.0",  # 改进版
    model="claude-haiku-4-5-20251001",
    max_tokens=1500,
    description="增加了 OWASP Top 10 检查清单",
    template="""
    按 OWASP Top 10 检查以下{language}代码：
    检查清单：注入/认证/数据暴露/XXE/权限控制/安全配置/XSS/反序列化/组件漏洞/日志监控

    代码：
    {code}

    只报告发现的问题，格式：[严重程度] 行号: 问题描述 -> 修复方案
    """
)

# 使用 A/B 测试选择最佳版本
class PromptRegistry:
    def __init__(self):
        self.prompts = {}
        self.performance_metrics = {}

    def register(self, prompt: PromptTemplate):
        key = f"{prompt.name}_v{prompt.version}"
        self.prompts[key] = prompt

    def get_best(self, name: str) -> PromptTemplate:
        """返回性能最好的版本"""
        candidates = {k: v for k, v in self.prompts.items()
                      if k.startswith(name)}
        if not candidates:
            raise KeyError(f"No prompt found: {name}")

        best_key = max(
            candidates.keys(),
            key=lambda k: self.performance_metrics.get(k, {}).get("score", 0)
        )
        return candidates[best_key]

    def record_result(self, prompt_name: str, version: str,
                       success: bool, latency: float):
        """记录提示词的执行结果，用于自动优化"""
        key = f"{prompt_name}_v{version}"
        if key not in self.performance_metrics:
            self.performance_metrics[key] = {"runs": 0, "successes": 0, "avg_latency": 0}

        m = self.performance_metrics[key]
        m["runs"] += 1
        m["successes"] += int(success)
        m["avg_latency"] = (m["avg_latency"] * (m["runs"] - 1) + latency) / m["runs"]
        m["score"] = m["successes"] / m["runs"]
```

---

## 五、小模型 + RAG = 大模型级别的知识能力

```python
class RAGAgent:
    """
    用小模型 + 向量数据库实现"超出训练集"的能力
    成本：Haiku + 向量DB << Opus 直接回答
    效果：在专有知识领域超越 Opus
    """

    def __init__(self, knowledge_dir: str):
        self.vector_db = self._build_vector_db(knowledge_dir)
        self.client = anthropic.Anthropic()

    def _build_vector_db(self, directory: str):
        """构建向量数据库（一次性，可缓存）"""
        documents = load_documents(directory)
        chunks = split_into_chunks(documents, size=500, overlap=50)
        embeddings = embed_all(chunks)
        return VectorDB(chunks, embeddings)

    def answer(self, question: str) -> str:
        # 1. 检索（快速）
        relevant_chunks = self.vector_db.search(question, top_k=5)
        context = "\n\n".join(relevant_chunks)

        # 2. 生成（用小模型）
        response = self.client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=800,
            messages=[{
                "role": "user",
                "content": f"""
                基于以下文档回答问题。如果文档中没有相关信息，直接说不知道。

                <documents>
                {context}
                </documents>

                问题：{question}
                """
            }]
        )
        return response.content[0].text
```

---

## 六、Agent 路由器（让对的任务用对的模型）

```python
class AgentRouter:
    """
    智能路由：自动判断任务复杂度，选择合适模型
    关键优化：路由器本身用 Haiku（便宜快速）
    """

    ROUTING_PROMPT = """
    判断以下任务的复杂度（只输出数字1-3）：
    1 = 简单（分类、提取、格式转换、简单问答）
    2 = 中等（代码生成、分析、多步骤推理）
    3 = 复杂（架构设计、创意写作、深度分析、跨领域整合）

    任务：{task}
    """

    MODEL_MAP = {
        1: "claude-haiku-4-5-20251001",
        2: "claude-sonnet-4-6",
        3: "claude-opus-4-6"
    }

    def route(self, task: str) -> str:
        # 用 Haiku 判断复杂度（约 0.001 美分）
        complexity = int(self.client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=5,
            messages=[{"role": "user",
                       "content": self.ROUTING_PROMPT.format(task=task)}]
        ).content[0].text.strip())

        return self.MODEL_MAP.get(complexity, "claude-sonnet-4-6")

    def run(self, task: str) -> str:
        model = self.route(task)
        # 用合适的模型执行
        return self._execute(model, task)
```

---

## 七、高频调用优化清单

- [ ] **缓存常见查询**：相同/相似输入不重复调用（节省 60-80% 成本）
- [ ] **批处理**：多条相似任务合并一次调用
- [ ] **流式输出**：用户感知延迟减少 60%（`stream=True`）
- [ ] **提前终止**：得到需要的信息就停止，不等完整回复
- [ ] **温度设置**：确定性任务用 `temperature=0`，避免重试
- [ ] **系统缓存**：`cache_control: {"type": "ephemeral"}` 缓存长系统提示词

---

*核心参考：Anthropic Prompt Engineering Guide, DSPy, PromptFlow*
