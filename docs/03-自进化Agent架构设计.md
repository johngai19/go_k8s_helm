# 自进化 Agent：架构设计与实现指南

> 核心思想：Agent 不只是执行任务，还能从执行中学习并改进自身

---

## 一、什么是"自进化"Agent？

传统 Agent：
```
输入 → [固定逻辑] → 输出
（每次都一样，不会变）
```

自进化 Agent：
```
输入 → [执行] → 输出
          ↓
       [反思/评估]
          ↓
       [更新知识/提示词/策略]
          ↓
       下次执行变得更好
```

**自进化的三个维度：**
1. **知识积累** — 记住有用的信息和解决方案
2. **技能优化** — 改进提示词、工具调用策略
3. **行为校正** — 从错误中学习，避免重蹈覆辙

---

## 二、核心架构：Knowledge-Skills 解耦设计

这是一个重要的新架构理念，类比软件工程中的"数据与逻辑分离"：

```
┌─────────────────────────────────────────┐
│              Agent 核心                  │
├──────────────────┬──────────────────────┤
│   Knowledge Base │    Skills Library     │
│  (知识库 - 数据) │   (技能库 - 逻辑)    │
│                  │                       │
│ • 领域事实       │ • 提示词模板          │
│ • 历史记录       │ • 工具调用序列        │
│ • 用户偏好       │ • 解决问题的步骤      │
│ • 错误教训       │ • 决策规则            │
│ • 成功案例       │ • 工作流程            │
├──────────────────┴──────────────────────┤
│           Reflection Engine             │
│            (反思引擎)                    │
│  • 评估执行质量                          │
│  • 提取可复用知识                        │
│  • 优化技能参数                          │
└─────────────────────────────────────────┘
```

### 为什么要解耦？

| 不解耦（混在一起） | 解耦后 |
|----------------|--------|
| 知识更新需要修改代码 | 知识独立存储，随时更新 |
| 技能无法跨 Agent 复用 | 技能可组合、继承、共享 |
| 错误学习难以追踪 | 清晰记录"什么出错了" |
| 个性化困难 | 每个用户有独立知识库 |

---

## 三、Knowledge Base 设计

### 3.1 分层知识结构

```python
class KnowledgeBase:
    """
    知识库层次：
    L0 - 原始事实（来自外部）
    L1 - 提炼的规则（从 L0 推导）
    L2 - 元知识（关于知识本身的知识）
    """

    def __init__(self, storage_path: str):
        self.facts = {}        # L0: 原始事实
        self.rules = {}        # L1: 提炼规则
        self.meta = {}         # L2: 元知识
        self.embeddings = {}   # 向量索引，用于语义搜索
        self.storage_path = storage_path

    def add_fact(self, key: str, value: any, source: str, confidence: float = 1.0):
        """添加事实，带来源和置信度"""
        self.facts[key] = {
            "value": value,
            "source": source,
            "confidence": confidence,
            "created_at": datetime.now().isoformat(),
            "access_count": 0
        }
        self._update_embedding(key, str(value))

    def add_lesson(self, situation: str, mistake: str, correction: str):
        """记录教训"""
        lesson_id = f"lesson_{len(self.rules)}"
        self.rules[lesson_id] = {
            "type": "lesson",
            "situation": situation,
            "mistake": mistake,
            "correction": correction,
            "importance": 1.0
        }

    def search(self, query: str, top_k: int = 5) -> list:
        """语义搜索相关知识"""
        query_embedding = embed(query)
        results = []
        for key, embedding in self.embeddings.items():
            score = cosine_similarity(query_embedding, embedding)
            results.append((score, key, self.facts.get(key) or self.rules.get(key)))
        return sorted(results, reverse=True)[:top_k]

    def forget_stale(self, days: int = 30):
        """遗忘长期未访问的低价值知识"""
        threshold = datetime.now() - timedelta(days=days)
        to_delete = [
            k for k, v in self.facts.items()
            if v["access_count"] < 2 and
               datetime.fromisoformat(v["created_at"]) < threshold and
               v["confidence"] < 0.7
        ]
        for k in to_delete:
            del self.facts[k]
```

### 3.2 Knowledge Graph（知识图谱）

比平铺存储更强大，适合复杂关系：

```python
# 使用 MCP memory server 的 Knowledge Graph 模式
# 实体 + 关系 形式存储

entities = [
    {"name": "用户A", "type": "user", "attrs": {"preference": "简洁风格"}},
    {"name": "Python调试", "type": "skill", "attrs": {"difficulty": "medium"}},
]

relations = [
    {"from": "用户A", "to": "Python调试", "type": "擅长"},
    {"from": "Python调试", "to": "pdb工具", "type": "使用工具"},
]
```

---

## 四、Skills Library 设计

### 4.1 技能定义

```python
from dataclasses import dataclass
from typing import Callable

@dataclass
class Skill:
    name: str
    description: str
    prompt_template: str        # 可优化的提示词模板
    tool_sequence: list[str]    # 调用工具的顺序
    success_criteria: str       # 成功判断标准
    version: int = 1
    performance_score: float = 0.5  # 0-1，会随使用更新

class SkillsLibrary:
    def __init__(self):
        self.skills: dict[str, Skill] = {}

    def register(self, skill: Skill):
        self.skills[skill.name] = skill

    def evolve_skill(self, skill_name: str, feedback: str, new_prompt: str):
        """根据反馈进化技能"""
        skill = self.skills[skill_name]
        # 保存旧版本
        old_version = f"{skill_name}_v{skill.version}"
        self.skills[old_version] = skill

        # 更新技能
        skill.prompt_template = new_prompt
        skill.version += 1
```

### 4.2 技能的面向对象设计（继承和组合）

```python
# 基础技能
class BaseSkill:
    def execute(self, context: dict) -> str:
        raise NotImplementedError

# 继承：特化技能
class PythonDebugSkill(BaseSkill):
    """继承自基础调试技能，专门处理 Python"""
    parent_skill = "generic_debug"

    def execute(self, context: dict) -> str:
        # 先调用父技能的通用逻辑
        base_analysis = super().execute(context)
        # 再添加 Python 特有处理
        return self._python_specific(base_analysis, context)

# 组合：复合技能
class CodeReviewSkill(BaseSkill):
    """组合多个子技能"""
    def __init__(self):
        self.sub_skills = [
            SecurityCheckSkill(),
            PerformanceCheckSkill(),
            StyleCheckSkill()
        ]

    def execute(self, context: dict) -> str:
        results = [skill.execute(context) for skill in self.sub_skills]
        return self._synthesize(results)
```

---

## 五、反思引擎（Reflection Engine）

这是自进化的核心：

```python
class ReflectionEngine:
    def __init__(self, kb: KnowledgeBase, skills: SkillsLibrary):
        self.kb = kb
        self.skills = skills
        self.client = anthropic.Anthropic()

    def reflect_on_task(self, task: str, execution_trace: list, result: str,
                         user_feedback: str = None) -> dict:
        """对任务执行进行反思"""

        reflection_prompt = f"""
        任务：{task}

        执行过程：
        {json.dumps(execution_trace, ensure_ascii=False, indent=2)}

        结果：{result}

        用户反馈：{user_feedback or "未提供"}

        请分析：
        1. 执行中有哪些做得好的地方？（可复用的成功模式）
        2. 有哪些失误或低效？（需要避免的错误）
        3. 哪些知识应该记录下来？
        4. 哪个技能/提示词可以改进？给出具体改进建议。
        5. 这个任务的成功率评估（0-1）

        返回 JSON 格式。
        """

        response = self.client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            messages=[{"role": "user", "content": reflection_prompt}]
        )

        insights = json.loads(response.content[0].text)
        self._apply_insights(insights, task)
        return insights

    def _apply_insights(self, insights: dict, task: str):
        """将反思结果应用到知识库和技能库"""
        # 更新知识库
        for lesson in insights.get("lessons", []):
            self.kb.add_lesson(
                situation=lesson["situation"],
                mistake=lesson["mistake"],
                correction=lesson["correction"]
            )

        # 优化技能
        for improvement in insights.get("skill_improvements", []):
            skill_name = improvement["skill"]
            if skill_name in self.skills.skills:
                self.skills.evolve_skill(
                    skill_name,
                    feedback=improvement["feedback"],
                    new_prompt=improvement["improved_prompt"]
                )

        # 记录成功模式
        if insights.get("success_score", 0) > 0.8:
            self.kb.add_fact(
                key=f"success_pattern_{hash(task)}",
                value=insights.get("success_patterns"),
                source="reflection",
                confidence=insights.get("success_score", 0.8)
            )
```

---

## 六、完整的自进化 Agent 框架

```python
class EvolvingAgent:
    """
    自进化智能体：
    - 每次任务执行后自动反思
    - 持续积累知识和优化技能
    - 支持多用户隔离的个性化
    """

    def __init__(self, agent_id: str, user_id: str = "default"):
        self.agent_id = agent_id
        self.user_id = user_id

        # 核心组件
        self.kb = KnowledgeBase(f"./data/kb_{user_id}.json")
        self.skills = SkillsLibrary()
        self.reflection = ReflectionEngine(self.kb, self.skills)

        # MCP 工具
        self.tools = self._load_mcp_tools()

        # 执行追踪
        self.execution_trace = []

    def run(self, task: str) -> str:
        """执行任务，自动追踪和反思"""
        self.execution_trace = []

        # 1. 检索相关知识
        relevant_knowledge = self.kb.search(task, top_k=5)
        context = self._build_context(task, relevant_knowledge)

        # 2. 选择合适技能
        skill = self._select_skill(task)

        # 3. 执行
        result = self._execute_with_skill(skill, context, task)

        # 4. 异步反思（不阻塞响应）
        threading.Thread(
            target=self.reflection.reflect_on_task,
            args=(task, self.execution_trace, result)
        ).start()

        return result

    def _build_context(self, task: str, knowledge: list) -> str:
        """将知识注入上下文"""
        if not knowledge:
            return task

        knowledge_text = "\n".join([
            f"- {item[1]}: {item[2]['value'] if 'value' in item[2] else item[2]}"
            for item in knowledge
        ])

        return f"""
        <relevant_knowledge>
        {knowledge_text}
        </relevant_knowledge>

        <task>
        {task}
        </task>
        """

    def teach(self, fact: str, category: str = "general"):
        """直接教给 Agent 知识"""
        self.kb.add_fact(
            key=f"{category}_{hash(fact)}",
            value=fact,
            source="human_teaching",
            confidence=1.0
        )
```

---

## 七、自进化的最佳实践

### DO ✅
- **渐进式进化**：每次微调，不要大幅改变
- **版本控制技能**：保留历史版本，可回滚
- **置信度管理**：低置信度知识不要轻易覆盖高置信度知识
- **遗忘机制**：过期无用的知识要清理，避免"知识污染"
- **人在循环**：重要决策让人类确认

### DON'T ❌
- 盲目相信用户反馈（可能有噪音）
- 把错误的成功案例记入知识库
- 无限制积累知识（内存和性能问题）
- 让 Agent 自己修改自己的核心约束（安全风险）

---

## 八、与 LangGraph 集成示例

```python
from langgraph.graph import StateGraph, END

def create_evolving_workflow():
    """使用 LangGraph 构建有状态的自进化工作流"""

    workflow = StateGraph(AgentState)

    # 节点
    workflow.add_node("retrieve_knowledge", retrieve_knowledge)
    workflow.add_node("plan", plan_task)
    workflow.add_node("execute", execute_task)
    workflow.add_node("evaluate", evaluate_result)
    workflow.add_node("update_knowledge", update_knowledge)

    # 边（流程）
    workflow.set_entry_point("retrieve_knowledge")
    workflow.add_edge("retrieve_knowledge", "plan")
    workflow.add_edge("plan", "execute")
    workflow.add_edge("execute", "evaluate")

    # 条件边：评估后决定是否重试
    workflow.add_conditional_edges(
        "evaluate",
        lambda state: "retry" if state["quality_score"] < 0.7 else "done",
        {
            "retry": "plan",      # 质量不够，重新规划
            "done": "update_knowledge"  # 质量OK，更新知识
        }
    )
    workflow.add_edge("update_knowledge", END)

    return workflow.compile()
```

---

*核心参考：Anthropic Agent Guidelines, LangGraph, Reflexion Paper, MemGPT*
