# 软件工程原则与 Agent 设计：用 OOP/SOLID 构建可维护的智能体系统

---

## 一、为什么要把软件工程原则用于 Agent？

Agent 系统面临的挑战和传统软件一模一样：
- 需求不断变化 → 需要可扩展
- 多人协作 → 需要可维护
- 出了问题 → 需要可调试
- 功能越来越多 → 需要防止"混乱膨胀"

好消息：软件工程几十年积累的智慧完全适用于 Agent 设计！

---

## 二、SOLID 原则在 Agent 中的应用

### S — 单一职责原则（Single Responsibility）

**软件版本：** 一个类只做一件事

**Agent 版本：** 一个 Agent 只有一个专长

```python
# ❌ 违反 SRP 的 Agent（什么都干）
class GodAgent:
    def handle_customer_service(self): ...
    def write_code(self): ...
    def analyze_data(self): ...
    def manage_schedule(self): ...
    # 什么都能做 = 什么都做不精

# ✅ 遵守 SRP 的 Agent（专精）
class CustomerServiceAgent:
    """只处理客户服务，内部再细分意图"""
    def classify_intent(self): ...
    def generate_response(self): ...
    def escalate_to_human(self): ...

class CodeGenerationAgent:
    """只生成代码"""
    def understand_requirements(self): ...
    def generate_code(self): ...
    def add_tests(self): ...

class DataAnalysisAgent:
    """只分析数据"""
    def load_data(self): ...
    def run_analysis(self): ...
    def visualize(self): ...
```

---

### O — 开闭原则（Open/Closed）

**软件版本：** 对扩展开放，对修改关闭

**Agent 版本：** 添加新能力不修改核心，通过插件/工具扩展

```python
class AgentCore:
    """核心 Agent 逻辑，不修改"""
    def __init__(self):
        self.tools: dict[str, Tool] = {}
        self.skills: dict[str, Skill] = {}

    def register_tool(self, tool: Tool):
        """扩展点：添加新工具不修改核心代码"""
        self.tools[tool.name] = tool

    def register_skill(self, skill: Skill):
        """扩展点：添加新技能不修改核心代码"""
        self.skills[skill.name] = skill

    def run(self, task: str) -> str:
        # 核心逻辑不变，但通过已注册的工具和技能扩展能力
        ...

# 添加新能力时，只需要注册，不需要修改 AgentCore
agent = AgentCore()
agent.register_tool(BraveSearchTool())    # 增加搜索能力
agent.register_tool(PostgreSQLTool())     # 增加数据库能力
agent.register_skill(CodeReviewSkill())  # 增加代码审查技能
agent.register_skill(DataAnalysisSkill()) # 增加数据分析技能
```

---

### L — 里氏替换原则（Liskov Substitution）

**Agent 版本：** 专用 Agent 可以替换通用 Agent，且表现更好

```python
from abc import ABC, abstractmethod

class BaseAgent(ABC):
    """所有 Agent 的基类，定义接口契约"""

    @abstractmethod
    def handle(self, task: str, context: dict) -> AgentResponse:
        """处理任务，所有子类必须实现"""
        pass

    @abstractmethod
    def can_handle(self, task: str) -> float:
        """返回0-1，表示能处理该任务的置信度"""
        pass

class GeneralAgent(BaseAgent):
    """通用 Agent，什么都能处理，但不专精"""
    def can_handle(self, task: str) -> float:
        return 0.5  # 总是中等置信度

class PythonExpertAgent(BaseAgent):
    """Python 专家 Agent，对 Python 任务更好"""
    def can_handle(self, task: str) -> float:
        if "python" in task.lower() or ".py" in task:
            return 0.95  # 高置信度
        return 0.1  # 不擅长其他

# 路由器：自动选择最合适的 Agent（里氏替换的体现）
class AgentSelector:
    def __init__(self, agents: list[BaseAgent]):
        self.agents = agents

    def select(self, task: str) -> BaseAgent:
        return max(self.agents, key=lambda a: a.can_handle(task))
```

---

### I — 接口隔离原则（Interface Segregation）

**Agent 版本：** 工具接口要小而精，不强迫 Agent 依赖不需要的能力

```python
# ❌ 胖接口（强迫实现所有能力）
class MegaTool:
    def search_web(self): ...
    def read_file(self): ...
    def write_file(self): ...
    def send_email(self): ...
    def run_code(self): ...
    # 一个只需要搜索的 Agent 被迫依赖发邮件功能

# ✅ 细粒度接口
class SearchCapability:
    def search(self, query: str) -> list[str]: ...

class FileReadCapability:
    def read(self, path: str) -> str: ...

class FileWriteCapability:
    def write(self, path: str, content: str) -> bool: ...

class EmailCapability:
    def send(self, to: str, subject: str, body: str) -> bool: ...

# Agent 按需组合
class ResearchAgent(SearchCapability, FileWriteCapability):
    """只需要搜索和写文件"""
    pass

class FileProcessorAgent(FileReadCapability, FileWriteCapability):
    """只需要读写文件"""
    pass
```

---

### D — 依赖倒置原则（Dependency Inversion）

**Agent 版本：** Agent 依赖抽象接口，不依赖具体实现（易于替换模型/工具）

```python
from abc import ABC, abstractmethod

# 抽象接口
class LLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str, max_tokens: int) -> str: ...

class VectorStore(ABC):
    @abstractmethod
    def search(self, query: str, top_k: int) -> list: ...

# 具体实现
class ClaudeProvider(LLMProvider):
    def generate(self, prompt: str, max_tokens: int) -> str:
        return anthropic_client.generate(prompt, max_tokens)

class OpenAIProvider(LLMProvider):
    def generate(self, prompt: str, max_tokens: int) -> str:
        return openai_client.generate(prompt, max_tokens)

class PineconeStore(VectorStore):
    def search(self, query: str, top_k: int) -> list:
        return pinecone_client.query(query, top_k)

class ChromaStore(VectorStore):
    def search(self, query: str, top_k: int) -> list:
        return chroma_client.query(query, top_k)

# Agent 依赖抽象，不依赖具体实现
class ResearchAgent:
    def __init__(self, llm: LLMProvider, store: VectorStore):
        self.llm = llm    # 任意 LLM 都行
        self.store = store # 任意向量数据库都行

# 轻松切换
agent = ResearchAgent(
    llm=ClaudeProvider(),    # 换成 OpenAIProvider() 也行
    store=ChromaStore()      # 换成 PineconeStore() 也行
)
```

---

## 三、设计模式在 Agent 中的应用

### 3.1 策略模式（Strategy Pattern）— 可替换的执行策略

```python
class TaskExecutionStrategy(ABC):
    @abstractmethod
    def execute(self, task: str, context: dict) -> str: ...

class DirectExecutionStrategy(TaskExecutionStrategy):
    """直接执行，不验证"""
    def execute(self, task: str, context: dict) -> str:
        return run_task(task)

class VerifiedExecutionStrategy(TaskExecutionStrategy):
    """执行前验证，执行后检查"""
    def execute(self, task: str, context: dict) -> str:
        if not validate(task):
            raise ValueError("任务验证失败")
        result = run_task(task)
        assert quality_check(result), "结果质量不合格"
        return result

class SandboxedExecutionStrategy(TaskExecutionStrategy):
    """在沙箱中执行，防止副作用"""
    def execute(self, task: str, context: dict) -> str:
        with Sandbox() as sandbox:
            return sandbox.run(task)

# Agent 可以动态切换策略
class Agent:
    def __init__(self, strategy: TaskExecutionStrategy):
        self.strategy = strategy

    def set_strategy(self, strategy: TaskExecutionStrategy):
        self.strategy = strategy  # 运行时切换策略

    def run(self, task: str) -> str:
        return self.strategy.execute(task, self.context)
```

---

### 3.2 观察者模式（Observer Pattern）— Agent 事件系统

```python
class AgentEvent:
    TASK_STARTED = "task_started"
    TOOL_CALLED = "tool_called"
    TASK_COMPLETED = "task_completed"
    ERROR_OCCURRED = "error_occurred"
    KNOWLEDGE_UPDATED = "knowledge_updated"

class EventBus:
    def __init__(self):
        self._handlers: dict[str, list] = {}

    def subscribe(self, event: str, handler):
        self._handlers.setdefault(event, []).append(handler)

    def publish(self, event: str, data: dict):
        for handler in self._handlers.get(event, []):
            handler(data)

# 全局事件总线
bus = EventBus()

# 各种观察者
bus.subscribe(AgentEvent.TASK_COMPLETED, logger.log)        # 日志
bus.subscribe(AgentEvent.TASK_COMPLETED, metrics.record)   # 监控
bus.subscribe(AgentEvent.ERROR_OCCURRED, alerter.alert)    # 告警
bus.subscribe(AgentEvent.KNOWLEDGE_UPDATED, sync.sync)     # 同步

# Agent 只负责发布事件
class InstrumentedAgent:
    def run(self, task: str) -> str:
        bus.publish(AgentEvent.TASK_STARTED, {"task": task})
        try:
            result = self._execute(task)
            bus.publish(AgentEvent.TASK_COMPLETED, {"task": task, "result": result})
            return result
        except Exception as e:
            bus.publish(AgentEvent.ERROR_OCCURRED, {"task": task, "error": str(e)})
            raise
```

---

### 3.3 装饰器模式（Decorator Pattern）— Agent 能力增强

```python
class AgentDecorator(BaseAgent):
    """装饰器基类"""
    def __init__(self, agent: BaseAgent):
        self._agent = agent

    def handle(self, task: str, context: dict) -> AgentResponse:
        return self._agent.handle(task, context)

class CachingDecorator(AgentDecorator):
    """增加缓存能力"""
    def __init__(self, agent, ttl: int = 3600):
        super().__init__(agent)
        self.cache = {}
        self.ttl = ttl

    def handle(self, task: str, context: dict) -> AgentResponse:
        cache_key = hash(task + str(context))
        if cache_key in self.cache:
            return self.cache[cache_key]
        result = self._agent.handle(task, context)
        self.cache[cache_key] = result
        return result

class RetryDecorator(AgentDecorator):
    """增加自动重试能力"""
    def __init__(self, agent, max_retries: int = 3):
        super().__init__(agent)
        self.max_retries = max_retries

    def handle(self, task: str, context: dict) -> AgentResponse:
        for attempt in range(self.max_retries):
            try:
                return self._agent.handle(task, context)
            except TransientError as e:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2 ** attempt)

class LoggingDecorator(AgentDecorator):
    """增加日志能力"""
    def handle(self, task: str, context: dict) -> AgentResponse:
        logger.info(f"Agent 处理任务: {task[:50]}...")
        start = time.time()
        result = self._agent.handle(task, context)
        logger.info(f"完成，耗时 {time.time()-start:.2f}s")
        return result

# 组合使用（洋葱模型）
base_agent = CodeReviewAgent()
enhanced_agent = LoggingDecorator(
    RetryDecorator(
        CachingDecorator(base_agent, ttl=1800),
        max_retries=3
    )
)
```

---

## 四、Agent 系统的分层架构

```
┌─────────────────────────────────────┐
│            API / Interface 层        │  ← 对外接口，接受请求
├─────────────────────────────────────┤
│          Orchestration 层            │  ← 任务路由，Agent 协调
├─────────────────────────────────────┤
│           Agent 执行层               │  ← 具体 Agent 逻辑
├─────────────────────────────────────┤
│           Tools / Skills 层          │  ← 工具调用，技能执行
├─────────────────────────────────────┤
│         Knowledge / Memory 层        │  ← 知识存储，记忆管理
├─────────────────────────────────────┤
│           Infrastructure 层          │  ← LLM API, 数据库, 缓存
└─────────────────────────────────────┘
```

**关键规则：**
- 上层可以调用下层，下层不能调用上层
- 同层之间通过接口通信，不直接依赖
- 每层可以独立测试和替换

---

## 五、Agent 系统的测试策略

```python
# 单元测试：测试单个 Agent 的逻辑（Mock LLM）
class TestCodeReviewAgent:
    def test_detects_sql_injection(self):
        agent = CodeReviewAgent(llm=MockLLM(response="发现SQL注入漏洞"))
        result = agent.handle("审查代码: SELECT * FROM users WHERE id = " + user_input)
        assert "SQL注入" in result.text

# 集成测试：测试 Agent 间协作
class TestMultiAgentPipeline:
    def test_full_review_pipeline(self):
        pipeline = create_review_pipeline()
        result = pipeline.run(sample_code)
        assert result.has_security_review
        assert result.has_performance_review
        assert result.has_synthesis

# 回归测试：确保新版本不比旧版本差
class TestAgentRegression:
    def test_no_regression(self):
        old_scores = load_benchmark_scores("v1.0")
        new_scores = run_benchmark(current_agent)
        assert new_scores.accuracy >= old_scores.accuracy * 0.95
```

---

*核心参考：Clean Architecture (Uncle Bob), Design Patterns (GoF), Domain-Driven Design*
