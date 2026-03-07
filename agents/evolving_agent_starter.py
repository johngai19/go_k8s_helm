"""
自进化 Agent 入门框架
可直接运行的最小实现

依赖安装：
pip install anthropic

运行：
python evolving_agent_starter.py
"""

import json
import os
import hashlib
from datetime import datetime
from pathlib import Path
import anthropic

# ============================================================
# 配置
# ============================================================
MODEL_STRONG = "claude-sonnet-4-6"       # 用于复杂任务和反思
MODEL_FAST = "claude-haiku-4-5-20251001"  # 用于简单任务和分类
MEMORY_FILE = Path("./agent_memory.json") # 持久化记忆文件


# ============================================================
# 知识库（轻量级实现）
# ============================================================
class SimpleKnowledgeBase:
    """简单的 JSON 文件知识库，开箱即用"""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data = self._load()

    def _load(self) -> dict:
        if self.file_path.exists():
            with open(self.file_path) as f:
                return json.load(f)
        return {"facts": {}, "lessons": [], "successes": []}

    def _save(self):
        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

    def add_fact(self, key: str, value: str):
        self.data["facts"][key] = {
            "value": value,
            "created_at": datetime.now().isoformat()
        }
        self._save()

    def add_lesson(self, situation: str, lesson: str):
        self.data["lessons"].append({
            "situation": situation,
            "lesson": lesson,
            "created_at": datetime.now().isoformat()
        })
        self._save()

    def add_success(self, task: str, approach: str):
        self.data["successes"].append({
            "task": task,
            "approach": approach,
            "created_at": datetime.now().isoformat()
        })
        self._save()

    def get_relevant_context(self, task: str, max_items: int = 5) -> str:
        """获取与当前任务相关的知识（简单关键词匹配）"""
        relevant = []
        task_lower = task.lower()

        # 搜索事实
        for key, fact in self.data["facts"].items():
            if any(word in key.lower() or word in str(fact["value"]).lower()
                   for word in task_lower.split() if len(word) > 3):
                relevant.append(f"[知识] {key}: {fact['value']}")

        # 搜索教训
        for lesson in self.data["lessons"][-10:]:  # 最近10条
            if any(word in lesson["situation"].lower()
                   for word in task_lower.split() if len(word) > 3):
                relevant.append(f"[教训] {lesson['situation']} → {lesson['lesson']}")

        # 搜索成功案例
        for success in self.data["successes"][-5:]:  # 最近5条
            if any(word in success["task"].lower()
                   for word in task_lower.split() if len(word) > 3):
                relevant.append(f"[成功案例] {success['task']}: {success['approach']}")

        return "\n".join(relevant[:max_items]) if relevant else ""

    def summary(self) -> str:
        return (f"知识库状态：{len(self.data['facts'])} 条事实，"
                f"{len(self.data['lessons'])} 条教训，"
                f"{len(self.data['successes'])} 个成功案例")


# ============================================================
# 核心 Agent
# ============================================================
class EvolvingAgent:
    """
    自进化 Agent：
    - 每次任务后自动反思并更新知识库
    - 下次遇到相似任务会更好
    """

    def __init__(self, name: str = "Assistant"):
        self.name = name
        self.kb = SimpleKnowledgeBase(MEMORY_FILE)
        self.client = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY")
        )
        print(f"[{self.name}] 启动完成。{self.kb.summary()}")

    def _classify_complexity(self, task: str) -> int:
        """判断任务复杂度（1=简单，2=中等，3=复杂）"""
        response = self.client.messages.create(
            model=MODEL_FAST,
            max_tokens=5,
            messages=[{
                "role": "user",
                "content": f"""判断任务复杂度，只输出1、2或3：
1=简单（翻译/格式转换/简单问答）
2=中等（分析/代码生成/多步骤）
3=复杂（架构设计/深度研究/创意写作）

任务：{task}
复杂度："""
            }]
        )
        try:
            return int(response.content[0].text.strip()[0])
        except:
            return 2

    def _select_model(self, complexity: int) -> str:
        """根据复杂度选择模型"""
        return MODEL_STRONG if complexity >= 2 else MODEL_FAST

    def _build_system_prompt(self, task: str) -> str:
        """构建包含历史知识的系统提示词"""
        relevant_knowledge = self.kb.get_relevant_context(task)

        base_prompt = f"""你是 {self.name}，一个持续学习和进化的 AI 助手。"""

        if relevant_knowledge:
            base_prompt += f"""

根据过去的经验，以下知识可能对当前任务有帮助：
{relevant_knowledge}

请结合这些经验来处理当前任务。"""

        return base_prompt

    def run(self, task: str, reflect: bool = True) -> str:
        """
        执行任务

        Args:
            task: 任务描述
            reflect: 是否在完成后反思（默认开启）

        Returns:
            任务结果
        """
        print(f"\n[{self.name}] 处理任务：{task[:50]}...")

        # 1. 判断复杂度，选择模型
        complexity = self._classify_complexity(task)
        model = self._select_model(complexity)
        print(f"[{self.name}] 复杂度：{complexity}/3，使用模型：{model.split('-')[1]}")

        # 2. 构建上下文
        system_prompt = self._build_system_prompt(task)

        # 3. 执行任务
        response = self.client.messages.create(
            model=model,
            max_tokens=2000,
            system=system_prompt,
            messages=[{"role": "user", "content": task}]
        )
        result = response.content[0].text

        # 4. 反思（异步感觉，实际同步）
        if reflect and complexity >= 2:
            self._reflect(task, result)

        return result

    def _reflect(self, task: str, result: str):
        """对执行结果进行反思，提取可复用的知识"""
        print(f"[{self.name}] 正在反思...")

        reflection_response = self.client.messages.create(
            model=MODEL_FAST,
            max_tokens=500,
            messages=[{
                "role": "user",
                "content": f"""对以下任务执行进行简短反思，返回 JSON：

任务：{task}
结果摘要：{result[:200]}...

返回格式（必须是合法JSON）：
{{
  "key_insight": "最重要的一句话洞察（可为null）",
  "lesson": "遇到类似情况应该注意什么（可为null）",
  "was_successful": true
}}

只返回JSON，不要其他内容。"""
            }]
        )

        try:
            text = reflection_response.content[0].text.strip()
            # 提取 JSON 部分
            if "```" in text:
                text = text.split("```")[1].replace("json", "").strip()

            insights = json.loads(text)

            if insights.get("key_insight"):
                key = hashlib.md5(task.encode()).hexdigest()[:8]
                self.kb.add_fact(f"insight_{key}", insights["key_insight"])

            if insights.get("lesson"):
                self.kb.add_lesson(task[:100], insights["lesson"])

            if insights.get("was_successful"):
                # 只记录前100字符的方法摘要
                approach = result[:100] + "..." if len(result) > 100 else result
                self.kb.add_success(task[:100], approach)

            print(f"[{self.name}] 反思完成，知识库已更新")

        except json.JSONDecodeError:
            pass  # 解析失败也没关系，不影响主流程

    def teach(self, fact: str, category: str = "general"):
        """直接教给 Agent 知识"""
        key = f"{category}_{hashlib.md5(fact.encode()).hexdigest()[:8]}"
        self.kb.add_fact(key, fact)
        print(f"[{self.name}] 已记住：{fact[:50]}...")

    def remember(self, key: str, value: str):
        """记住特定的键值对"""
        self.kb.add_fact(key, value)
        print(f"[{self.name}] 已记住 {key} = {value[:50]}...")

    def show_memory(self):
        """显示当前知识库内容"""
        print("\n=== 知识库内容 ===")
        print(f"事实（{len(self.kb.data['facts'])} 条）：")
        for key, fact in list(self.kb.data["facts"].items())[:5]:
            print(f"  {key}: {fact['value'][:60]}")

        print(f"\n教训（{len(self.kb.data['lessons'])} 条）：")
        for lesson in self.kb.data["lessons"][-3:]:
            print(f"  {lesson['situation'][:40]} → {lesson['lesson'][:60]}")

        print(f"\n成功案例（{len(self.kb.data['successes'])} 条）：")
        for s in self.kb.data["successes"][-3:]:
            print(f"  {s['task'][:60]}")
        print("==================\n")


# ============================================================
# 多 Agent 协作示例
# ============================================================
def multi_agent_code_review(code: str) -> dict:
    """
    使用多个专用 Agent 进行代码审查
    展示并行执行模式
    """
    import threading

    client = anthropic.Anthropic()
    results = {}

    def run_specialized_review(role: str, focus: str, system: str):
        response = client.messages.create(
            model=MODEL_FAST,
            max_tokens=800,
            system=system,
            messages=[{"role": "user", "content": f"审查以下代码：\n\n```\n{code}\n```"}]
        )
        results[role] = response.content[0].text

    # 三个专家并行审查
    threads = [
        threading.Thread(target=run_specialized_review, args=(
            "security", "安全",
            "你是安全专家。只检查安全漏洞：SQL注入/XSS/认证问题等。每条问题格式：[严重程度] 行X: 问题 → 修复"
        )),
        threading.Thread(target=run_specialized_review, args=(
            "performance", "性能",
            "你是性能专家。只检查性能问题：N+1查询/内存泄漏/算法复杂度等。每条格式：[影响程度] 行X: 问题 → 优化"
        )),
        threading.Thread(target=run_specialized_review, args=(
            "maintainability", "可维护性",
            "你是代码质量专家。只检查可维护性：命名/结构/重复代码/注释等。每条格式：[优先级] 行X: 问题 → 建议"
        )),
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 综合分析（用强模型）
    synthesis = client.messages.create(
        model=MODEL_STRONG,
        max_tokens=1000,
        messages=[{
            "role": "user",
            "content": f"""整合以下三个专家的代码审查意见，给出优先级排序的改进建议：

安全审查：
{results.get('security', '无')}

性能审查：
{results.get('performance', '无')}

可维护性审查：
{results.get('maintainability', '无')}

请给出：
1. 必须立即修复的问题（P0）
2. 应该尽快修复的问题（P1）
3. 可以考虑改进的地方（P2）
4. 整体评分（1-10分）"""
        }]
    ).content[0].text

    results["synthesis"] = synthesis
    return results


# ============================================================
# 主程序（演示）
# ============================================================
if __name__ == "__main__":
    # 基本使用
    agent = EvolvingAgent(name="MyAgent")

    # 教给 Agent 一些知识
    agent.teach("用户偏好简洁的代码风格，不喜欢过度注释", "user_preference")
    agent.teach("项目使用 Python 3.11，FastAPI 框架", "project_context")
    agent.remember("user_name", "开发者小王")

    print("\n" + "="*50)
    print("示例 1：普通任务（自动选择 Haiku）")
    print("="*50)
    result = agent.run("将 hello world 翻译成中文", reflect=False)
    print(f"结果：{result}")

    print("\n" + "="*50)
    print("示例 2：中等复杂度任务（自动选择 Sonnet，执行后反思）")
    print("="*50)
    result = agent.run("用 Python 写一个读取 CSV 文件并计算平均值的函数")
    print(f"结果预览：{result[:200]}...")

    print("\n" + "="*50)
    print("查看知识库状态")
    print("="*50)
    agent.show_memory()

    print("\n" + "="*50)
    print("示例 3：多 Agent 代码审查")
    print("="*50)
    sample_code = """
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    result = db.execute(query)
    return result[0]
"""
    reviews = multi_agent_code_review(sample_code)
    print("综合审查结果：")
    print(reviews["synthesis"])
