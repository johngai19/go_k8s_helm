"""
自定义 MCP Server 模板
快速构建自己的 Claude 工具集

安装依赖：
pip install mcp

运行（开发测试）：
python custom-mcp-server-template.py

注册到 Claude Desktop（claude_desktop_config.json）：
{
  "mcpServers": {
    "my-tools": {
      "command": "python",
      "args": ["/path/to/custom-mcp-server-template.py"]
    }
  }
}
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# 初始化 MCP Server
mcp = FastMCP("我的自定义工具集")

# ============================================================
# 示例工具 1：项目笔记管理
# ============================================================
NOTES_DB = Path("./notes.db")

def init_db():
    conn = sqlite3.connect(NOTES_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            tags TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@mcp.tool()
def add_note(title: str, content: str, tags: str = "") -> str:
    """
    添加一条笔记到项目知识库

    Args:
        title: 笔记标题
        content: 笔记内容
        tags: 逗号分隔的标签，如 "python,api,重要"
    """
    now = datetime.now().isoformat()
    conn = sqlite3.connect(NOTES_DB)
    conn.execute(
        "INSERT INTO notes (title, content, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (title, content, tags, now, now)
    )
    conn.commit()
    conn.close()
    return f"✅ 笔记已保存：{title}"


@mcp.tool()
def search_notes(query: str, tag: str = "") -> str:
    """
    搜索笔记

    Args:
        query: 搜索关键词（搜索标题和内容）
        tag: 可选，按标签过滤
    """
    conn = sqlite3.connect(NOTES_DB)
    conn.row_factory = sqlite3.Row

    if tag:
        cursor = conn.execute(
            "SELECT * FROM notes WHERE (title LIKE ? OR content LIKE ?) AND tags LIKE ? ORDER BY updated_at DESC LIMIT 10",
            (f"%{query}%", f"%{query}%", f"%{tag}%")
        )
    else:
        cursor = conn.execute(
            "SELECT * FROM notes WHERE title LIKE ? OR content LIKE ? ORDER BY updated_at DESC LIMIT 10",
            (f"%{query}%", f"%{query}%")
        )

    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return f"没有找到包含 '{query}' 的笔记"

    results = []
    for row in rows:
        results.append(f"## {row['title']}\n标签: {row['tags']}\n{row['content'][:200]}...")

    return f"找到 {len(rows)} 条笔记：\n\n" + "\n\n---\n\n".join(results)


@mcp.tool()
def list_notes(limit: int = 10) -> str:
    """
    列出最近的笔记

    Args:
        limit: 返回数量，默认 10
    """
    conn = sqlite3.connect(NOTES_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT id, title, tags, updated_at FROM notes ORDER BY updated_at DESC LIMIT ?",
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return "知识库中还没有笔记"

    items = [f"- [{row['id']}] **{row['title']}** ({row['tags']}) — {row['updated_at'][:10]}"
             for row in rows]
    return f"最近 {len(rows)} 条笔记：\n" + "\n".join(items)


# ============================================================
# 示例工具 2：代码片段管理
# ============================================================
SNIPPETS_FILE = Path("./snippets.json")

def load_snippets() -> dict:
    if SNIPPETS_FILE.exists():
        with open(SNIPPETS_FILE) as f:
            return json.load(f)
    return {}

def save_snippets(snippets: dict):
    with open(SNIPPETS_FILE, "w", encoding="utf-8") as f:
        json.dump(snippets, f, ensure_ascii=False, indent=2)


@mcp.tool()
def save_snippet(name: str, code: str, language: str, description: str = "") -> str:
    """
    保存一个常用代码片段

    Args:
        name: 片段名称（唯一标识，如 'python-retry-decorator'）
        code: 代码内容
        language: 编程语言（python/javascript/go等）
        description: 说明这个代码片段的用途
    """
    snippets = load_snippets()
    snippets[name] = {
        "code": code,
        "language": language,
        "description": description,
        "saved_at": datetime.now().isoformat()
    }
    save_snippets(snippets)
    return f"✅ 代码片段 '{name}' 已保存"


@mcp.tool()
def get_snippet(name: str) -> str:
    """
    获取已保存的代码片段

    Args:
        name: 片段名称
    """
    snippets = load_snippets()
    if name not in snippets:
        available = list(snippets.keys())
        return f"未找到 '{name}'，可用片段：{available}"

    s = snippets[name]
    return f"# {name}\n{s['description']}\n\n```{s['language']}\n{s['code']}\n```"


@mcp.tool()
def list_snippets(language: str = "") -> str:
    """
    列出所有代码片段

    Args:
        language: 可选，按语言过滤
    """
    snippets = load_snippets()
    if not snippets:
        return "还没有保存任何代码片段"

    items = []
    for name, s in snippets.items():
        if language and s["language"] != language:
            continue
        items.append(f"- **{name}** ({s['language']}): {s['description'][:60]}")

    return "\n".join(items) if items else f"没有 {language} 语言的片段"


# ============================================================
# 示例工具 3：任务追踪
# ============================================================
TASKS_FILE = Path("./tasks.json")

def load_tasks() -> list:
    if TASKS_FILE.exists():
        with open(TASKS_FILE) as f:
            return json.load(f)
    return []

def save_tasks(tasks: list):
    with open(TASKS_FILE, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)


@mcp.tool()
def add_task(title: str, priority: str = "medium", due_date: str = "") -> str:
    """
    添加一个任务

    Args:
        title: 任务标题
        priority: 优先级（high/medium/low）
        due_date: 截止日期（YYYY-MM-DD格式，可选）
    """
    tasks = load_tasks()
    task = {
        "id": len(tasks) + 1,
        "title": title,
        "priority": priority,
        "due_date": due_date,
        "status": "todo",
        "created_at": datetime.now().isoformat()
    }
    tasks.append(task)
    save_tasks(tasks)
    return f"✅ 任务已添加：[{task['id']}] {title}"


@mcp.tool()
def complete_task(task_id: int) -> str:
    """
    标记任务为完成

    Args:
        task_id: 任务 ID
    """
    tasks = load_tasks()
    for task in tasks:
        if task["id"] == task_id:
            task["status"] = "done"
            task["completed_at"] = datetime.now().isoformat()
            save_tasks(tasks)
            return f"✅ 任务 [{task_id}] '{task['title']}' 已完成！"
    return f"未找到任务 ID: {task_id}"


@mcp.tool()
def list_tasks(status: str = "todo") -> str:
    """
    列出任务

    Args:
        status: 过滤状态（todo/done/all）
    """
    tasks = load_tasks()

    if status != "all":
        tasks = [t for t in tasks if t["status"] == status]

    if not tasks:
        return f"没有 '{status}' 状态的任务"

    # 按优先级排序
    priority_order = {"high": 0, "medium": 1, "low": 2}
    tasks.sort(key=lambda t: priority_order.get(t["priority"], 1))

    priority_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}
    items = [
        f"{priority_emoji.get(t['priority'], '⚪')} [{t['id']}] {t['title']}"
        f"{' (截止: ' + t['due_date'] + ')' if t['due_date'] else ''}"
        for t in tasks
    ]
    return f"任务列表（{status}）：\n" + "\n".join(items)


# ============================================================
# 资源（Resource）示例：提供静态/动态数据
# ============================================================
@mcp.resource("knowledge://quick-reference")
def get_quick_reference() -> str:
    """提供项目快速参考手册"""
    return """
# 项目快速参考

## 常用命令
- 启动：`make dev`
- 测试：`make test`
- 部署：`make deploy`

## 重要端口
- API: 8000
- 数据库: 5432
- Redis: 6379

## 联系人
- 后端负责人：张三 (zhangsan@example.com)
- 前端负责人：李四 (lisi@example.com)
"""


@mcp.resource("knowledge://tech-decisions")
def get_tech_decisions() -> str:
    """返回技术决策记录"""
    decisions_file = Path("./tech-decisions.md")
    if decisions_file.exists():
        return decisions_file.read_text(encoding="utf-8")
    return "技术决策文档还未创建，使用 add_note 工具添加决策记录"


# ============================================================
# 启动
# ============================================================
if __name__ == "__main__":
    print("自定义 MCP Server 启动...")
    print("可用工具：add_note, search_notes, list_notes")
    print("         save_snippet, get_snippet, list_snippets")
    print("         add_task, complete_task, list_tasks")
    mcp.run()
