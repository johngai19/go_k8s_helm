# MCP (Model Context Protocol) 完全指南

> Claude 的"插件系统"——让 AI 真正连接外部世界

---

## 一、什么是 MCP？

MCP（Model Context Protocol）是 Anthropic 在 2024 年底开源的标准协议，本质是**给 AI 模型接入外部工具和数据的统一接口标准**。

```
你的问题
   ↓
Claude (大脑)
   ↓ 调用
MCP Server (工具/数据源)
   ↓ 返回结果
Claude 整合后回答
```

**类比理解：**
- 以前：Claude 是一个博学但"闭关"的人，只能靠自身知识回答
- 有了 MCP：Claude 变成了一个"总指挥"，可以随时调用各种专家工具

---

## 二、MCP 架构

```
┌─────────────────────────────────────┐
│          Claude (Host/Client)        │
│  - 理解意图                          │
│  - 决定调用哪个工具                   │
│  - 整合结果                          │
└──────────────┬──────────────────────┘
               │ MCP Protocol (JSON-RPC)
    ┌──────────┼──────────┐
    ↓          ↓          ↓
┌───────┐ ┌───────┐ ┌───────┐
│文件系统│ │数据库 │ │浏览器 │  ...更多 Server
└───────┘ └───────┘ └───────┘
```

每个 MCP Server 对外暴露三类能力：
- **Tools** — 可执行的函数（如"搜索文件"、"运行SQL"）
- **Resources** — 数据资源（如"读取文件内容"）
- **Prompts** — 预置提示词模板

---

## 三、最重要的 MCP Servers（可直接使用）

### 🔴 必装级别

#### 1. Filesystem（文件系统）
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/your/project/path"]
    }
  }
}
```
**能力：** 读写文件、列目录、搜索文件内容
**场景：** 让 Claude 直接操作你的代码库

#### 2. Memory（持久记忆）
```json
{
  "mcpServers": {
    "memory": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-memory"]
    }
  }
}
```
**能力：** Knowledge Graph 形式存储实体和关系，跨对话持久化
**场景：** 让 Claude 记住你的偏好、项目上下文、关键决策
**这是实现"自进化 Agent"的关键工具之一！**

#### 3. Brave Search（网络搜索）
```json
{
  "mcpServers": {
    "brave-search": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-brave-search"],
      "env": { "BRAVE_API_KEY": "your-key" }
    }
  }
}
```
**能力：** 实时网络搜索，获取最新信息
**场景：** 突破训练数据截止日期限制

#### 4. GitHub
```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "your-token" }
    }
  }
}
```
**能力：** 读写仓库、创建 PR/Issue、搜索代码
**场景：** 完整的代码协作工作流

#### 5. PostgreSQL / SQLite
```json
{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://user:pass@localhost/db"]
    }
  }
}
```
**能力：** 直接查询数据库，生成报表
**场景：** 数据分析、业务查询

---

### 🟡 强烈推荐

#### 6. Puppeteer（浏览器自动化）
**能力：** 控制真实浏览器，截图、填表、抓取动态页面
```bash
npx @modelcontextprotocol/server-puppeteer
```

#### 7. Slack
**能力：** 读取/发送 Slack 消息，搜索历史
**场景：** 让 Claude 帮你处理工作沟通

#### 8. Google Drive / Google Maps
**能力：** 访问 Drive 文件、地图信息
**场景：** 文档管理、位置相关任务

#### 9. Sentry
**能力：** 查看错误报告，分析 Bug
**场景：** 让 Claude 自动分析生产环境问题

#### 10. Sequential Thinking（思维链工具）
```json
{
  "mcpServers": {
    "sequential-thinking": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"]
    }
  }
}
```
**能力：** 结构化思考过程，可修订和分支
**场景：** 复杂问题分析、多步骤规划——**让小模型也能思考复杂问题**

---

### 🟢 场景专用

| Server | 用途 |
|--------|------|
| `server-aws-kb-retrieval` | AWS 知识库 RAG |
| `server-everart` | AI 图像生成 |
| `server-fetch` | HTTP 请求，抓取网页 |
| `server-redis` | Redis 缓存操作 |
| `server-kubernetes` | K8s 集群管理 |
| `server-docker` | Docker 容器管理 |
| `server-jira` | Jira 工单管理 |
| `server-notion` | Notion 文档操作 |

---

## 四、MCP 配置文件（Claude Desktop / Claude Code）

配置文件路径：
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux:** `~/.config/claude/claude_desktop_config.json`
- **Claude Code:** `.claude/settings.json` 中的 `mcpServers` 字段

### 一个完整的生产级配置示例：

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem",
               "/Users/you/projects", "/Users/you/documents"]
    },
    "memory": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-memory"]
    },
    "brave-search": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-brave-search"],
      "env": { "BRAVE_API_KEY": "BSA..." }
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..." }
    },
    "sequential-thinking": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"]
    },
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres",
               "postgresql://localhost/mydb"]
    }
  }
}
```

---

## 五、自己写 MCP Server（Python 示例）

```python
# my_mcp_server.py
from mcp.server.fastmcp import FastMCP
import json

mcp = FastMCP("我的自定义工具")

@mcp.tool()
def search_knowledge_base(query: str, top_k: int = 5) -> str:
    """在知识库中搜索相关内容"""
    # 实际实现：向量搜索、BM25 等
    results = vector_search(query, top_k)
    return json.dumps(results, ensure_ascii=False)

@mcp.tool()
def update_agent_memory(key: str, value: str, category: str = "general") -> str:
    """更新 Agent 的长期记忆"""
    # 实际实现：写入数据库/文件
    save_memory(key, value, category)
    return f"已记录: {key}"

@mcp.resource("knowledge://topics")
def list_topics() -> str:
    """列出知识库中的所有主题"""
    return json.dumps(get_all_topics())

if __name__ == "__main__":
    mcp.run()
```

注册到配置：
```json
{
  "mcpServers": {
    "my-tools": {
      "command": "python",
      "args": ["/path/to/my_mcp_server.py"]
    }
  }
}
```

---

## 六、MCP 的局限和注意事项

1. **安全边界**：每个 Server 能访问的资源要最小化授权
2. **性能**：每次工具调用都有延迟，避免不必要的调用
3. **上下文消耗**：工具返回的内容会占用 context window，注意压缩
4. **幂等性**：写操作类工具要设计幂等，避免重复执行

---

## 七、MCP vs 其他平台工具对比

| 特性 | Claude MCP | ChatGPT Plugins | OpenAI Assistants |
|------|-----------|-----------------|-------------------|
| 协议标准 | 开放标准 | 私有 | 私有 |
| 本地运行 | ✅ 支持 | ❌ 不支持 | ❌ 不支持 |
| 自定义工具 | ✅ 极易 | 需要部署 API | 需要部署 API |
| 数据隐私 | ✅ 本地处理 | ⚠️ 上传到 OpenAI | ⚠️ 上传到 OpenAI |
| 工具发现 | 动态 | 静态注册 | 静态注册 |

---

*更新时间：2026-03 | 参考：[MCP 官方文档](https://modelcontextprotocol.io)*
