# Claude Code 知识库

> AI Agent 开发的系统性知识整理——从入门到自建进化型智能体

---

## 📚 内容导航

### docs/ — 核心知识文档

| 文件 | 内容 | 适合谁看 |
|------|------|---------|
| [01-MCP-完全指南.md](docs/01-MCP-完全指南.md) | MCP 协议原理、最佳 Server、自定义开发 | 所有人必读 |
| [02-多Agent与长上下文最佳实践.md](docs/02-多Agent与长上下文最佳实践.md) | Orchestrator/Worker 模式、上下文压缩、多Agent协作 | 有基础的开发者 |
| [03-自进化Agent架构设计.md](docs/03-自进化Agent架构设计.md) | Knowledge-Skills解耦、反思引擎、进化机制 | 想构建高级 Agent |
| [04-小模型高效Agent提示词工程.md](docs/04-小模型高效Agent提示词工程.md) | 模型选择策略、CoT/Few-shot/结构化输出、成本优化 | 所有开发者 |
| [05-软件工程原则与Agent设计.md](docs/05-软件工程原则与Agent设计.md) | SOLID原则、设计模式、分层架构、Agent测试 | 有工程背景的开发者 |
| [06-2025-2026最新进展与知识盲区.md](docs/06-2025-2026最新进展与知识盲区.md) | 框架对比、Claude新能力、Manus分析、工具推荐 | 想了解最新动态 |

### guides/ — 快速上手指南

| 文件 | 内容 |
|------|------|
| [quickstart-mcp-setup.md](guides/quickstart-mcp-setup.md) | 15分钟配置 MCP，复制即用 |

### agents/ — 可运行的 Agent 代码

| 文件 | 内容 |
|------|------|
| [evolving_agent_starter.py](agents/evolving_agent_starter.py) | 完整的自进化 Agent 实现，含多 Agent 代码审查示例 |

### mcp/ — MCP Server 模板

| 文件 | 内容 |
|------|------|
| [custom-mcp-server-template.py](mcp/custom-mcp-server-template.py) | 自定义 MCP Server，含笔记/代码片段/任务管理工具 |

### tools/ — 工具和模板

| 文件 | 内容 |
|------|------|
| [CLAUDE.md模板.md](tools/CLAUDE.md模板.md) | 项目级 CLAUDE.md 配置模板，让 Claude Code 立刻了解你的项目 |

---

## 🚀 30 分钟快速开始路径

### 第一步：配置 MCP（5分钟）
```bash
# 编辑 Claude Desktop 配置文件
# macOS: ~/Library/Application Support/Claude/claude_desktop_config.json

# 最小配置（复制粘贴即用）：
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/你的项目目录"]
    },
    "memory": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-memory"]
    }
  }
}
```

### 第二步：配置项目 CLAUDE.md（5分钟）
```bash
# 复制模板到你的项目
cp tools/CLAUDE.md模板.md /你的项目/CLAUDE.md
# 填写项目信息
```

### 第三步：运行自进化 Agent（5分钟）
```bash
pip install anthropic
export ANTHROPIC_API_KEY=your_key
python agents/evolving_agent_starter.py
```

### 第四步：部署自定义 MCP Server（15分钟）
```bash
pip install mcp
# 修改 mcp/custom-mcp-server-template.py 添加你的工具
python mcp/custom-mcp-server-template.py
# 注册到 Claude Desktop 配置
```

---

## 🧠 核心理念速览

### 1. Knowledge vs Skills 解耦
```
传统 Agent：知识和能力混在一起，难以维护
                      ↓
解耦后：
  Knowledge Base（知识库）— 存储事实、教训、偏好
  Skills Library（技能库）— 存储提示词模板、工作流
  Reflection Engine（反思引擎）— 执行后自动更新两者
```

### 2. 模型选择原则
```
Haiku  → 分类/提取/路由/高频简单任务（成本最优）
Sonnet → 日常编程/分析/多步骤任务（性价比最高）
Opus   → 复杂架构/深度分析/关键决策（效果最好）
```

### 3. 自进化循环
```
执行任务 → 反思结果 → 更新知识库 → 下次更好
```

---

## 📖 推荐阅读顺序

**完全新手：**
01-MCP指南 → guides/quickstart → 04-提示词工程

**有基础的开发者：**
02-多Agent最佳实践 → 03-自进化架构 → agents/starter代码

**想深入架构的：**
05-软件工程原则 → 03-自进化架构 → 自己扩展代码

**想了解最新动态：**
06-2025-2026最新进展（直接跳这篇）

---

## 原始项目

原 Go/K8s/Helm 工具项目保存在 `master` 分支。

---

*由 Claude Code 整理 | 持续更新 | 2026-03*
