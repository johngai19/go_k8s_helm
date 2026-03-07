# MCP 快速配置指南（15 分钟上手）

## 前置条件
- Node.js >= 18
- Claude Desktop 或 Claude Code

## 步骤 1：安装 Node.js（如果没有）
```bash
# macOS
brew install node

# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# 验证
node --version  # 应显示 v18+
```

## 步骤 2：配置文件位置
```bash
# macOS Claude Desktop
~/Library/Application Support/Claude/claude_desktop_config.json

# Linux Claude Desktop
~/.config/claude/claude_desktop_config.json

# Claude Code（项目级）
.claude/settings.json

# Claude Code（全局）
~/.claude/settings.json
```

## 步骤 3：基础配置（复制即用）

创建或编辑配置文件：

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/替换成你的项目目录",
        "/替换成你的文档目录"
      ]
    },
    "memory": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-memory"]
    },
    "sequential-thinking": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"]
    }
  }
}
```

## 步骤 4：添加网络搜索（需要 API Key）

1. 访问 https://brave.com/search/api/ 获取免费 API Key
2. 更新配置：

```json
{
  "mcpServers": {
    "brave-search": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-brave-search"],
      "env": {
        "BRAVE_API_KEY": "你的APIKey"
      }
    }
  }
}
```

## 步骤 5：添加 GitHub 集成

1. 访问 GitHub → Settings → Developer settings → Personal access tokens
2. 创建 token，勾选 repo 权限
3. 更新配置：

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_你的token"
      }
    }
  }
}
```

## 步骤 6：重启 Claude Desktop

重启后在对话中询问："你现在有哪些工具？" 验证配置是否生效。

## 验证成功的标志

Claude 应该能够：
- "帮我列出 /Users/你/projects 目录下的文件" → 使用 filesystem
- "记住：我喜欢简洁的代码风格" → 使用 memory
- "搜索一下最新的 Python 3.13 新特性" → 使用 brave-search

## 完整的生产级配置（9 个 Server）

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem",
               "/Users/yourname/projects", "/Users/yourname/documents"]
    },
    "memory": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-memory"]
    },
    "brave-search": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-brave-search"],
      "env": {"BRAVE_API_KEY": "BSA_KEY_HERE"}
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_TOKEN_HERE"}
    },
    "sequential-thinking": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"]
    },
    "puppeteer": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-puppeteer"]
    },
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres",
               "postgresql://localhost/mydb"]
    },
    "fetch": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-fetch"]
    },
    "slack": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-slack"],
      "env": {
        "SLACK_BOT_TOKEN": "xoxb-TOKEN",
        "SLACK_TEAM_ID": "T_TEAM_ID"
      }
    }
  }
}
```

## 常见问题

**Q: npx 命令找不到？**
```bash
npm install -g npx
# 或确保 Node.js 正确安装
```

**Q: Server 启动失败？**
```bash
# 手动测试
npx -y @modelcontextprotocol/server-filesystem /tmp
# 如果报错，看错误信息
```

**Q: 权限被拒绝？**
- 确保配置中的目录路径有读取权限
- Windows 用户用正斜杠或转义反斜杠

**Q: Claude 看不到工具？**
- 重启 Claude Desktop（不只是关闭对话）
- 检查 JSON 格式是否合法（用 jsonlint.com 验证）
