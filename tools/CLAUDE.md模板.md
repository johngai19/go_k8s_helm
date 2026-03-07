# CLAUDE.md 项目配置模板

> 复制此文件到你的项目根目录，重命名为 `CLAUDE.md`，填写项目信息
> Claude Code 每次启动会自动读取这个文件，让 Claude 立刻了解你的项目

---

# [项目名称]

## 项目概述
[一句话描述这个项目是什么]

## 技术栈
- **语言：** Python 3.11 / TypeScript 5.x / Go 1.22
- **主框架：** FastAPI / Next.js / Gin
- **数据库：** PostgreSQL 15 + Redis
- **测试：** pytest / Jest / go test
- **部署：** Docker + Kubernetes

## 目录结构
```
src/
├── api/          # API 路由和控制器
├── services/     # 业务逻辑层
├── models/       # 数据模型/数据库 Schema
├── utils/        # 工具函数
└── config/       # 配置文件

tests/
├── unit/         # 单元测试
├── integration/  # 集成测试
└── fixtures/     # 测试数据

docs/             # 文档
scripts/          # 运维脚本
```

## 常用命令
```bash
# 开发
make dev              # 启动开发环境
make test             # 运行所有测试
make test-unit        # 只运行单元测试
make lint             # 代码检查
make format           # 代码格式化

# 数据库
make db-migrate       # 运行数据库迁移
make db-rollback      # 回滚最近一次迁移
make db-seed          # 插入测试数据

# 部署
make build            # 构建 Docker 镜像
make deploy-staging   # 部署到测试环境
make deploy-prod      # 部署到生产（谨慎！）
```

## 编码规范

### 必须遵守
- 所有函数必须有类型注解
- 所有公共 API 必须有文档字符串
- 错误处理用自定义异常类（见 `src/exceptions.py`）
- 数据库操作必须使用 ORM，**禁止** SQL 字符串拼接
- 所有外部 HTTP 调用必须设置超时（默认 30 秒）

### 推荐做法
- 优先 async/await，避免阻塞 IO
- 复杂逻辑写注释说明"为什么"，不是"做了什么"
- 函数长度超过 50 行时考虑拆分

## 重要约束（必读）

⚠️ **以下目录/文件不得修改，只读：**
- `src/core/` — 核心框架代码
- `src/migrations/` — 数据库迁移历史，只能添加不能修改
- `.env.example` — 环境变量模板，敏感配置在 `.env`（不提交）

⚠️ **以下操作需要人工确认：**
- 修改数据库 Schema
- 修改认证/授权逻辑
- 修改支付相关代码
- 任何生产环境操作

## 当前工作状态

### 正在进行
- [ ] 实现用户认证模块（JWT + Refresh Token）
- [ ] 集成第三方支付（微信/支付宝）

### 已知问题
- `GET /api/users` 在并发超过 100 时偶发 500 — 疑似连接池不足
- 登录接口响应时间 >500ms — 待优化
- 测试覆盖率 67% — 目标 80%

### 近期完成
- ✅ 用户注册/登录基础功能
- ✅ 商品管理 CRUD
- ✅ Docker 化部署

## 相关文档
- API 文档：http://localhost:8000/docs（开发环境）
- 数据库 ERD：`docs/database-erd.png`
- 架构设计：`docs/architecture.md`
- 部署手册：`docs/deployment.md`

## 团队约定
- PR 必须经过至少 1 人 Review
- commit message 格式：`feat:` / `fix:` / `refactor:` / `docs:`
- 发现 Bug 先开 Issue，再修复
- 每周四下午代码 Review 会议

---

## Claude Code 专用提示

当我请求 Claude Code 帮助时，请默认：
1. 遵守上述编码规范，不要问我要不要遵守
2. 新代码优先放到对应的目录层（如业务逻辑放 services/）
3. 修改代码前先读相关文件，不要假设代码内容
4. 运行测试验证修改（`make test`）
5. 大的修改拆成小步骤，每步确认后再继续

我的技术偏好：
- 代码风格：简洁优于冗余
- 注释：只在复杂逻辑处写，不需要逐行注释
- 错误处理：明确的错误信息，对用户友好
- 性能：够用即可，不要过早优化
