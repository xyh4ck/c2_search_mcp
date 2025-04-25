# 基于FastMCP的威胁情报查询服务 - 任务清单

## 项目初始化
- [x] 创建项目基本结构
- [x] 配置开发环境(Python 3.12, uv)
- [x] 创建README.md文件
- [x] 创建requirements.txt/pyproject.toml
- [x] 配置GitHub Actions工作流

## 核心功能模块开发

### 1. 查询处理模块
- [x] 实现MCP请求的解析处理
- [x] 设计查询参数验证机制
  - [x] IP地址验证(IPv4/IPv6)
  - [x] URL格式验证
  - [x] 文件哈希格式验证(MD5/SHA1/SHA256)
- [x] 实现请求路由与分发

### 2. 威胁情报集成模块
- [x] 基础API封装类
  - [x] 实现API鉴权机制
  - [x] 请求错误处理与重试逻辑
  - [x] 响应数据预处理

- [x] VirusTotal API集成
  - [x] IP查询功能
  - [x] URL查询功能
  - [x] 文件哈希查询功能

- [x] AbuseIPDB API集成
  - [x] IP查询功能

- [x] Hybrid Analysis API集成
  - [x] 文件哈希查询功能

- [x] URLScan.io API集成
  - [x] URL查询功能

- [x] ThreatFox API集成
  - [x] 文件哈希查询功能

- [x] IPinfo API集成
  - [x] IP地址查询功能

- [x] Shodan API集成(可选)
  - [x] IP查询功能

### 3. 结果聚合与返回模块
- [x] 设计统一的响应数据结构
- [x] 实现多API结果聚合逻辑
  - [x] 威胁等级评分计算
  - [x] 标签聚合与分类
  - [x] 地理位置信息整合
  - [x] 活动历史记录合并
- [x] 实现MCP响应格式化与返回

### 4. 日志与审计模块
- [x] 设计日志记录格式
- [x] 实现查询日志记录
- [x] 实现API调用日志记录
- [x] 日志存储与检索机制


## 文档编写
- [ ] API接口文档
- [ ] 部署与配置指南
- [ ] 使用示例文档
