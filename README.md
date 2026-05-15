# VulFR - 漏洞靶场管理平台

VulFR 是一个基于 Spring Boot 的漏洞靶场管理平台，用于管理和运行各种安全漏洞演示环境。

## 功能特性

- 🎯 **靶场环境管理**：支持添加、编辑、删除和复制靶场环境
- 📦 **自动打包**：支持 Maven 项目自动打包，跨平台支持（Windows/Linux/Mac）
- 🚀 **一键启动/停止**：通过 docker-compose 快速启动和停止靶场环境
- ✅ **自动验证**：启动后自动验证环境是否可访问
- ⏱️ **超时处理**：60秒验证超时自动关闭环境，3分钟打包超时自动停止
- 🔍 **环境搜索**：支持按名称和CVE编号搜索靶场环境
- 🎨 **统一提示**：所有操作提示使用统一的颜色和格式

## 技术栈

- **后端框架**: Spring Boot 2.6.13
- **数据库**: MySQL 8.0+
- **容器编排**: Docker Compose
- **前端**: HTML5 + JavaScript + Bootstrap 5

## 快速开始

### 环境要求

- JDK 1.8+
- Maven 3.6+
- Docker & Docker Compose
- MySQL 8.0+

### 数据库配置

创建数据库并配置连接信息：

```sql
CREATE DATABASE vulfr_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 运行项目

```bash
# 克隆项目
git clone https://github.com/mlf519/VulFR.git
cd VulFR

# 编译项目
mvn clean compile

# 运行项目
mvn spring-boot:run
```

项目启动后访问：http://localhost:8082

## API 接口

| 接口 | 方法 | 描述 |
|------|------|------|
| `/api/environments` | GET | 获取所有靶场环境 |
| `/api/environments/{id}` | GET | 获取单个靶场环境 |
| `/api/environments` | POST | 创建新靶场环境 |
| `/api/environments/{id}` | PUT | 更新靶场环境 |
| `/api/environments/{id}` | DELETE | 删除靶场环境 |
| `/api/environments/{id}/start` | POST | 启动靶场环境 |
| `/api/environments/{id}/stop` | POST | 停止靶场环境 |
| `/api/environments/{id}/verify` | GET | 验证环境是否可访问 |
| `/api/environments/{id}/mark-running` | POST | 标记环境为运行状态 |
| `/api/environments/{id}/package` | POST | 启动打包任务 |
| `/api/environments/{id}/package/status` | GET | 查询打包状态 |
| `/api/environments/{id}/package/check` | GET | 检查是否已打包 |

## 项目结构

```
VulFR/
├── src/main/java/org/mcc/vulfr/
│   ├── VulFrApplication.java    # 启动类
│   ├── controller/              # REST API 控制器
│   ├── service/                 # 业务逻辑层
│   ├── repository/              # 数据访问层
│   ├── entity/                  # 实体类
│   └── config/                  # 配置类
├── src/main/resources/
│   ├── static/                  # 静态资源
│   ├── application.yml          # 应用配置
│   └── schema.sql               # 数据库初始化
├── vulnerable-apps/             # 漏洞环境目录
│   └── log4j/CVE-2021-44228/    # Log4j 漏洞环境
└── pom.xml                      # Maven 配置
```

## 漏洞环境

### CVE-2021-44228 (Log4j RCE)

包含一个存在 Log4j 远程代码执行漏洞的博客应用，用于演示和学习 Log4j 漏洞的利用与防护。

**启动方式**：
1. 在管理平台中找到 "Log4j CVE-2021-44228" 环境
2. 点击 "启动" 按钮
3. 等待验证完成后即可访问

## 使用说明

1. **添加靶场环境**：点击"添加环境"按钮，填写环境名称、CVE编号、描述、路径和访问链接
2. **打包环境**：点击"打包"按钮，系统会自动查找项目目录中的 `pom.xml` 并执行 Maven 打包
   - 支持跨平台打包（Windows/Linux/Mac）
   - 自动识别项目文件夹
   - 打包超时时间：3分钟
   - 每5秒轮询一次打包状态
3. **启动环境**：点击环境对应的"启动"按钮
   - 启动前自动检查是否已打包
   - 未打包会提示先进行打包操作
   - 系统会自动执行 docker-compose 启动并验证
   - 验证超时时间：60秒
4. **访问环境**：环境启动成功后，点击访问链接即可进入靶场
5. **停止环境**：点击"停止"按钮，系统会自动关闭环境

### 打包功能说明

**自动项目识别**：
- 系统会自动在配置的路径下查找 `pom.xml` 文件
- 如果当前目录没有，会自动查找子目录
- 找到项目后在该目录下执行 Maven 打包命令

**打包流程**：
1. 点击"打包"按钮
2. 系统检查是否已打包（检查 `target` 目录下是否有 jar 包）
3. 已打包则直接提示"项目已打包，可直接启动"
4. 未打包则执行 `mvn clean package -DskipTests -q`
5. 前端每5秒轮询一次打包状态
6. 打包成功后检查是否生成 jar 包
7. 超过3分钟未完成则自动停止

**跨平台支持**：
- Windows: 使用 `mvn.cmd` 命令
- Linux/Mac: 使用 `mvn` 命令
- 自动配置 Maven 环境变量

## 安全警告

⚠️ **警告**：本项目包含多个已知漏洞的演示环境，仅供安全研究和学习使用。请不要在生产环境中部署这些漏洞环境，确保在隔离的网络环境中运行。

## License

Apache License 2.0
