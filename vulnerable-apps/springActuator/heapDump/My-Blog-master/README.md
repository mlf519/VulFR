# My Blog - Spring Actuator 漏洞演示环境

> **⚠️ 安全警告**：本项目包含 Spring Actuator 不当配置导致的 heapdump 信息泄露漏洞，仅供安全研究和学习使用。请勿在生产环境中部署。

## 项目简介

这是一个存在 **Spring Actuator 不当配置漏洞** 的博客应用，用于演示和学习 Spring Actuator 配置不当可能导致的敏感信息泄露风险。

Spring Actuator 是 Spring Boot 提供的监控和管理生产环境的工具，可以帮助开发者监控应用的健康状态、查看配置信息、获取线程转储等。然而，如果配置不当，攻击者可以通过访问 Actuator 暴露的端点获取敏感信息，甚至导致远程代码执行。

## 漏洞信息

| 属性   | 值                              |
| ---- | ------------------------------ |
| 漏洞类型 | 敏感信息泄露 (Heap Dump)             |
| 严重程度 | 高                              |
| 影响组件 | Spring Boot Actuator           |
| 漏洞描述 | 不当配置导致 /actuator/heapdump 端点暴露 |

## 漏洞背景

### Heap Dump 泄露风险

Heap Dump 是 Java 虚拟机在某个时间点的内存快照，包含了：

- 所有对象的实例数据
- 类信息和方法信息
- 对象引用关系
- 可能包含密码、密钥、会话令牌等敏感信息

当 `/actuator/heapdump` 端点被未授权访问时，攻击者可以：

1. 下载完整的堆转储文件
2. 使用工具分析堆转储，提取敏感信息
3. 获取数据库密码、API密钥、用户凭证等

### 漏洞配置分析

本项目的 `application.properties` 中存在以下危险配置：

```properties
# 危险配置：暴露所有 Actuator 端点
management.endpoints.web.exposure.include=*
management.security.enabled=false
```

这导致以下敏感端点可被未授权访问：

- `/actuator/heapdump` - 获取堆内存快照
- `/actuator/env` - 查看所有环境变量和配置信息
- `/actuator/beans` - 查看所有 Spring Bean 信息
- `/actuator/mappings` - 查看所有 URL 映射
- `/actuator/threaddump` - 获取线程转储
- `/actuator/configprops` - 查看所有配置属性

## 技术栈

- Spring Boot 2.7.5
- MyBatis
- Thymeleaf
- MySQL

## 快速开始

### 方式一：通过 VulFR 平台启动（推荐）

1. 启动 VulFR 漏洞靶场管理平台
2. 在平台中找到 "Spring Actuator Heap Dump" 环境
3. 点击 "启动" 按钮
4. 等待验证完成后即可访问

### 方式二：手动启动

```bash
# 进入项目目录
cd vulnerable-apps/springActuator/heapDump/My-Blog-master

# 使用 Maven 编译打包
mvn clean package -DskipTests

# 运行应用
java -jar target/my-blog-4.0.0-SNAPSHOT.jar
```

### 访问地址

- 博客首页：<http://localhost:28083>
- 后台管理：<http://localhost:28083/admin>
- Actuator 端点：<http://localhost:28083/actuator>

### 默认账号

- 用户名：admin
- 密码：123456

## 漏洞演示

### 漏洞功能点位置

漏洞存在于 Spring Actuator 的配置中，以下端点可被未授权访问：

| 端点                     | 功能描述         | 风险等级 |
| ---------------------- | ------------ | ---- |
| `/actuator/heapdump`   | 下载堆内存快照      | 高危   |
| `/actuator/env`        | 查看环境变量和配置    | 高危   |
| `/actuator/beans`      | 查看所有 Bean 定义 | 中危   |
| `/actuator/mappings`   | 查看所有 URL 映射  | 中危   |
| `/actuator/threaddump` | 获取线程转储       | 中危   |

### 利用方式

**获取 heapdump 文件：**

**提取敏感信息示例：**
```bash
# 下载 heapdump 文件
curl -o heapdump.hprof http://localhost:28083/actuator/heapdump

# 分析 heapdump 文件
java -jar heapdump_tool.jar heapdump
```

从 heapdump 中可以提取到：

- 数据库连接信息（用户名、密码）
- 应用配置参数
- 用户会话数据
- 内存中的敏感业务数据

## 防护建议

### 安全配置建议

1. **限制端点暴露范围**：只暴露必要的端点
   ```properties
   management.endpoints.web.exposure.include=health,info
   ```
2. **启用安全认证**：使用 Spring Security 保护 Actuator 端点
   ```properties
   management.security.enabled=true
   ```
3. **网络层限制**：通过防火墙限制 Actuator 端点只能从内网访问
4. **使用 Spring Security 配置示例**：
   ```java
   @Configuration
   public class ActuatorSecurityConfig extends WebSecurityConfigurerAdapter {
       @Override
       protected void configure(HttpSecurity http) throws Exception {
           http.requestMatcher(EndpointRequest.toAnyEndpoint())
               .authorizeRequests()
               .anyRequest().hasRole("ACTUATOR_ADMIN")
               .and()
               .httpBasic();
       }
   }
   ```
5. **生产环境建议**：
   - 禁止暴露 `/heapdump`、`/env`、`/beans` 等敏感端点
   - 使用 Spring Security 的 IP 白名单功能
   - 配置适当的访问日志和监控告警

## 安全提醒

⚠️ **重要**：

- 本环境仅供安全研究和教育目的使用
- 请勿用于非法攻击或未经授权的测试
- 建议在隔离的网络环境中运行
- 生产环境中务必遵循安全配置最佳实践

## License

Apache License 2.0
