FROM openjdk:8-jdk-alpine

LABEL maintainer="VulFR Platform"
LABEL description="My Blog Application for SpringActuator Vulnerability Demonstration"

# 设置工作目录
WORKDIR /app

# 复制jar包
COPY My-Blog-master/target/my-blog-4.0.0-SNAPSHOT.jar app.jar

# 暴露应用端口
EXPOSE 28083

# 启动应用
ENTRYPOINT ["java", "-jar", "app.jar"]
