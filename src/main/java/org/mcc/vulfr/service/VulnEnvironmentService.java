package org.mcc.vulfr.service;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.*;
import org.mcc.vulfr.entity.VulnEnvironment;
import org.mcc.vulfr.repository.VulnEnvironmentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
public class VulnEnvironmentService {

    private static final Logger logger = LoggerFactory.getLogger(VulnEnvironmentService.class);
    private static final int PORT_MIN = 10000;
    private static final int PORT_MAX = 12000;

    private final VulnEnvironmentRepository repository;
    private final DockerClient dockerClient;
    private final String projectRootPath;

    public VulnEnvironmentService(VulnEnvironmentRepository repository, DockerClient dockerClient) {
        this.repository = repository;
        this.dockerClient = dockerClient;
        this.projectRootPath = new File(".").getAbsolutePath();
    }

    private File resolvePath(String path) {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("路径不能为空");
        }
        
        path = path.trim();
        
        if (path.contains("..") || path.contains("~") || path.startsWith("/") || path.contains(":")) {
            throw new IllegalArgumentException("路径包含非法字符");
        }
        
        File file = new File(path);
        if (file.isAbsolute()) {
            try {
                File rootFile = new File(projectRootPath).getCanonicalFile();
                File targetFile = file.getCanonicalFile();
                if (!targetFile.toPath().startsWith(rootFile.toPath())) {
                    throw new IllegalArgumentException("路径超出项目根目录范围");
                }
                return targetFile;
            } catch (IOException e) {
                throw new IllegalArgumentException("路径解析失败", e);
            }
        }
        
        try {
            File resolvedFile = new File(projectRootPath, path).getCanonicalFile();
            File rootFile = new File(projectRootPath).getCanonicalFile();
            if (!resolvedFile.toPath().startsWith(rootFile.toPath())) {
                throw new IllegalArgumentException("路径超出项目根目录范围");
            }
            return resolvedFile;
        } catch (IOException e) {
            throw new IllegalArgumentException("路径解析失败", e);
        }
    }
    
    private void validateEnvironmentInput(VulnEnvironment environment) {
        if (environment.getName() == null || environment.getName().trim().isEmpty()) {
            throw new IllegalArgumentException("靶场名称不能为空");
        }
        
        String name = environment.getName().trim();
        if (name.length() > 100) {
            throw new IllegalArgumentException("靶场名称长度不能超过100个字符");
        }
        
        if (environment.getCveId() != null && !environment.getCveId().trim().isEmpty()) {
            String cveId = environment.getCveId().trim();
            if (!cveId.matches("^CVE-\\d{4}-\\d{4,}$")) {
                throw new IllegalArgumentException("CVE编号格式不正确，应为CVE-YYYY-NNNN");
            }
        }
        
        if (environment.getDescription() != null && environment.getDescription().length() > 500) {
            throw new IllegalArgumentException("描述长度不能超过500个字符");
        }
        
        if (environment.getPath() != null) {
            String path = environment.getPath().trim();
            if (path.length() > 500) {
                throw new IllegalArgumentException("路径长度不能超过500个字符");
            }
            if (path.contains("..") || path.contains("~") || path.startsWith("/") || path.contains(":") || path.contains("|") || path.contains("<") || path.contains(">") || path.contains("*") || path.contains("?")) {
                throw new IllegalArgumentException("路径包含非法字符");
            }
        }
        
        if (environment.getAccessUrls() != null && environment.getAccessUrls().length() > 2000) {
            throw new IllegalArgumentException("访问链接数据过长");
        }
    }

    public List<VulnEnvironment> getAllEnvironments() {
        return repository.findAll();
    }
    
    public Page<VulnEnvironment> searchEnvironments(String keyword, Pageable pageable) {
        return repository.searchByNameOrCveId(keyword, pageable);
    }

    public Optional<VulnEnvironment> getEnvironmentById(Long id) {
        return repository.findById(id);
    }

    public Optional<VulnEnvironment> getEnvironmentByName(String name) {
        return repository.findByName(name);
    }

    @Transactional
    public VulnEnvironment createEnvironment(VulnEnvironment environment) {
        validateEnvironmentInput(environment);
        
        if (environment.getPort() == null) {
            environment.setPort(allocatePort());
        } else if (repository.existsByPort(environment.getPort())) {
            throw new IllegalArgumentException("端口 " + environment.getPort() + " 已被使用");
        }
        if (environment.getDockerImage() == null || environment.getDockerImage().isEmpty()) {
            environment.setDockerImage("custom");
        }
        if (environment.getStatus() == null || environment.getStatus().isEmpty()) {
            environment.setStatus("stopped");
        }
        return repository.save(environment);
    }

    @Transactional
    public VulnEnvironment updateEnvironment(Long id, VulnEnvironment update) {
        VulnEnvironment existing = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("未找到ID为 " + id + " 的靶场环境"));
        
        if (update.getName() != null) {
            validateEnvironmentInput(update);
        }

        if (update.getName() != null) {
            existing.setName(update.getName());
        }

        if (update.getDescription() != null) {
            existing.setDescription(update.getDescription());
        }
        if (update.getCveId() != null) {
            existing.setCveId(update.getCveId());
        }
        if (update.getPath() != null) {
            existing.setPath(update.getPath());
        }
        if (update.getPort() != null && !update.getPort().equals(existing.getPort())) {
            if (repository.existsByPort(update.getPort())) {
                throw new IllegalArgumentException("Port " + update.getPort() + " is already in use");
            }
            existing.setPort(update.getPort());
        }
        if (update.getAccessUrls() != null) {
            existing.setAccessUrls(update.getAccessUrls());
        }

        return repository.save(existing);
    }

    @Transactional
    public void deleteEnvironment(Long id) {
        VulnEnvironment env = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Environment not found with id: " + id));

        if ("running".equals(env.getStatus())) {
            throw new IllegalStateException("Cannot delete a running environment. Please stop it first.");
        }

        repository.deleteById(id);
    }

    @Transactional
    public VulnEnvironment startEnvironment(Long id) {
        VulnEnvironment env = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("未找到ID为 " + id + " 的靶场环境"));

        if ("running".equals(env.getStatus())) {
            return env;
        }

        long runningCount = repository.countByStatus("running");
        if (runningCount > 0) {
            throw new IllegalStateException("已有靶场环境正在运行，请先停止当前环境");
        }

        String envPath = env.getPath();
        if (envPath == null || envPath.isEmpty()) {
            throw new IllegalStateException("靶场路径未配置");
        }

        File envDir = resolvePath(envPath);
        if (!envDir.exists()) {
            throw new IllegalStateException("靶场目录不存在: " + envDir.getAbsolutePath());
        }

        boolean started = false;
        String errorMessage = "";

        try {
            started = startWithDockerCompose(envDir);
            if (started) {
                logger.info("Docker Compose启动成功");
                env.setStatus("running");
                env.setContainerId("docker-compose");
                return repository.save(env);
            }
        } catch (Exception e) {
            errorMessage = "Docker Compose 启动失败: " + e.getMessage();
            logger.warn(errorMessage);
        }

        if (!started) {
            logger.info("Docker Compose失败，尝试备选Docker方案...");
            try {
                String containerId = startWithAlternativeDocker(envDir);
                if (containerId != null) {
                    logger.info("备选Docker方案启动成功");
                    env.setStatus("running");
                    env.setContainerId(containerId);
                    return repository.save(env);
                }
            } catch (Exception e) {
                errorMessage = "备选Docker方案启动失败: " + e.getMessage();
                logger.error(errorMessage);
            }
        }

        if (!started) {
            logger.info("所有Docker方案失败，尝试本地Java启动...");
            try {
                started = startWithJavaJar(envDir);
                if (started) {
                    logger.info("本地Java启动成功");
                    env.setStatus("running");
                    env.setContainerId("local-java");
                    return repository.save(env);
                }
            } catch (Exception e) {
                errorMessage = "本地Java启动失败: " + e.getMessage();
                logger.error(errorMessage);
            }
        }

        throw new RuntimeException("启动靶场失败: " + errorMessage);
    }

    @Transactional
    public VulnEnvironment stopEnvironment(Long id) {
        VulnEnvironment env = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("未找到ID为 " + id + " 的靶场环境"));

        if ("stopped".equals(env.getStatus())) {
            return env;
        }

        String envPath = env.getPath();
        if (envPath == null || envPath.isEmpty()) {
            throw new IllegalStateException("靶场路径未配置");
        }

        File envDir = resolvePath(envPath);

        try {
            boolean stopped = stopWithScript(envDir);
            if (stopped) {
                logger.info("靶场停止成功");
                env.setStatus("stopped");
                env.setContainerId(null);
                return repository.save(env);
            } else {
                throw new RuntimeException("停止脚本执行失败");
            }
        } catch (Exception e) {
            logger.error("停止脚本执行异常: {}", e.getMessage());
            throw new RuntimeException("停止靶场失败: " + e.getMessage());
        }
    }

    private boolean startWithDockerCompose(File envDir) {
        try {
            ProcessBuilder pb = new ProcessBuilder("docker-compose", "up", "-d");
            pb.directory(envDir);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                    logger.debug("docker-compose: {}", line);
                }
            }

            boolean finished = process.waitFor(120, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                logger.error("Docker Compose timeout");
                return false;
            }

            if (process.exitValue() == 0) {
                logger.info("Docker Compose started successfully");
                return true;
            } else {
                logger.error("Docker Compose failed with exit code: {}", process.exitValue());
                logger.error("Output: {}", output);
                return false;
            }
        } catch (Exception e) {
            logger.error("Failed to run docker-compose: {}", e.getMessage());
            return false;
        }
    }

    private boolean startWithScript(File envDir) {
        String os = System.getProperty("os.name").toLowerCase();
        String scriptName;

        if (os.contains("win")) {
            scriptName = "start.bat";
        } else if (os.contains("mac")) {
            scriptName = "start-mac.sh";
        } else {
            scriptName = "start.sh";
        }

        File scriptFile = new File(envDir, scriptName);
        if (!scriptFile.exists()) {
            logger.warn("Startup script not found: {}", scriptFile.getAbsolutePath());
            return startWithJavaJar(envDir);
        }

        try {
            ProcessBuilder pb;
            if (os.contains("win")) {
                pb = new ProcessBuilder("cmd.exe", "/c", scriptName);
            } else {
                pb = new ProcessBuilder("sh", scriptName);
            }
            pb.directory(envDir);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), "UTF-8"))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                    logger.debug("script: {}", line);
                }
            }

            boolean finished = process.waitFor(120, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                logger.error("Startup script timeout");
                return startWithJavaJar(envDir);
            }

            if (process.exitValue() == 0) {
                logger.info("Startup script executed successfully");
                return true;
            } else {
                logger.error("Startup script failed with exit code: {}", process.exitValue());
                logger.error("Output: {}", output);
                return startWithJavaJar(envDir);
            }
        } catch (Exception e) {
            logger.error("Failed to run startup script: {}, trying direct Java execution", e.getMessage());
            return startWithJavaJar(envDir);
        }
    }

    private String startWithAlternativeDocker(File envDir) {
        try {
            logger.info("Trying alternative Docker approach...");
            
            String envPath = envDir.getAbsolutePath();
            String containerName = "vulfr-" + System.currentTimeMillis();
            
            ProcessBuilder pb = new ProcessBuilder(
                "docker", "run", "-d",
                "--name", containerName,
                "-p", "28083:8080",
                "-e", "SPRING_DATASOURCE_URL=jdbc:mysql://host.docker.internal:13306/my_blog_db?useUnicode=true&characterEncoding=utf8&autoReconnect=true&useSSL=false&serverTimezone=UTC",
                "-e", "SPRING_DATASOURCE_USERNAME=root",
                "-e", "SPRING_DATASOURCE_PASSWORD=519666",
                "-v", envPath + "/My-Blog-master/target:/app",
                "openjdk:11-jre-slim",
                "java", "-jar", "/app/my-blog-4.0.0-SNAPSHOT.jar"
            );
            pb.redirectErrorStream(true);
            
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }
            
            process.waitFor(30, TimeUnit.SECONDS);
            
            if (process.exitValue() == 0 && output.length() > 0) {
                String containerId = output.toString().trim();
                logger.info("Alternative Docker started successfully, container ID: {}", containerId);
                Thread.sleep(15000);
                return containerId;
            } else {
                logger.error("Alternative Docker failed with exit code: {}", process.exitValue());
                return null;
            }
        } catch (Exception e) {
            logger.error("Failed to start with alternative Docker: {}", e.getMessage());
            return null;
        }
    }

    private boolean startWithJavaJar(File envDir) {
        try {
            logger.info("Trying direct Java JAR execution...");
            
            File myBlogDir = new File(envDir, "My-Blog-master");
            File jarFile = new File(myBlogDir, "target/my-blog-4.0.0-SNAPSHOT.jar");
            
            if (!jarFile.exists()) {
                logger.error("JAR file not found: {}", jarFile.getAbsolutePath());
                return false;
            }

            logger.info("Local MySQL detected, connecting directly...");

            ProcessBuilder pb = new ProcessBuilder("java", "-jar", "target/my-blog-4.0.0-SNAPSHOT.jar");
            pb.directory(myBlogDir);
            pb.redirectErrorStream(true);
            
            Process process = pb.start();

            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), "UTF-8"))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        logger.info("app: {}", line);
                    }
                } catch (Exception e) {
                    logger.error("Error reading app output: {}", e.getMessage());
                }
            }).start();

            Thread.sleep(10000);
            
            if (process.isAlive()) {
                logger.info("Application started successfully via Java JAR");
                return true;
            } else {
                logger.error("Application process died");
                return false;
            }
        } catch (Exception e) {
            logger.error("Failed to start with Java JAR: {}", e.getMessage());
            return false;
        }
    }

    private boolean stopWithScript(File envDir) {
        String os = System.getProperty("os.name").toLowerCase();
        String scriptName;

        if (os.contains("win")) {
            scriptName = "stop.bat";
        } else {
            scriptName = "stop.sh";
        }

        File scriptFile = new File(envDir, scriptName);
        if (!scriptFile.exists()) {
            logger.warn("停止脚本不存在: {}, 尝试直接使用docker-compose down", scriptFile.getAbsolutePath());
            return stopWithDockerComposeFallback(envDir);
        }

        try {
            ProcessBuilder pb;
            if (os.contains("win")) {
                pb = new ProcessBuilder("cmd.exe", "/c", scriptName);
            } else {
                pb = new ProcessBuilder("sh", scriptName);
            }
            pb.directory(envDir);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                    logger.debug("停止脚本: {}", line);
                }
            }

            boolean finished = process.waitFor(60, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                logger.warn("停止脚本超时，尝试备选方案");
                return stopWithDockerComposeFallback(envDir);
            }

            if (process.exitValue() != 0) {
                logger.warn("停止脚本执行失败，退出码: {}, 尝试备选方案", process.exitValue());
                return stopWithDockerComposeFallback(envDir);
            } else {
                logger.info("停止脚本执行成功");
                return true;
            }
        } catch (Exception e) {
            logger.error("执行停止脚本异常: {}, 尝试备选方案", e.getMessage());
            return stopWithDockerComposeFallback(envDir);
        }
    }

    private boolean stopWithDockerComposeFallback(File envDir) {
        try {
            ProcessBuilder pb = new ProcessBuilder("docker-compose", "down");
            pb.directory(envDir);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    logger.debug("docker-compose down: {}", line);
                }
            }

            boolean finished = process.waitFor(60, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                logger.error("Docker Compose停止超时");
                return false;
            }

            if (process.exitValue() != 0) {
                logger.error("Docker Compose停止失败，退出码: {}", process.exitValue());
                return false;
            }
            
            logger.info("Docker Compose停止成功");
            return true;
        } catch (Exception e) {
            logger.error("使用docker-compose停止失败: {}", e.getMessage());
            return false;
        }
    }

    private Integer allocatePort() {
        for (int port = PORT_MIN; port <= PORT_MAX; port++) {
            if (!repository.existsByPort(port)) {
                return port;
            }
        }
        throw new IllegalStateException("No available ports in range " + PORT_MIN + "-" + PORT_MAX);
    }

    private boolean verifyStart(VulnEnvironment env, File envDir) {
        logger.info("Verifying environment startup...");
        
        int maxAttempts = 10;
        int delayMs = 3000;
        
        for (int i = 0; i < maxAttempts; i++) {
            try {
                Thread.sleep(delayMs);
                
                if (isDockerContainerRunning(envDir)) {
                    logger.info("Docker container is running");
                    return true;
                }
                
                if (isLocalPortListening(28083)) {
                    logger.info("Local port 28083 is listening");
                    return true;
                }
                
                logger.debug("Verification attempt {} failed, retrying...", i + 1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        
        logger.warn("Startup verification failed after {} attempts", maxAttempts);
        return false;
    }

    private boolean verifyStop(VulnEnvironment env, File envDir) {
        logger.info("Verifying environment stop...");
        
        int maxAttempts = 5;
        int delayMs = 2000;
        
        for (int i = 0; i < maxAttempts; i++) {
            try {
                Thread.sleep(delayMs);
                
                if (!isDockerContainerRunning(envDir) && !isLocalPortListening(28083)) {
                    logger.info("Environment stopped successfully");
                    return true;
                }
                
                logger.debug("Stop verification attempt {} failed, retrying...", i + 1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        
        logger.warn("Stop verification failed after {} attempts", maxAttempts);
        return false;
    }

    private boolean isDockerContainerRunning(File envDir) {
        try {
            ProcessBuilder pb = new ProcessBuilder("docker-compose", "ps", "-q");
            pb.directory(envDir);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            String output = new BufferedReader(new InputStreamReader(process.getInputStream())).readLine();
            process.waitFor();
            
            return output != null && !output.isEmpty();
        } catch (Exception e) {
            logger.debug("Error checking Docker containers: {}", e.getMessage());
            return false;
        }
    }

    private boolean isLocalPortListening(int port) {
        try {
            ProcessBuilder pb = new ProcessBuilder("netstat", "-ano");
            Process process = pb.start();
            
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line);
                }
            }
            process.waitFor();
            
            return output.toString().contains(":" + port + " ");
        } catch (Exception e) {
            logger.debug("Error checking port: {}", e.getMessage());
            return false;
        }
    }
}
