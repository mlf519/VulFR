package org.mcc.vulfr.service;

import com.github.dockerjava.api.DockerClient;
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

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
public class VulnEnvironmentService {

    private static final Logger logger = LoggerFactory.getLogger(VulnEnvironmentService.class);
    private static final int PORT_MIN = 10000;
    private static final int PORT_MAX = 12000;
    private static final int VERIFICATION_TIMEOUT_SECONDS = 60;

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

        if ("running".equals(env.getStatus()) || "starting".equals(env.getStatus())) {
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

        try {
            boolean composeStarted = startWithDockerCompose(envDir);
            if (!composeStarted) {
                throw new RuntimeException("Docker Compose 启动失败");
            }

            env.setStatus("starting");
            env.setContainerId("docker-compose");
            return repository.save(env);
        } catch (Exception e) {
            logger.error("启动靶场失败: {}", e.getMessage());
            throw new RuntimeException("启动靶场失败: " + e.getMessage(), e);
        }
    }

    public boolean verifyAccessUrl(Long id) {
        VulnEnvironment env = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("未找到ID为 " + id + " 的靶场环境"));

        String accessUrlsRaw = env.getAccessUrls();
        logger.info("环境 {} 的 accessUrls 原始值: {}", id, accessUrlsRaw);
        
        String firstAccessUrl = getFirstAccessUrl(env);
        logger.info("解析后的第一个访问链接: {}", firstAccessUrl);
        
        if (firstAccessUrl == null || firstAccessUrl.isEmpty()) {
            logger.info("访问链接为空，直接返回true");
            return true;
        }

        try {
            URL url = new URL(firstAccessUrl);
            logger.info("正在访问: {}:{}", url.getHost(), url.getPort());
            
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);
            connection.setRequestMethod("GET");
            connection.setInstanceFollowRedirects(true);

            int responseCode = connection.getResponseCode();
            logger.info("HTTP响应状态码: {}", responseCode);
            
            if (responseCode >= 200 && responseCode < 400) {
                logger.info("验证成功!");
                return true;
            } else {
                logger.warn("验证失败，HTTP状态码: {}", responseCode);
                return false;
            }
        } catch (IOException e) {
            logger.error("验证访问链接失败: {}", e.getMessage());
            return false;
        }
    }

    @Transactional
    public VulnEnvironment markAsRunning(Long id) {
        VulnEnvironment env = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("未找到ID为 " + id + " 的靶场环境"));

        if ("starting".equals(env.getStatus())) {
            env.setStatus("running");
            return repository.save(env);
        }
        return env;
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
            boolean stopped = stopWithDockerCompose(envDir);
            if (stopped) {
                logger.info("靶场停止成功");
                env.setStatus("stopped");
                env.setContainerId(null);
                return repository.save(env);
            } else {
                throw new RuntimeException("Docker Compose 停止失败");
            }
        } catch (Exception e) {
            logger.error("停止靶场失败: {}", e.getMessage());
            throw new RuntimeException("停止靶场失败: " + e.getMessage(), e);
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

    private boolean stopWithDockerCompose(File envDir) {
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
                logger.error("Docker Compose stop timeout");
                return false;
            }

            if (process.exitValue() != 0) {
                logger.error("Docker Compose stop failed with exit code: {}", process.exitValue());
                return false;
            }
            
            logger.info("Docker Compose stopped successfully");
            return true;
        } catch (Exception e) {
            logger.error("Failed to stop docker-compose: {}", e.getMessage());
            return false;
        }
    }

    private String getFirstAccessUrl(VulnEnvironment env) {
        String accessUrls = env.getAccessUrls();
        if (accessUrls == null || accessUrls.trim().isEmpty()) {
            return null;
        }
        
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            java.util.List<java.util.Map<String, String>> urlList = mapper.readValue(
                accessUrls, 
                new com.fasterxml.jackson.core.type.TypeReference<java.util.List<java.util.Map<String, String>>>() {}
            );
            
            if (urlList != null && !urlList.isEmpty()) {
                java.util.Map<String, String> firstUrlMap = urlList.get(0);
                String urlValue = firstUrlMap.get("value");
                return urlValue != null && !urlValue.trim().isEmpty() ? urlValue.trim() : null;
            }
        } catch (Exception e) {
            logger.warn("解析 accessUrls JSON 失败: {}", e.getMessage());
        }
        
        return null;
    }

    private boolean verifyAccessUrl(String urlStr, File envDir) {
        logger.info("开始验证访问链接: {}, 超时时间: {}秒", urlStr, VERIFICATION_TIMEOUT_SECONDS);
        
        for (int i = 0; i < VERIFICATION_TIMEOUT_SECONDS; i++) {
            try {
                URL url = new URL(urlStr);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setConnectTimeout(3000);
                connection.setReadTimeout(3000);
                connection.setRequestMethod("GET");
                
                int responseCode = connection.getResponseCode();
                if (responseCode >= 200 && responseCode < 400) {
                    logger.info("访问链接验证成功，HTTP状态码: {}", responseCode);
                    return true;
                }
                
                logger.debug("验证尝试 {}: HTTP状态码 {}", i + 1, responseCode);
            } catch (IOException e) {
                logger.debug("验证尝试 {}: 连接失败 - {}", i + 1, e.getMessage());
            }
            
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warn("验证被中断");
                return false;
            }
        }
        
        logger.warn("访问链接验证超时，{}秒内未能成功访问", VERIFICATION_TIMEOUT_SECONDS);
        return false;
    }

    private Integer allocatePort() {
        for (int port = PORT_MIN; port <= PORT_MAX; port++) {
            if (!repository.existsByPort(port)) {
                return port;
            }
        }
        throw new IllegalStateException("No available ports in range " + PORT_MIN + "-" + PORT_MAX);
    }
}
