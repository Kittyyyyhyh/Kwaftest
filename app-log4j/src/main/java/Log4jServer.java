import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Log4j2 漏洞靶场 — 内嵌 HTTP 服务器
 *
 * 端口: 8080
 * 端点:
 *   GET /log4j/level1?name=  — 日志记录 URL 参数 (L1: 参数注入)
 *   GET /log4j/level2         — 日志记录 User-Agent 头 (L2: Header 注入)
 *
 * Flag 嵌入方式: 环境变量
 *   LOG4J_FLAG_L1 = flag{log4j_env_param_2b6d}
 *   LOG4J_FLAG_L2 = flag{log4j_env_header_9f1a}
 *
 * Log4j2 会解析 ${env:LOG4J_FLAG_L1} → flag 值直接泄露到日志输出中
 * 攻击者无需 JNDI 基础设施，只需 ${env:FLAG_NAME} 语法即可窃取环境变量
 */
public class Log4jServer {
    private static final Logger logger = LogManager.getLogger(Log4jServer.class);

    // 存储最近的日志输出，供 /status 端点查询
    private static final List<String> recentLogs = new ArrayList<>();
    private static final int MAX_LOGS = 50;

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);

        server.createContext("/log4j/level1", new Level1Handler());
        server.createContext("/log4j/level2", new Level2Handler());
        server.createContext("/log4j/", new IndexHandler());
        server.createContext("/", new IndexHandler());

        server.setExecutor(null);
        server.start();

        logger.info("Log4j2 vulnerable lab started on port {}", port);
        logger.info("Endpoints: /log4j/level1 (param), /log4j/level2 (header)");
        System.out.println("Log4j2 Lab running on port " + port);
    }

    static synchronized void addLog(String entry) {
        recentLogs.add(entry);
        if (recentLogs.size() > MAX_LOGS) {
            recentLogs.remove(0);
        }
    }

    /**
     * L1 — URL 参数注入
     * GET /log4j/level1?name=xxx
     * name 参数直接写入 Log4j2 日志（漏洞点）
     * 攻击: ?name=${env:LOG4J_FLAG_L1}
     */
    static class Level1Handler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            Map<String, String> params = parseQuery(query);
            String name = params.getOrDefault("name", "guest");

            // ⚠️ 漏洞点: 用户输入直接传给 Log4j2 logger
            // Log4j2 会解析 ${...} 表达式，包括 ${env:VAR}, ${jndi:ldap://}, ${java:version} 等
            logger.info("L1 - User lookup request: name={}", name);
            addLog("L1 name=" + name);

            String json = String.format(
                "{\"endpoint\":\"level1\",\"param\":\"name\",\"input\":\"%s\",\"result\":\"logged\"}",
                escapeJson(name)
            );

            sendResponse(exchange, 200, "application/json", json);
        }
    }

    /**
     * L2 — HTTP Header 注入 (User-Agent)
     * GET /log4j/level2
     * User-Agent 头直接写入 Log4j2 日志
     * 攻击: curl -H 'User-Agent: ${env:LOG4J_FLAG_L2}' /log4j/level2
     */
    static class Level2Handler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
            if (userAgent == null) userAgent = "unknown";

            // ⚠️ 漏洞点: User-Agent 直接传给 Log4j2 logger
            logger.info("L2 - Request from UA: {}", userAgent);
            addLog("L2 UA=" + userAgent);

            String json = String.format(
                "{\"endpoint\":\"level2\",\"header\":\"User-Agent\",\"input\":\"%s\",\"result\":\"logged\"}",
                escapeJson(userAgent)
            );

            sendResponse(exchange, 200, "application/json", json);
        }
    }

    /**
     * 索引页 — 展示最近日志（用于验证 Log4j2 是否解析了表达式）
     */
    static class IndexHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            if (!path.equals("/log4j/") && !path.equals("/")) {
                sendResponse(exchange, 404, "text/plain", "Not Found");
                return;
            }

            StringBuilder html = new StringBuilder();
            html.append("<!DOCTYPE html><html lang=\"zh\"><head><meta charset=\"UTF-8\">");
            html.append("<title>Log4j2 Lab</title>");
            html.append("<style>");
            html.append("body{font-family:monospace;max-width:900px;margin:50px auto;padding:20px;background:#1a1a2e;color:#e0e0e0;}");
            html.append("h2{color:#e94560;}.info{background:#16213e;padding:15px;border-radius:5px;margin:20px 0;border-left:4px solid #e94560;}");
            html.append(".endpoint{background:#0f3460;padding:10px;border-radius:3px;margin:10px 0;color:#53d769;}");
            html.append("pre{background:#0f3460;padding:10px;border-radius:3px;overflow-x:auto;color:#53d769;}");
            html.append(".log-entry{border-bottom:1px solid #1a1a3e;padding:5px 0;font-size:0.85em;}");
            html.append("a{color:#53d769;}");
            // ⚠️ 漏洞点: 将最近日志直接嵌入 HTML（Log4j2 已将 ${...} 解析后的值写入日志）
            // 如果攻击者注入 ${env:LOG4J_FLAG_L1}，解析后的 flag 会出现在这里
            html.append(".flag-hint{background:#2d132c;border:1px dashed #e94560;padding:8px 12px;border-radius:3px;margin:10px 0;font-size:0.8em;color:#ff6b81;}");
            html.append("</style></head><body>");
            html.append("<h2>🪵 Log4j2 漏洞靶场</h2>");

            html.append("<div class=\"info\">");
            html.append("<strong>说明:</strong> 此服务使用 Apache Log4j2 2.14.1（存在 JNDI 注入漏洞 CVE-2021-44228）。<br>");
            html.append("用户输入直接传给 Log4j2 logger，Log4j2 会解析 <code>${...}</code> 表达式。<br>");
            html.append("<br><strong>攻击目标:</strong><br>");
            html.append("L1 — 通过 URL 参数 <code>?name=</code> 窃取环境变量 <code>LOG4J_FLAG_L1</code><br>");
            html.append("L2 — 通过 User-Agent 头窃取环境变量 <code>LOG4J_FLAG_L2</code><br>");
            html.append("<br><strong>提示:</strong> 使用 <code>${env:VARIABLE_NAME}</code> 语法读取敏感环境变量<br>");
            html.append("不使用 JNDI/LDAP，仅用 Log4j2 内置 <code>env</code> lookup 即可成功提取 flag");
            html.append("</div>");

            html.append("<div class=\"flag-hint\">");
            html.append("🔑 环境变量已设置（模拟生产环境中的敏感凭证）：<br>");
            html.append("<code>LOG4J_FLAG_L1</code> — L1 目标<br>");
            html.append("<code>LOG4J_FLAG_L2</code> — L2 目标<br>");
            html.append("使用 <code>${env:LOG4J_FLAG_L1}</code> 语法提取值");
            html.append("</div>");

            html.append("<h3>🔌 端点</h3>");
            html.append("<div class=\"endpoint\">GET /log4j/level1?name= — L1 参数注入</div>");
            html.append("<div class=\"endpoint\">GET /log4j/level2 — L2 Header 注入 (User-Agent)</div>");

            html.append("<h3>📋 最近日志 (Log4j2 已解析 ${...} 后的输出)</h3>");
            html.append("<pre>");
            synchronized (Log4jServer.class) {
                for (String log : recentLogs) {
                    html.append("<div class=\"log-entry\">")
                        .append(escapeHtml(log))
                        .append("</div>");
                }
                if (recentLogs.isEmpty()) {
                    html.append("(暂无日志 — 发送请求后刷新此页)");
                }
            }
            html.append("</pre>");

            html.append("<p><a href=\"/log4j/level1?name=test\">→ 测试 L1 (name=test)</a></p>");
            html.append("<p><a href=\"/log4j/\">→ 刷新此页查看日志</a></p>");

            html.append("</body></html>");

            sendResponse(exchange, 200, "text/html; charset=utf-8", html.toString());
        }
    }

    // ---- 工具方法 ----

    static Map<String, String> parseQuery(String query) {
        Map<String, String> map = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) return map;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq >= 0) {
                try {
                    String key = java.net.URLDecoder.decode(pair.substring(0, eq), "UTF-8");
                    String val = java.net.URLDecoder.decode(pair.substring(eq + 1), "UTF-8");
                    map.put(key, val);
                } catch (UnsupportedEncodingException e) {
                    map.put(pair.substring(0, eq), pair.substring(eq + 1));
                }
            }
        }
        return map;
    }

    static void sendResponse(HttpExchange exchange, int code, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(code, bytes.length);
        OutputStream os = exchange.getResponseBody();
        os.write(bytes);
        os.close();
    }

    static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }

    static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }
}
