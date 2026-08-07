FROM maven:3.8-openjdk-8-slim AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:resolve -q
COPY src/ ./src/
RUN mvn package -DskipTests -q

FROM openjdk:8-jre-slim
WORKDIR /app
COPY --from=build /app/target/log4j-vuln-1.0.jar /app/app.jar

# 环境变量形式的 flag — 模拟生产环境中存储的敏感凭证
# Log4j2 的 ${env:VAR} lookup 可以直接读取这些值
ENV LOG4J_FLAG_L1=flag{log4j_env_param_2b6d}
ENV LOG4J_FLAG_L2=flag{log4j_env_header_9f1a}

EXPOSE 8080
CMD ["java", "-jar", "/app/app.jar"]
