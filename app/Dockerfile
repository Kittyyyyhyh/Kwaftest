FROM php:8.2-apache

# 安装 mysqli 扩展
RUN docker-php-ext-install mysqli pdo pdo_mysql

# 启用 Apache rewrite 模块（靶场主页路由用）
RUN a2enmod rewrite

# 将 www-data 的 uid/gid 改为 999，与 WAF 容器的 httpd 用户对齐
# 这样 PHP 可以通过共享卷读取 WAF 审计日志
RUN usermod -u 999 www-data && groupmod -g 999 www-data

# 复制应用代码
COPY . /var/www/html/

# 创建 flag 文件 — 模拟生产环境中不同危害级别的敏感文件
RUN mkdir -p /srv/app/config /srv/data /var/backups /opt/app
COPY --chown=www-data:www-data flag_database.cnf /srv/app/config/database.cnf
COPY --chown=www-data:www-data flag_credentials.env /srv/app/config/credentials.env
COPY --chown=www-data:www-data flag_server.yml /srv/data/server_config.yml
COPY --chown=www-data:www-data flag_backup.sql /var/backups/db_dump_202607.sql

# 设置权限
RUN chown -R www-data:www-data /var/www/html /srv/app /srv/data \
    && chmod -R 755 /var/www/html /srv/app /srv/data \
    && mkdir -p /var/www/html/uploads \
    && chmod 777 /var/www/html/uploads

# 暴露端口
EXPOSE 80
