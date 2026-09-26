use anyhow::Result;
use regex::Regex;
use std::fs;
use std::path::Path;

use crate::models::ConfigReference;

pub struct ConfigScanner;

impl ConfigScanner {
    pub fn scan() -> Result<Vec<ConfigReference>> {
        let mut references = Vec::new();

        references.extend(Self::scan_nginx()?);
        references.extend(Self::scan_apache()?);
        references.extend(Self::scan_haproxy()?);
        references.extend(Self::scan_traefik()?);
        references.extend(Self::scan_caddy()?);
        references.extend(Self::scan_php_fpm()?);
        references.extend(Self::scan_app_configs()?);
        references.extend(Self::scan_env_files()?);
        references.extend(Self::scan_database_configs()?);

        references.sort_by(|a, b| {
            (&a.file_path, &a.hostname, &a.port, &a.context).cmp(&(
                &b.file_path,
                &b.hostname,
                &b.port,
                &b.context,
            ))
        });
        references.dedup_by(|a, b| {
            a.file_path == b.file_path
                && a.hostname == b.hostname
                && a.port == b.port
                && a.context == b.context
        });

        Ok(references)
    }

    fn scan_nginx() -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let nginx_dirs = vec![
            "/etc/nginx",
            "/etc/nginx/sites-available",
            "/etc/nginx/sites-enabled",
        ];

        for dir in nginx_dirs {
            if Path::new(dir).exists() {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        if let Ok(path) = entry.path().canonicalize() {
                            if path.is_file() {
                                if let Ok(content) = fs::read_to_string(&path) {
                                    refs.extend(Self::parse_nginx_config(&path, &content)?);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(refs)
    }

    fn parse_nginx_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let upstream_re = Regex::new(r"(?m)upstream\s+\w+\s*\{([^}]+)\}")?;
        let server_re = Regex::new(r"(?m)server\s+([^\s;]+)(?::(\d+))?")?;
        let proxy_re = Regex::new(r"proxy_pass\s+(?:https?://)?([^/:]+)(?::(\d+))?")?;
        let site_re = Regex::new(r"(?ms)server\s*\{([^}]*)\}")?;
        let name_re = Regex::new(r"\bserver_name\s+([^;]+);")?;
        let root_re = Regex::new(r"\broot\s+([^;]+);")?;
        let listen_re = Regex::new(r"\blisten\s+([^;]+);")?;

        for site in site_re.captures_iter(content) {
            let Some(block) = site.get(1).map(|value| value.as_str()) else {
                continue;
            };
            let root = root_re
                .captures(block)
                .and_then(|capture| capture.get(1))
                .map(|value| value.as_str().trim().to_string());
            let ports = listen_re
                .captures_iter(block)
                .filter_map(|capture| capture.get(1))
                .filter_map(|value| value.as_str().split_whitespace().next())
                .filter_map(|value| {
                    value
                        .rsplit(':')
                        .next()
                        .unwrap_or(value)
                        .parse::<u16>()
                        .ok()
                })
                .collect::<Vec<_>>();
            if let Some(names) = name_re.captures(block).and_then(|capture| capture.get(1)) {
                for hostname in names
                    .as_str()
                    .split_whitespace()
                    .filter(|name| Self::is_valid_hostname(name) && *name != "_")
                {
                    let mut context = root
                        .as_ref()
                        .map(|path| format!("nginx site; root={}", path))
                        .unwrap_or_else(|| "nginx site".to_string());
                    if !ports.is_empty() {
                        context.push_str(&format!(
                            "; ports={}",
                            ports
                                .iter()
                                .map(u16::to_string)
                                .collect::<Vec<_>>()
                                .join(",")
                        ));
                    }
                    refs.push(ConfigReference {
                        file_path: path.display().to_string(),
                        hostname: hostname.to_string(),
                        port: None,
                        context,
                        config_line: None,
                    });
                }
            }
        }

        for caps in upstream_re.captures_iter(content) {
            if let Some(upstream_block) = caps.get(1) {
                for server_cap in server_re.captures_iter(upstream_block.as_str()) {
                    if let Some(host) = server_cap.get(1) {
                        let hostname = host.as_str().to_string();
                        let port = server_cap.get(2).and_then(|p| p.as_str().parse().ok());

                        if Self::is_valid_hostname(&hostname) {
                            refs.push(ConfigReference {
                                file_path: path.display().to_string(),
                                hostname,
                                port,
                                context: "nginx upstream".to_string(),
                                config_line: None,
                            });
                        }
                    }
                }
            }
        }

        for caps in proxy_re.captures_iter(content) {
            if let Some(host) = caps.get(1) {
                let hostname = host.as_str().to_string();
                let port = caps.get(2).and_then(|p| p.as_str().parse().ok());

                if Self::is_valid_hostname(&hostname) {
                    refs.push(ConfigReference {
                        file_path: path.display().to_string(),
                        hostname,
                        port,
                        context: "proxy_pass".to_string(),
                        config_line: None,
                    });
                }
            }
        }

        Ok(refs)
    }

    fn scan_apache() -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();
        for dir in [
            "/etc/apache2/sites-enabled",
            "/etc/apache2/sites-available",
            "/etc/httpd/conf.d",
            "/etc/httpd/sites-enabled",
        ] {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(content) = fs::read_to_string(&path) {
                            refs.extend(Self::parse_apache_config(&path, &content)?);
                        }
                    }
                }
            }
        }
        Ok(refs)
    }

    fn parse_apache_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();
        let vhost_re = Regex::new(r"(?is)<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>")?;
        let name_re = Regex::new(r"(?mi)^\s*ServerName\s+(\S+)")?;
        let alias_re = Regex::new(r"(?mi)^\s*ServerAlias\s+(.+)")?;
        let root_re = Regex::new(r"(?mi)^\s*DocumentRoot\s+([^\s#]+)")?;
        let proxy_re =
            Regex::new(r"(?mi)^\s*ProxyPass\s+\S+\s+(?:https?://)?([^/:\s]+)(?::(\d+))?")?;

        for capture in vhost_re.captures_iter(content) {
            let specification = capture
                .get(1)
                .map(|value| value.as_str())
                .unwrap_or_default();
            let block = capture
                .get(2)
                .map(|value| value.as_str())
                .unwrap_or_default();
            let ports = specification
                .split_whitespace()
                .filter_map(|value| value.rsplit(':').next())
                .filter_map(|value| value.parse::<u16>().ok())
                .collect::<Vec<_>>();
            let root = root_re
                .captures(block)
                .and_then(|value| value.get(1))
                .map(|value| value.as_str().to_string());
            let mut names = Vec::new();
            if let Some(name) = name_re.captures(block).and_then(|value| value.get(1)) {
                names.push(name.as_str().to_string());
            }
            if let Some(aliases) = alias_re.captures(block).and_then(|value| value.get(1)) {
                names.extend(aliases.as_str().split_whitespace().map(str::to_string));
            }
            for hostname in names.iter().filter(|name| Self::is_valid_hostname(name)) {
                let mut context = root
                    .as_ref()
                    .map(|value| format!("apache site; root={}", value))
                    .unwrap_or_else(|| "apache site".to_string());
                if !ports.is_empty() {
                    context.push_str(&format!(
                        "; ports={}",
                        ports
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    ));
                }
                refs.push(ConfigReference {
                    file_path: path.display().to_string(),
                    hostname: hostname.clone(),
                    port: None,
                    context,
                    config_line: None,
                });
            }
            for proxy in proxy_re.captures_iter(block) {
                let Some(hostname) = proxy.get(1).map(|value| value.as_str()) else {
                    continue;
                };
                if Self::is_valid_hostname(hostname) {
                    refs.push(ConfigReference {
                        file_path: path.display().to_string(),
                        hostname: hostname.to_string(),
                        port: proxy.get(2).and_then(|value| value.as_str().parse().ok()),
                        context: "apache proxy_pass".to_string(),
                        config_line: None,
                    });
                }
            }
        }
        Ok(refs)
    }

    fn scan_haproxy() -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();
        let mut paths = vec![Path::new("/etc/haproxy/haproxy.cfg").to_path_buf()];
        if let Ok(entries) = fs::read_dir("/etc/haproxy/conf.d") {
            paths.extend(entries.flatten().map(|entry| entry.path()));
        }
        for path in paths {
            if path.is_file() {
                if let Ok(content) = fs::read_to_string(&path) {
                    refs.extend(Self::parse_haproxy_config(&path, &content)?);
                }
            }
        }
        Ok(refs)
    }

    fn parse_haproxy_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let server_re =
            Regex::new(r"(?mi)^\s*server\s+\S+\s+(?:[a-z0-9_-]+@)?([^\s:]+)(?::(\d+))?")?;
        let mut refs = Vec::new();
        for capture in server_re.captures_iter(content) {
            let Some(hostname) = capture.get(1).map(|value| value.as_str()) else {
                continue;
            };
            if Self::is_valid_hostname(hostname) {
                refs.push(ConfigReference {
                    file_path: path.display().to_string(),
                    hostname: hostname.to_string(),
                    port: capture.get(2).and_then(|value| value.as_str().parse().ok()),
                    context: "haproxy backend".to_string(),
                    config_line: None,
                });
            }
        }
        Ok(refs)
    }

    fn scan_traefik() -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();
        let mut paths = Vec::new();
        for path in [
            "/etc/traefik/traefik.yml",
            "/etc/traefik/traefik.yaml",
            "/etc/traefik/traefik.toml",
            "/etc/traefik/dynamic.yml",
            "/etc/traefik/dynamic.yaml",
            "/etc/traefik/dynamic.toml",
        ] {
            paths.push(Path::new(path).to_path_buf());
        }
        for dir in ["/etc/traefik/conf.d", "/etc/traefik/dynamic"] {
            if let Ok(entries) = fs::read_dir(dir) {
                paths.extend(entries.flatten().map(|entry| entry.path()));
            }
        }
        for path in paths {
            if path.is_file() {
                if let Ok(content) = fs::read_to_string(&path) {
                    refs.extend(Self::parse_traefik_config(&path, &content)?);
                }
            }
        }
        Ok(refs)
    }

    fn parse_traefik_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let url_re =
            Regex::new(r##"(?mi)\burl\s*[:=]\s*["']?(?:https?://)?([^/:\s"']+)(?::(\d+))?"##)?;
        let mut refs = Vec::new();
        for capture in url_re.captures_iter(content) {
            let Some(hostname) = capture.get(1).map(|value| value.as_str()) else {
                continue;
            };
            if Self::is_valid_hostname(hostname) {
                refs.push(ConfigReference {
                    file_path: path.display().to_string(),
                    hostname: hostname.to_string(),
                    port: capture.get(2).and_then(|value| value.as_str().parse().ok()),
                    context: "traefik service".to_string(),
                    config_line: None,
                });
            }
        }
        Ok(refs)
    }

    fn scan_caddy() -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();
        let paths = [
            Path::new("/etc/caddy/Caddyfile"),
            Path::new("/etc/caddy/caddyfile"),
        ];
        for path in paths {
            if path.is_file() {
                if let Ok(content) = fs::read_to_string(path) {
                    refs.extend(Self::parse_caddy_config(path, &content)?);
                }
            }
        }
        Ok(refs)
    }

    fn parse_caddy_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let site_re = Regex::new(r"(?m)^\s*([^{}]+)\{([^}]*)\}")?;
        let root_re = Regex::new(r"(?m)^\s*root\s+\S+\s+([^\s#]+)")?;
        let proxy_re = Regex::new(r"(?m)^\s*reverse_proxy(?:\s+\S+)?\s+([^\s{,]+)")?;
        let mut refs = Vec::new();

        for site in site_re.captures_iter(content) {
            let names = site.get(1).map(|value| value.as_str()).unwrap_or_default();
            let block = site.get(2).map(|value| value.as_str()).unwrap_or_default();
            let root = root_re
                .captures(block)
                .and_then(|capture| capture.get(1))
                .map(|value| value.as_str().to_string());
            for name in names
                .split_whitespace()
                .filter(|name| Self::is_valid_hostname(name))
            {
                let context = root
                    .as_ref()
                    .map(|value| format!("caddy site; root={}", value))
                    .unwrap_or_else(|| "caddy site".to_string());
                refs.push(ConfigReference {
                    file_path: path.display().to_string(),
                    hostname: name.to_string(),
                    port: None,
                    context,
                    config_line: None,
                });
            }
            for proxy in proxy_re.captures_iter(block) {
                let Some(target) = proxy.get(1).map(|value| value.as_str()) else {
                    continue;
                };
                let Some((hostname, port)) = Self::parse_target(target) else {
                    continue;
                };
                refs.push(ConfigReference {
                    file_path: path.display().to_string(),
                    hostname,
                    port,
                    context: "caddy reverse_proxy".to_string(),
                    config_line: None,
                });
            }
        }
        Ok(refs)
    }

    fn parse_target(target: &str) -> Option<(String, Option<u16>)> {
        let target = target.trim().trim_matches('"').trim_matches('\'');
        let target = target
            .strip_prefix("http://")
            .or_else(|| target.strip_prefix("https://"))
            .unwrap_or(target);
        let (hostname, port) = target
            .rsplit_once(':')
            .filter(|(_, port)| port.parse::<u16>().is_ok())
            .map(|(hostname, port)| (hostname, port.parse().ok()))
            .unwrap_or((target, None));
        Self::is_valid_hostname(hostname).then(|| (hostname.to_string(), port))
    }

    fn scan_php_fpm() -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let php_dirs = vec!["/etc/php", "/etc/php-fpm.d"];

        for dir in php_dirs {
            if Path::new(dir).exists() {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        if let Ok(path) = entry.path().canonicalize() {
                            if path.is_file() && path.to_string_lossy().ends_with(".conf") {
                                if let Ok(content) = fs::read_to_string(&path) {
                                    refs.extend(Self::parse_php_config(&path, &content)?);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(refs)
    }

    fn parse_php_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let listen_re = Regex::new(r"(?m)listen\s*=\s*([^\s]+)")?;

        for caps in listen_re.captures_iter(content) {
            if let Some(addr) = caps.get(1) {
                let addr_str = addr.as_str();
                if addr_str.contains(':') && !addr_str.starts_with('/') {
                    if let Some(colon_pos) = addr_str.rfind(':') {
                        let hostname = addr_str[..colon_pos].to_string();
                        let port = addr_str[colon_pos + 1..].parse().ok();

                        if Self::is_valid_hostname(&hostname) && hostname != "127.0.0.1" {
                            refs.push(ConfigReference {
                                file_path: path.display().to_string(),
                                hostname,
                                port,
                                context: "PHP-FPM listen".to_string(),
                                config_line: None,
                            });
                        }
                    }
                }
            }
        }

        Ok(refs)
    }

    fn scan_app_configs() -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let config_patterns = vec![
            "/var/www/*/wp-config.php",
            "/var/www/*/.env",
            "/opt/*/config.ini",
            "/opt/*/config.yaml",
            "/opt/*/config.json",
            "/etc/app/config.ini",
            "/app/.env",
            "/app/config/*.yaml",
            "/app/config/*.yml",
            "/srv/*/config.yaml",
            "/home/*/app/.env",
        ];

        for pattern in config_patterns {
            if let Ok(entries) = glob::glob(pattern) {
                for entry in entries.flatten() {
                    if let Ok(content) = fs::read_to_string(&entry) {
                        refs.extend(Self::parse_app_config(&entry, &content)?);
                    }
                }
            }
        }

        Ok(refs)
    }

    fn parse_app_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let db_host_re = Regex::new(
            "(?mi)(?:DB_HOST|db_host|database\\.host|mysql\\.host|postgres\\.host|DATABASES.*host)\\s*[=:]\\s*[\"']?([^\\s;,\"'\\n}]+)"
        )?;
        let redis_re = Regex::new(
            "(?mi)(?:REDIS_HOST|CACHE_URL|redis\\.host|cache\\.redis)\\s*[=:]\\s*[\"']?([^\\s;,\"'\\n}]+)"
        )?;
        let api_re = Regex::new(
            "(?mi)(?:API_URL|api_url|api\\.base|api\\.endpoint|SERVICE_URL)\\s*[=:]\\s*[\"']?([^\\s;,\"'\\n}]+)",
        )?;
        let es_re = Regex::new(
            "(?mi)(?:ELASTICSEARCH|ELASTIC_URL|SEARCH_HOST)\\s*[=:]\\s*[\"']?([^\\s;,\"'\\n}]+)",
        )?;
        let storage_re = Regex::new(
            "(?mi)(?:S3_ENDPOINT|S3_URL|AWS_S3_ENDPOINT|MINIO_ENDPOINT|OBJECT_STORAGE_URL)\\s*[=:]\\s*[\"']?([^\\s;,\"'\\n}]+)"
        )?;

        let patterns = vec![
            (db_host_re, "Database host", Some(3306)),
            (redis_re, "Cache/Redis host", Some(6379)),
            (api_re, "API endpoint", None),
            (es_re, "Elasticsearch host", Some(9200)),
            (storage_re, "Object storage endpoint", Some(9000)),
        ];

        for (re, context, default_port) in patterns {
            for caps in re.captures_iter(content) {
                if let Some(host_match) = caps.get(1) {
                    let host_str = host_match
                        .as_str()
                        .trim_matches(|c: char| c == '"' || c == '\'' || c == ' ');

                    if host_str.starts_with("http://") || host_str.starts_with("https://") {
                        if let Ok(parsed) = url::Url::parse(host_str) {
                            if let Some(host) = parsed.host_str() {
                                let hostname = host.to_string();
                                let port = parsed.port().or(default_port);
                                if Self::is_valid_hostname(&hostname) {
                                    refs.push(ConfigReference {
                                        file_path: path.display().to_string(),
                                        hostname: hostname.clone(),
                                        port,
                                        context: context.to_string(),
                                        config_line: Some(format!(
                                            "setting={} scheme={} host={} port={:?}",
                                            context,
                                            parsed.scheme(),
                                            hostname,
                                            port
                                        )),
                                    });
                                }
                            }
                        }
                    } else if Self::is_valid_hostname(host_str) {
                        let port = if host_str.contains(':') {
                            host_str.split(':').next_back().and_then(|p| p.parse().ok())
                        } else {
                            default_port
                        };

                        let hostname = host_str.split(':').next().unwrap_or(host_str).to_string();
                        refs.push(ConfigReference {
                            file_path: path.display().to_string(),
                            hostname: hostname.clone(),
                            port,
                            context: context.to_string(),
                            config_line: Some(format!(
                                "setting={} host={} port={:?}",
                                context, hostname, port
                            )),
                        });
                    }
                }
            }
        }

        Ok(refs)
    }

    fn scan_env_files() -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let env_paths = vec![
            "/etc/environment",
            "/root/.env",
            "/home/*/.env",
            "/var/www/*/.env",
            "/opt/*/.env",
        ];

        for pattern in env_paths {
            if let Ok(entries) = glob::glob(pattern) {
                for entry in entries.flatten() {
                    if let Ok(content) = fs::read_to_string(&entry) {
                        refs.extend(Self::parse_env_file(&entry, &content)?);
                    }
                }
            }
        }

        Ok(refs)
    }

    fn parse_env_file(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let env_var_re = Regex::new(r"(?m)^([A-Z_]+)=(.*)$")?;

        for caps in env_var_re.captures_iter(content) {
            if let (Some(key), Some(value)) = (caps.get(1), caps.get(2)) {
                let key_str = key.as_str();
                let val_str = value.as_str().trim_matches(|c| c == '"' || c == '\'');

                if Self::is_host_env_key(key_str) {
                    if let Some((hostname, port)) = Self::parse_host_value(val_str, None) {
                        refs.push(ConfigReference {
                            file_path: path.display().to_string(),
                            hostname: hostname.clone(),
                            port,
                            context: format!("Environment: {}", key_str),
                            config_line: Some(format!(
                                "setting={} host={} port={:?}",
                                key_str, hostname, port
                            )),
                        });
                    }
                } else if Self::is_url_env_key(key_str) {
                    if let Ok(parsed) = url::Url::parse(val_str) {
                        if let Some(hostname) = parsed.host_str() {
                            if Self::is_valid_hostname(hostname) {
                                let port = parsed.port();
                                refs.push(ConfigReference {
                                    file_path: path.display().to_string(),
                                    hostname: hostname.to_string(),
                                    port,
                                    context: format!(
                                        "Environment URL: {} (scheme={})",
                                        key_str,
                                        parsed.scheme()
                                    ),
                                    config_line: Some(format!(
                                        "setting={} scheme={} host={} port={:?}",
                                        key_str,
                                        parsed.scheme(),
                                        hostname,
                                        port
                                    )),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(refs)
    }

    fn is_host_env_key(key: &str) -> bool {
        matches!(
            key,
            "DB_HOST"
                | "DATABASE_HOST"
                | "MYSQL_HOST"
                | "POSTGRES_HOST"
                | "REDIS_HOST"
                | "CACHE_HOST"
                | "API_HOST"
                | "SMTP_HOST"
                | "MAIL_HOST"
                | "SEARCH_HOST"
                | "ELASTICSEARCH_HOST"
                | "BROKER_HOST"
                | "QUEUE_HOST"
        )
    }

    fn is_url_env_key(key: &str) -> bool {
        matches!(
            key,
            "URL"
                | "API_URL"
                | "SERVICE_URL"
                | "DATABASE_URL"
                | "DB_URL"
                | "REDIS_URL"
                | "CACHE_URL"
                | "SMTP_URL"
                | "BROKER_URL"
        )
    }

    fn parse_host_value(value: &str, default_port: Option<u16>) -> Option<(String, Option<u16>)> {
        let value = value.trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace());
        let (hostname, port) = value
            .rsplit_once(':')
            .filter(|(_, port)| port.parse::<u16>().is_ok())
            .map(|(hostname, port)| (hostname, port.parse().ok()))
            .unwrap_or((value, default_port));
        Self::is_valid_hostname(hostname).then(|| (hostname.to_string(), port))
    }

    fn scan_database_configs() -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let db_config_paths = vec![
            "/etc/mysql/my.cnf",
            "/etc/postgresql/postgresql.conf",
            "/etc/mariadb/my.cnf",
        ];

        for path in db_config_paths {
            if let Ok(content) = fs::read_to_string(path) {
                refs.extend(Self::parse_database_config(Path::new(path), &content)?);
            }
        }

        Ok(refs)
    }

    fn parse_database_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let bind_re = Regex::new(r"(?m)bind-address\s*=\s*([^\s\n]+)")?;

        for caps in bind_re.captures_iter(content) {
            if let Some(addr) = caps.get(1) {
                let addr_str = addr.as_str();
                if addr_str != "127.0.0.1" && addr_str != "localhost" {
                    refs.push(ConfigReference {
                        file_path: path.display().to_string(),
                        hostname: addr_str.to_string(),
                        port: Some(3306),
                        context: "Database bind address".to_string(),
                        config_line: None,
                    });
                }
            }
        }

        Ok(refs)
    }

    fn is_valid_hostname(s: &str) -> bool {
        if s.is_empty() || s.len() > 255 {
            return false;
        }

        if s.starts_with('.') || s.ends_with('.') {
            return false;
        }

        if s.starts_with('/') {
            return false;
        }

        s.chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigScanner;
    use std::path::Path;

    #[test]
    fn env_scanner_only_accepts_host_keys_and_urls() {
        let refs = ConfigScanner::parse_env_file(
            Path::new("/tmp/test.env"),
            "DB_NAME=wordpress\nDB_PASSWORD=secret\nDB_HOST=db01:3306\nAPI_URL=https://api.example.com/v1?token=secret\n",
        ).unwrap();

        assert_eq!(refs.len(), 2);
        assert!(refs.iter().any(|reference| reference.hostname == "db01"));
        assert!(refs
            .iter()
            .any(|reference| reference.hostname == "api.example.com"));
        assert!(refs.iter().all(|reference| {
            reference
                .config_line
                .as_deref()
                .unwrap_or("")
                .contains("host=")
        }));
    }

    #[test]
    fn nginx_scanner_extracts_site_names_and_content_roots() {
        let refs = ConfigScanner::parse_nginx_config(
            Path::new("/etc/nginx/sites-enabled/example"),
            "server { server_name example.com www.example.com; root /srv/example/public; }",
        )
        .unwrap();

        assert_eq!(
            refs.iter()
                .filter(|reference| reference.context.starts_with("nginx site"))
                .count(),
            2
        );
        assert!(refs
            .iter()
            .any(|reference| reference.hostname == "example.com"
                && reference.context.contains("root=/srv/example/public")));
    }

    #[test]
    fn apache_scanner_extracts_virtual_hosts_and_proxy_targets() {
        let refs = ConfigScanner::parse_apache_config(
            Path::new("/etc/apache2/sites-enabled/example.conf"),
            "<VirtualHost *:443>\nServerName example.com\nServerAlias www.example.com\nDocumentRoot /srv/example/public\nProxyPass /api http://api.internal:8080\n</VirtualHost>",
        )
        .unwrap();

        assert!(refs.iter().any(|reference| {
            reference.hostname == "example.com"
                && reference.context.contains("root=/srv/example/public")
                && reference.context.contains("ports=443")
        }));
        assert!(refs.iter().any(|reference| {
            reference.hostname == "api.internal"
                && reference.port == Some(8080)
                && reference.context == "apache proxy_pass"
        }));
    }

    #[test]
    fn haproxy_scanner_extracts_backend_servers() {
        let refs = ConfigScanner::parse_haproxy_config(
            Path::new("/etc/haproxy/haproxy.cfg"),
            "backend app\n  server app01 app.internal:8080 check",
        )
        .unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].hostname, "app.internal");
        assert_eq!(refs[0].port, Some(8080));
        assert_eq!(refs[0].context, "haproxy backend");
    }

    #[test]
    fn traefik_scanner_extracts_service_urls() {
        let refs = ConfigScanner::parse_traefik_config(
            Path::new("/etc/traefik/dynamic.yml"),
            "http:\n  services:\n    app:\n      loadBalancer:\n        servers:\n          - url: http://app.internal:8080",
        )
        .unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].hostname, "app.internal");
        assert_eq!(refs[0].port, Some(8080));
    }

    #[test]
    fn caddy_scanner_extracts_sites_and_reverse_proxy_targets() {
        let refs = ConfigScanner::parse_caddy_config(
            Path::new("/etc/caddy/Caddyfile"),
            "example.com {\n  root * /srv/example\n  reverse_proxy localhost:8080\n}",
        )
        .unwrap();

        assert!(refs.iter().any(|reference| {
            reference.hostname == "example.com" && reference.context.contains("root=/srv/example")
        }));
        assert!(refs.iter().any(|reference| {
            reference.hostname == "localhost"
                && reference.port == Some(8080)
                && reference.context == "caddy reverse_proxy"
        }));
    }

    #[test]
    fn app_url_evidence_excludes_credentials_and_query_strings() {
        let refs = ConfigScanner::parse_app_config(
            Path::new("/tmp/config.env"),
            "API_URL=https://user:password@example.com/api?token=secret",
        )
        .unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].hostname, "example.com");
        assert!(!refs[0].config_line.as_deref().unwrap().contains("password"));
        assert!(!refs[0].config_line.as_deref().unwrap().contains("token"));
    }
}
