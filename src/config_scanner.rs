use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use regex::Regex;

use crate::models::ConfigReference;

pub struct ConfigScanner;

impl ConfigScanner {
    pub fn scan() -> Result<Vec<ConfigReference>> {
        let mut references = Vec::new();

        references.extend(Self::scan_nginx()?);
        references.extend(Self::scan_php_fpm()?);
        references.extend(Self::scan_app_configs()?);
        references.extend(Self::scan_env_files()?);
        references.extend(Self::scan_database_configs()?);

        references.sort_by(|a, b| a.file_path.cmp(&b.file_path));
        references.dedup_by(|a, b| {
            a.file_path == b.file_path && a.hostname == b.hostname
        });

        Ok(references)
    }

    fn scan_nginx() -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let nginx_dirs = vec!["/etc/nginx", "/etc/nginx/sites-available", "/etc/nginx/sites-enabled"];

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
            "(?mi)(?:ELASTICSEARCH|ELASTIC_URL|SEARCH_HOST)\\s*[=:]\\s*[\"']?([^\\s;,\"'\\n}]+)"
        )?;

        let patterns = vec![
            (db_host_re, "Database host", Some(3306)),
            (redis_re, "Cache/Redis host", Some(6379)),
            (api_re, "API endpoint", None),
            (es_re, "Elasticsearch host", Some(9200)),
        ];

        for (re, context, default_port) in patterns {
            for caps in re.captures_iter(content) {
                if let Some(host_match) = caps.get(1) {
                    let host_str = host_match.as_str().trim_matches(|c: char| c == '"' || c == '\'' || c == ' ');

                    if host_str.starts_with("http://") || host_str.starts_with("https://") {
                        if let Ok(parsed) = url::Url::parse(host_str) {
                            if let Some(host) = parsed.host_str() {
                                let hostname = host.to_string();
                                let port = parsed.port().or(default_port);
                                if Self::is_valid_hostname(&hostname) {
                                    refs.push(ConfigReference {
                                        file_path: path.display().to_string(),
                                        hostname,
                                        port,
                                        context: context.to_string(),
                                        config_line: Some(host_str.to_string()),
                                    });
                                }
                            }
                        }
                    } else if Self::is_valid_hostname(host_str) {
                        let port = if host_str.contains(':') {
                            host_str.split(':').last().and_then(|p| p.parse().ok())
                        } else {
                            default_port
                        };

                        let hostname = host_str.split(':').next().unwrap_or(host_str).to_string();
                        refs.push(ConfigReference {
                            file_path: path.display().to_string(),
                            hostname,
                            port,
                            context: context.to_string(),
                            config_line: Some(host_str.to_string()),
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

                if (key_str.contains("HOST") || key_str.contains("SERVER") || key_str.contains("DB")) &&
                   Self::is_valid_hostname(val_str) {
                    refs.push(ConfigReference {
                        file_path: path.display().to_string(),
                        hostname: val_str.to_string(),
                        port: None,
                        context: format!("Environment: {}", key_str),
                        config_line: None,
                    });
                }
            }
        }

        Ok(refs)
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
