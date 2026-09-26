use anyhow::{Context, Result};
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::models::{ConfigReference, ConfigScanAudit};

pub struct ConfigScanner;

const MAX_CONFIG_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CONFIG_TREE_ENTRIES: usize = 20_000;
const MAX_CONFIG_TREE_DEPTH: usize = 32;
const MAX_AUDIT_ERRORS: usize = 100;
const SCANNER_VERSION: &str = "config-scanner/4";
const DB_HOST_REGEX: &str = r#"(?mi)(DB_HOST|DATABASE_HOST|database\.host|mysql\.host|postgres\.host|POSTGRES_HOST|DATABASES.*host)\s*[=:]\s*["']?([^\s;,"'\n}]+)"#;
const REDIS_HOST_REGEX: &str =
    r#"(?mi)(?:REDIS_HOST|CACHE_URL|redis\.host|cache\.redis)\s*[=:]\s*["']?([^\s;,"'\n}]+)"#;
const API_URL_REGEX: &str =
    r#"(?mi)(?:API_URL|api_url|api\.base|api\.endpoint|SERVICE_URL)\s*[=:]\s*["']?([^\s;,"'\n}]+)"#;
const SEARCH_HOST_REGEX: &str =
    r#"(?mi)(?:ELASTICSEARCH|ELASTIC_URL|SEARCH_HOST)\s*[=:]\s*["']?([^\s;,"'\n}]+)"#;
const STORAGE_ENDPOINT_REGEX: &str = r#"(?mi)(?:S3_ENDPOINT|S3_URL|AWS_S3_ENDPOINT|MINIO_ENDPOINT|OBJECT_STORAGE_URL)\s*[=:]\s*["']?([^\s;,"'\n}]+)"#;
const POSTGRES_LISTEN_REGEX: &str = r"(?mi)^\s*listen_addresses\s*=\s*([^\n]+)";
const DATABASE_PORT_REGEX: &str = r"(?mi)^\s*port\s*=\s*(\d+)\s*$";
const DATABASE_BIND_REGEX: &str = r"(?mi)^\s*bind-address\s*=\s*([^\s\n]+)";
const CONFIG_REGEX_PATTERNS: &[&str] = &[
    r"(?m)upstream\s+\w+\s*\{([^}]+)\}",
    r"(?m)server\s+([^\s;]+)(?::(\d+))?",
    r"proxy_pass\s+(?:https?://)?([^/:]+)(?::(\d+))?",
    r"\bserver_name\s+([^;]+);",
    r"\broot\s+([^;]+);",
    r"\blisten\s+([^;]+);",
    r"\bserver\s*\{",
    r"(?is)<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>",
    r"(?mi)^\s*ServerName\s+(\S+)",
    r"(?mi)^\s*ServerAlias\s+(.+)",
    r"(?mi)^\s*DocumentRoot\s+([^\s#]+)",
    r"(?mi)^\s*ProxyPass\s+\S+\s+(?:https?://)?([^/:\s]+)(?::(\d+))?",
    r"(?mi)^\s*server\s+\S+\s+(?:[a-z0-9_-]+@)?([^\s:]+)(?::(\d+))?",
    r##"(?mi)\burl\s*[:=]\s*["']?(?:https?://)?([^/:\s"']+)(?::(\d+))?"##,
    r"(?m)^\s*([^{}]+)\{([^}]*)\}",
    r"(?m)^\s*root\s+\S+\s+([^\s#]+)",
    r"(?m)^\s*reverse_proxy(?:\s+\S+)?\s+([^\s{,]+)",
    r"(?m)listen\s*=\s*([^\s]+)",
    DB_HOST_REGEX,
    REDIS_HOST_REGEX,
    API_URL_REGEX,
    SEARCH_HOST_REGEX,
    STORAGE_ENDPOINT_REGEX,
    r"(?m)^([A-Z_]+)=(.*)$",
    r"(?m)bind-address\s*=\s*([^\s\n]+)",
    POSTGRES_LISTEN_REGEX,
    DATABASE_PORT_REGEX,
    DATABASE_BIND_REGEX,
];
const SCAN_ROOTS: &[&str] = &[
    "/etc/nginx",
    "/etc/apache2",
    "/etc/httpd",
    "/etc/haproxy",
    "/etc/traefik",
    "/etc/caddy",
    "/etc/php",
    "/etc/php-fpm.d",
    "/etc/mysql",
    "/etc/my.cnf",
    "/etc/my.cnf.d",
    "/etc/postgresql",
    "/etc/mariadb",
    "/etc/app",
    "/etc/environment",
    "/var/www",
    "/opt",
    "/app",
    "/srv",
    "/home",
    "/root",
];
type ConfigScanFn = fn(&mut ScanContext) -> Result<Vec<ConfigReference>>;

#[derive(Default)]
struct ScanContext {
    audit: ConfigScanAudit,
    discovered: BTreeSet<PathBuf>,
    parsed: BTreeSet<PathBuf>,
    skipped: BTreeSet<PathBuf>,
    contents: HashMap<PathBuf, Option<String>>,
}

impl ScanContext {
    fn record_file_error(&mut self, path: &Path, error: &anyhow::Error) {
        let identity = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        self.discovered.insert(identity.clone());
        self.audit.files_discovered = self.discovered.len();
        if self.skipped.insert(identity) {
            self.audit.files_skipped += 1;
        }

        let permission_denied = error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .map(|io_error| io_error.kind() == std::io::ErrorKind::PermissionDenied)
                .unwrap_or(false)
        });
        if permission_denied {
            self.audit.permission_denied += 1;
        }

        if self.audit.errors.len() < MAX_AUDIT_ERRORS {
            self.audit
                .errors
                .push(format!("{}: {:#}", path.display(), error));
        } else {
            self.audit.errors_truncated += 1;
        }
    }

    fn record_scanner_error(&mut self, scanner: &str, error: &anyhow::Error) {
        let permission_denied = error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .map(|io_error| io_error.kind() == std::io::ErrorKind::PermissionDenied)
                .unwrap_or(false)
        });
        if permission_denied {
            self.audit.permission_denied += 1;
        }
        if self.audit.errors.len() < MAX_AUDIT_ERRORS {
            self.audit
                .errors
                .push(format!("{} scanner: {:#}", scanner, error));
        } else {
            self.audit.errors_truncated += 1;
        }
    }
}

impl ConfigScanner {
    fn compiled_regex(pattern: &'static str) -> &'static Regex {
        static REGEXES: OnceLock<HashMap<&'static str, Regex>> = OnceLock::new();
        REGEXES
            .get_or_init(|| {
                CONFIG_REGEX_PATTERNS
                    .iter()
                    .map(|pattern| {
                        (
                            *pattern,
                            Regex::new(pattern).expect("static config scanner regex is valid"),
                        )
                    })
                    .collect()
            })
            .get(pattern)
            .expect("config scanner regex is registered")
    }

    fn path_is_within_search_root(path: &Path, canonical_path: &Path, roots: &[&str]) -> bool {
        roots
            .iter()
            .map(Path::new)
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
            .map(|root| Self::path_is_within_root(path, canonical_path, root))
            .unwrap_or(false)
    }

    fn path_is_within_root(path: &Path, canonical_path: &Path, root: &Path) -> bool {
        path.starts_with(root)
            && root
                .canonicalize()
                .map(|canonical_root| canonical_path.starts_with(canonical_root))
                .unwrap_or(false)
    }

    fn scan_with_context(context: &mut ScanContext) -> Vec<ConfigReference> {
        let mut references = Vec::new();
        let scanners: [(&str, ConfigScanFn); 9] = [
            ("nginx", Self::scan_nginx),
            ("apache", Self::scan_apache),
            ("haproxy", Self::scan_haproxy),
            ("traefik", Self::scan_traefik),
            ("caddy", Self::scan_caddy),
            ("php-fpm", Self::scan_php_fpm),
            ("application", Self::scan_app_configs),
            ("environment", Self::scan_env_files),
            ("database", Self::scan_database_configs),
        ];
        for (name, scan) in scanners {
            match scan(context) {
                Ok(found) => references.extend(found),
                Err(error) => context.record_scanner_error(name, &error),
            }
        }

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

        references
    }

    pub fn scan_with_audit() -> Result<(Vec<ConfigReference>, ConfigScanAudit)> {
        let paths_searched = Self::searched_path_descriptions();
        let mut context = ScanContext::default();
        let references = Self::scan_with_context(&mut context);
        context.audit.scanner_version = SCANNER_VERSION.to_string();
        context.audit.paths_searched = paths_searched.into_iter().map(str::to_string).collect();
        context.audit.syntax_validation =
            "not performed; extraction uses pattern-based directives".to_string();
        Ok((references, context.audit))
    }

    fn searched_path_descriptions() -> Vec<&'static str> {
        vec![
            "/etc/nginx/** (recursive; disabled sites-available files excluded)",
            "/etc/apache2/** and /etc/httpd/** (recursive; sites-available files included only through enabled links)",
            "/etc/haproxy/** (recursive)",
            "/etc/traefik/** (recursive)",
            "/etc/caddy/** (recursive)",
            "/etc/php/**/*.conf and /etc/php-fpm.d/**/*.conf (recursive)",
            "/var/www/*/wp-config.php",
            "/var/www/*/.env",
            "/opt/*/config.ini|config.yaml|config.json",
            "/etc/app/config.ini",
            "/app/.env",
            "/app/config/*.yaml|*.yml",
            "/srv/*/config.yaml",
            "/home/*/app/.env",
            "/etc/environment",
            "/root/.env",
            "/home/*/.env",
            "/opt/*/.env",
            "/etc/mysql/**/*.cnf (recursive)",
            "/etc/my.cnf and /etc/my.cnf.d/**/*.cnf (recursive)",
            "/etc/postgresql/**/postgresql.conf (recursive; versioned clusters)",
            "/etc/mariadb/**/*.cnf (recursive)",
        ]
    }

    fn scan_nginx(context: &mut ScanContext) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        for path in Self::config_files_under(Path::new("/etc/nginx"))? {
            let Some(content) = Self::read_config_file(&path, context) else {
                continue;
            };
            refs.extend(Self::parse_nginx_config(&path, &content)?);
        }

        Ok(refs)
    }

    fn parse_nginx_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let content = Self::strip_comments(content, '#');
        let mut refs = Vec::new();

        let upstream_re = Self::compiled_regex(r"(?m)upstream\s+\w+\s*\{([^}]+)\}");
        let server_re = Self::compiled_regex(r"(?m)server\s+([^\s;]+)(?::(\d+))?");
        let proxy_re = Self::compiled_regex(r"proxy_pass\s+(?:https?://)?([^/:]+)(?::(\d+))?");
        let name_re = Self::compiled_regex(r"\bserver_name\s+([^;]+);");
        let root_re = Self::compiled_regex(r"\broot\s+([^;]+);");
        let listen_re = Self::compiled_regex(r"\blisten\s+([^;]+);");

        for block in Self::nginx_server_blocks(&content)? {
            let directives = Self::nginx_direct_scope(block);
            let root = root_re
                .captures(&directives)
                .and_then(|capture| capture.get(1))
                .map(|value| value.as_str().trim().to_string());
            let has_listen_directive = listen_re.is_match(&directives);
            let mut ports = listen_re
                .captures_iter(&directives)
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
            // Nginx HTTP server blocks default to port 80 when no listen
            // directive is present. Preserve that port so virtual hosts using
            // the implicit listener are recognized as sharing it.
            if ports.is_empty() && !has_listen_directive {
                ports.push(80);
            }
            if let Some(names) = name_re
                .captures(&directives)
                .and_then(|capture| capture.get(1))
            {
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

        for caps in upstream_re.captures_iter(&content) {
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

        for caps in proxy_re.captures_iter(&content) {
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

    fn nginx_server_blocks(content: &str) -> Result<Vec<&str>> {
        let server_start_re = Self::compiled_regex(r"\bserver\s*\{");
        let mut blocks = Vec::new();
        for start in server_start_re.find_iter(content) {
            let open_brace = start.end() - 1;
            let block_start = open_brace + 1;
            let mut depth = 1usize;
            let mut quote = None;
            let mut escaped = false;
            for (relative, character) in content[block_start..].char_indices() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if quote.is_some() && character == '\\' {
                    escaped = true;
                    continue;
                }
                if let Some(quote_character) = quote {
                    if character == quote_character {
                        quote = None;
                    }
                    continue;
                }
                match character {
                    '\'' | '"' => quote = Some(character),
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            blocks.push(&content[block_start..block_start + relative]);
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(blocks)
    }

    /// Masks nested Nginx scopes so site-level fields (e.g. `root`) are not
    /// accidentally taken from a `location` block.
    fn nginx_direct_scope(block: &str) -> String {
        let mut output = String::with_capacity(block.len());
        let mut depth = 0usize;
        let mut quote = None;
        let mut escaped = false;
        for character in block.chars() {
            if escaped {
                if depth == 0 {
                    output.push(character);
                } else {
                    output.push(if character == '\n' { '\n' } else { ' ' });
                }
                escaped = false;
                continue;
            }
            if quote.is_some() && character == '\\' {
                if depth == 0 {
                    output.push(character);
                } else {
                    output.push(' ');
                }
                escaped = true;
                continue;
            }
            if let Some(quote_character) = quote {
                if depth == 0 {
                    output.push(character);
                } else {
                    output.push(if character == '\n' { '\n' } else { ' ' });
                }
                if character == quote_character {
                    quote = None;
                }
                continue;
            }
            match character {
                '\'' | '"' => {
                    quote = Some(character);
                    output.push(if depth == 0 { character } else { ' ' });
                }
                '{' => {
                    depth += 1;
                    output.push(' ');
                }
                '}' => {
                    depth = depth.saturating_sub(1);
                    output.push(' ');
                }
                _ if depth == 0 => output.push(character),
                _ => output.push(if character == '\n' { '\n' } else { ' ' }),
            }
        }
        output
    }

    fn scan_apache(context: &mut ScanContext) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();
        for dir in Self::apache_config_roots(Path::new("/etc/apache2"), Path::new("/etc/httpd")) {
            for path in Self::config_files_under(&dir)? {
                let Some(content) = Self::read_config_file(&path, context) else {
                    continue;
                };
                refs.extend(Self::parse_apache_config(&path, &content)?);
            }
        }
        Ok(refs)
    }

    fn apache_config_roots(apache2_root: &Path, httpd_root: &Path) -> [PathBuf; 2] {
        [apache2_root.to_path_buf(), httpd_root.to_path_buf()]
    }

    fn parse_apache_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let content = Self::strip_comments(content, '#');
        let mut refs = Vec::new();
        let vhost_re = Self::compiled_regex(r"(?is)<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>");
        let name_re = Self::compiled_regex(r"(?mi)^\s*ServerName\s+(\S+)");
        let alias_re = Self::compiled_regex(r"(?mi)^\s*ServerAlias\s+(.+)");
        let root_re = Self::compiled_regex(r"(?mi)^\s*DocumentRoot\s+([^\s#]+)");
        let proxy_re =
            Self::compiled_regex(r"(?mi)^\s*ProxyPass\s+\S+\s+(?:https?://)?([^/:\s]+)(?::(\d+))?");

        for capture in vhost_re.captures_iter(&content) {
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

    fn scan_haproxy(context: &mut ScanContext) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();
        for path in Self::config_files_under(Path::new("/etc/haproxy"))? {
            let Some(content) = Self::read_config_file(&path, context) else {
                continue;
            };
            refs.extend(Self::parse_haproxy_config(&path, &content)?);
        }
        Ok(refs)
    }

    fn parse_haproxy_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let content = Self::strip_comments(content, '#');
        let server_re =
            Self::compiled_regex(r"(?mi)^\s*server\s+\S+\s+(?:[a-z0-9_-]+@)?([^\s:]+)(?::(\d+))?");
        let mut refs = Vec::new();
        for capture in server_re.captures_iter(&content) {
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

    fn scan_traefik(context: &mut ScanContext) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();
        for path in Self::config_files_under(Path::new("/etc/traefik"))? {
            let Some(content) = Self::read_config_file(&path, context) else {
                continue;
            };
            refs.extend(Self::parse_traefik_config(&path, &content)?);
        }
        Ok(refs)
    }

    fn parse_traefik_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let content = Self::strip_comments(content, '#');
        let url_re = Self::compiled_regex(
            r##"(?mi)\burl\s*[:=]\s*["']?(?:https?://)?([^/:\s"']+)(?::(\d+))?"##,
        );
        let mut refs = Vec::new();
        for capture in url_re.captures_iter(&content) {
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

    fn scan_caddy(context: &mut ScanContext) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();
        for path in Self::config_files_under(Path::new("/etc/caddy"))? {
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if file_name.eq_ignore_ascii_case("caddyfile") {
                let Some(content) = Self::read_config_file(&path, context) else {
                    continue;
                };
                refs.extend(Self::parse_caddy_config(&path, &content)?);
            }
        }
        Ok(refs)
    }

    fn parse_caddy_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let content = Self::strip_comments(content, '#');
        let site_re = Self::compiled_regex(r"(?m)^\s*([^{}]+)\{([^}]*)\}");
        let root_re = Self::compiled_regex(r"(?m)^\s*root\s+\S+\s+([^\s#]+)");
        let proxy_re = Self::compiled_regex(r"(?m)^\s*reverse_proxy(?:\s+\S+)?\s+([^\s{,]+)");
        let mut refs = Vec::new();

        for site in site_re.captures_iter(&content) {
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
        Self::parse_endpoint(target, None)
    }

    fn parse_endpoint(value: &str, default_port: Option<u16>) -> Option<(String, Option<u16>)> {
        let value = value.trim().trim_matches('"').trim_matches('\'');
        if value.is_empty() || value.starts_with('/') || value.starts_with("unix://") {
            return None;
        }

        if value.contains("://") {
            let (scheme, hostname, port) = Self::parse_url_endpoint(value)?;
            return Some((
                hostname,
                port.or(default_port)
                    .or_else(|| Self::default_port_for_scheme(&scheme)),
            ));
        }

        let (hostname, port) = if value.starts_with('[') {
            let closing = value.find(']')?;
            let hostname = &value[1..closing];
            let port = match value[closing + 1..].strip_prefix(':') {
                Some(port) => Some(port.parse::<u16>().ok()?),
                None => default_port,
            };
            (hostname, port)
        } else if value.parse::<std::net::IpAddr>().is_ok() {
            (value, default_port)
        } else if let Some((hostname, port)) = value.rsplit_once(':') {
            if !hostname.contains(':') && port.parse::<u16>().is_ok() {
                (hostname, port.parse::<u16>().ok())
            } else {
                (value, default_port)
            }
        } else {
            (value, default_port)
        };

        (Self::is_valid_hostname(hostname) || hostname.parse::<std::net::IpAddr>().is_ok())
            .then(|| (hostname.to_string(), port))
    }

    fn parse_url_endpoint(value: &str) -> Option<(String, String, Option<u16>)> {
        let (scheme, remainder) = value.split_once("://")?;
        let mut scheme_chars = scheme.chars();
        if !scheme_chars.next()?.is_ascii_alphabetic()
            || !scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
        {
            return None;
        }

        let authority = remainder.split(['/', '?', '#']).next()?;
        if authority.is_empty() || authority.chars().any(char::is_whitespace) {
            return None;
        }
        let host_port = authority.rsplit('@').next()?;
        let (hostname, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
            let closing = bracketed.find(']')?;
            let hostname = &bracketed[..closing];
            let suffix = &bracketed[closing + 1..];
            let port = if suffix.is_empty() {
                None
            } else {
                Some(suffix.strip_prefix(':')?.parse::<u16>().ok()?)
            };
            (hostname, port)
        } else if let Some((hostname, port)) = host_port.rsplit_once(':') {
            if hostname.contains(':') {
                return None;
            }
            (hostname, Some(port.parse::<u16>().ok()?))
        } else {
            (host_port, None)
        };

        let valid_host =
            Self::is_valid_hostname(hostname) || hostname.parse::<std::net::IpAddr>().is_ok();
        valid_host.then(|| (scheme.to_ascii_lowercase(), hostname.to_string(), port))
    }

    fn default_port_for_key(key: &str) -> Option<u16> {
        let key = key.to_ascii_lowercase();
        if key.contains("postgres") {
            Some(5432)
        } else if key.contains("mysql") || key == "db_host" || key == "database_host" {
            Some(3306)
        } else {
            None
        }
    }

    fn default_port_for_scheme(scheme: &str) -> Option<u16> {
        match scheme.to_ascii_lowercase().as_str() {
            "http" => Some(80),
            "https" => Some(443),
            "mysql" | "mariadb" => Some(3306),
            "postgres" | "postgresql" => Some(5432),
            "redis" | "rediss" => Some(6379),
            "mongodb" | "mongodb+srv" => Some(27017),
            "amqp" => Some(5672),
            _ => None,
        }
    }

    fn scan_php_fpm(context: &mut ScanContext) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        for root in [Path::new("/etc/php"), Path::new("/etc/php-fpm.d")] {
            for path in Self::config_files_under(root)? {
                if path.to_string_lossy().ends_with(".conf") {
                    let Some(content) = Self::read_config_file(&path, context) else {
                        continue;
                    };
                    refs.extend(Self::parse_php_config(&path, &content)?);
                }
            }
        }

        Ok(refs)
    }

    fn parse_php_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let content = Self::strip_comments(content, ';');
        let mut refs = Vec::new();

        let listen_re = Self::compiled_regex(r"(?m)listen\s*=\s*([^\s]+)");

        for caps in listen_re.captures_iter(&content) {
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

    fn scan_app_configs(context: &mut ScanContext) -> Result<Vec<ConfigReference>> {
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
            let entries =
                glob::glob(pattern).with_context(|| format!("Invalid config glob {}", pattern))?;
            for entry in entries {
                let entry = entry.with_context(|| format!("Unable to enumerate {}", pattern))?;
                if entry.file_name().and_then(|name| name.to_str()) == Some(".env") {
                    continue;
                }
                let Some(content) = Self::read_config_file(&entry, context) else {
                    continue;
                };
                refs.extend(Self::parse_app_config(&entry, &content)?);
            }
        }

        Ok(refs)
    }

    fn parse_app_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let content = Self::strip_comments(content, '#');
        let mut refs = Vec::new();

        let db_host_re = Self::compiled_regex(DB_HOST_REGEX);
        let redis_re = Self::compiled_regex(REDIS_HOST_REGEX);
        let api_re = Self::compiled_regex(API_URL_REGEX);
        let es_re = Self::compiled_regex(SEARCH_HOST_REGEX);
        let storage_re = Self::compiled_regex(STORAGE_ENDPOINT_REGEX);

        let patterns = vec![
            (db_host_re, "Database host", None),
            (redis_re, "Cache/Redis host", Some(6379)),
            (api_re, "API endpoint", None),
            (es_re, "Elasticsearch host", Some(9200)),
            (storage_re, "Object storage endpoint", Some(9000)),
        ];

        for (re, context, default_port) in patterns {
            for caps in re.captures_iter(&content) {
                let host_match = if context == "Database host" {
                    caps.get(2)
                } else {
                    caps.get(1)
                };
                if let Some(host_match) = host_match {
                    let host_str = host_match
                        .as_str()
                        .trim_matches(|c: char| c == '"' || c == '\'' || c == ' ');

                    let default_port = if context == "Database host" {
                        caps.get(1)
                            .and_then(|key| Self::default_port_for_key(key.as_str()))
                    } else {
                        default_port
                    };
                    if let Some((hostname, port)) = Self::parse_endpoint(host_str, default_port) {
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

    fn config_files_under(root: &Path) -> Result<Vec<PathBuf>> {
        Self::config_files_under_with_limits(root, MAX_CONFIG_TREE_ENTRIES, MAX_CONFIG_TREE_DEPTH)
    }

    fn config_files_under_with_limits(
        root: &Path,
        max_entries: usize,
        max_depth: usize,
    ) -> Result<Vec<PathBuf>> {
        if !root.exists() {
            return Ok(Vec::new());
        }

        let mut files = Vec::new();
        let mut entries_seen = 0;
        let boundary = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        Self::collect_config_files(
            root,
            &boundary,
            &mut files,
            &mut entries_seen,
            0,
            max_entries,
            max_depth,
        )?;
        Ok(files)
    }

    fn collect_config_files(
        root: &Path,
        boundary: &Path,
        files: &mut Vec<PathBuf>,
        entries_seen: &mut usize,
        depth: usize,
        max_entries: usize,
        max_depth: usize,
    ) -> Result<()> {
        for entry in fs::read_dir(root)
            .with_context(|| format!("Unable to read config directory {}", root.display()))?
        {
            let entry = entry.with_context(|| {
                format!("Unable to enumerate config directory {}", root.display())
            })?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            *entries_seen = entries_seen.saturating_add(1);
            if *entries_seen > max_entries {
                anyhow::bail!(
                    "Configuration tree at {} exceeded the {} entry scan limit",
                    root.display(),
                    max_entries
                );
            }
            if file_type.is_dir() {
                if depth >= max_depth {
                    anyhow::bail!(
                        "Configuration tree at {} exceeded the {} directory depth limit",
                        path.display(),
                        max_depth
                    );
                }
                Self::collect_config_files(
                    &path,
                    boundary,
                    files,
                    entries_seen,
                    depth + 1,
                    max_entries,
                    max_depth,
                )?;
            } else if file_type.is_file() || file_type.is_symlink() {
                let canonical = path
                    .canonicalize()
                    .with_context(|| format!("Unable to resolve config path {}", path.display()))?;
                let disabled = path.components().any(|component| {
                    component.as_os_str() == std::ffi::OsStr::new("sites-available")
                });
                if canonical.starts_with(boundary) && canonical.is_file() && !disabled {
                    files.push(canonical);
                }
            }
        }
        Ok(())
    }

    fn scan_env_files(context: &mut ScanContext) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();

        let env_paths = vec![
            "/etc/environment",
            "/root/.env",
            "/home/*/.env",
            "/var/www/*/.env",
            "/opt/*/.env",
        ];

        for pattern in env_paths {
            let entries = glob::glob(pattern)
                .with_context(|| format!("Invalid environment glob {}", pattern))?;
            for entry in entries {
                let entry = entry.with_context(|| format!("Unable to enumerate {}", pattern))?;
                let Some(content) = Self::read_config_file(&entry, context) else {
                    continue;
                };
                refs.extend(Self::parse_env_file(&entry, &content)?);
            }
        }

        Ok(refs)
    }

    fn parse_env_file(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let content = Self::strip_comments(content, '#');
        let mut refs = Vec::new();

        let env_var_re = Self::compiled_regex(r"(?m)^([A-Z_]+)=(.*)$");

        for caps in env_var_re.captures_iter(&content) {
            if let (Some(key), Some(value)) = (caps.get(1), caps.get(2)) {
                let key_str = key.as_str();
                let val_str = value.as_str().trim_matches(|c| c == '"' || c == '\'');

                if Self::is_host_env_key(key_str) {
                    if let Some((hostname, port)) =
                        Self::parse_endpoint(val_str, Self::default_port_for_key(key_str))
                    {
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
                    if let Some((scheme, hostname, port)) = Self::parse_url_endpoint(val_str) {
                        let port = port.or_else(|| Self::default_port_for_scheme(&scheme));
                        refs.push(ConfigReference {
                            file_path: path.display().to_string(),
                            hostname: hostname.clone(),
                            port,
                            context: format!("Environment URL: {} (scheme={})", key_str, scheme),
                            config_line: Some(format!(
                                "setting={} scheme={} host={} port={:?}",
                                key_str, scheme, hostname, port
                            )),
                        });
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

    fn scan_database_configs(context: &mut ScanContext) -> Result<Vec<ConfigReference>> {
        let mut refs = Vec::new();
        let standalone_mysql_config = Path::new("/etc/my.cnf");
        if standalone_mysql_config.is_file() {
            if let Some(content) = Self::read_config_file(standalone_mysql_config, context) {
                refs.extend(Self::parse_database_config(
                    standalone_mysql_config,
                    &content,
                )?);
            }
        }
        for root in [
            Path::new("/etc/mysql"),
            Path::new("/etc/my.cnf.d"),
            Path::new("/etc/postgresql"),
            Path::new("/etc/mariadb"),
        ] {
            for path in Self::config_files_under(root)? {
                let is_postgres = root == Path::new("/etc/postgresql");
                if !Self::is_supported_database_config_file(&path, is_postgres) {
                    continue;
                }
                let Some(content) = Self::read_config_file(&path, context) else {
                    continue;
                };
                refs.extend(Self::parse_database_config(&path, &content)?);
            }
        }

        Ok(refs)
    }

    fn is_supported_database_config_file(path: &Path, is_postgres: bool) -> bool {
        if is_postgres {
            matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("postgresql.conf" | "postgresql.auto.conf")
            )
        } else {
            path.file_name().and_then(|name| name.to_str()) == Some("my.cnf")
                || path.extension().and_then(|extension| extension.to_str()) == Some("cnf")
        }
    }

    fn parse_database_config(path: &Path, content: &str) -> Result<Vec<ConfigReference>> {
        let content = Self::strip_comments(content, '#');
        let mut refs = Vec::new();
        let is_postgres = path.starts_with("/etc/postgresql");
        let server_content = if is_postgres {
            content
        } else {
            Self::mysql_server_group_content(&content)
        };
        let default_port = if is_postgres { 5432 } else { 3306 };
        let port_re = Self::compiled_regex(DATABASE_PORT_REGEX);
        let port = port_re
            .captures_iter(&server_content)
            .filter_map(|capture| capture.get(1)?.as_str().parse::<u16>().ok())
            .filter(|port| *port != 0)
            .last()
            .unwrap_or(default_port);

        let address_re = if is_postgres {
            Self::compiled_regex(POSTGRES_LISTEN_REGEX)
        } else {
            Self::compiled_regex(DATABASE_BIND_REGEX)
        };

        for capture in address_re.captures_iter(&server_content) {
            let Some(value) = capture.get(1) else {
                continue;
            };
            let value = value
                .as_str()
                .trim()
                .trim_matches(|character| character == '\'' || character == '"');
            let addresses = if is_postgres {
                value.split(',').collect::<Vec<_>>()
            } else {
                vec![value]
            };
            for address in addresses {
                let address = address.trim();
                if address == "*" || address.eq_ignore_ascii_case("localhost") {
                    continue;
                }
                let Some((hostname, _)) = Self::parse_endpoint(address, None) else {
                    continue;
                };
                let Ok(ip) = hostname.parse::<std::net::IpAddr>() else {
                    refs.push(ConfigReference {
                        file_path: path.display().to_string(),
                        hostname,
                        port: Some(port),
                        context: "Database bind address".to_string(),
                        config_line: None,
                    });
                    continue;
                };
                if !ip.is_loopback() && !ip.is_unspecified() {
                    refs.push(ConfigReference {
                        file_path: path.display().to_string(),
                        hostname: hostname.to_string(),
                        port: Some(port),
                        context: "Database bind address".to_string(),
                        config_line: None,
                    });
                }
            }
        }

        Ok(refs)
    }

    fn mysql_server_group_content(content: &str) -> String {
        let mut in_server_group = false;
        let mut selected = String::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(group) = trimmed
                .strip_prefix('[')
                .and_then(|group| group.strip_suffix(']'))
            {
                let group = group.trim().to_ascii_lowercase();
                in_server_group = matches!(
                    group.as_str(),
                    "server" | "mysqld" | "mariadb" | "mariadbd" | "client-server"
                ) || group.starts_with("mysqld-")
                    || group.starts_with("mariadb-");
            } else if in_server_group {
                selected.push_str(line);
                selected.push('\n');
            }
        }
        selected
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

    fn read_config_file(path: &Path, context: &mut ScanContext) -> Option<String> {
        Self::read_config_file_with_roots(path, context, SCAN_ROOTS)
    }

    fn read_config_file_with_roots(
        path: &Path,
        context: &mut ScanContext,
        roots: &[&str],
    ) -> Option<String> {
        let identity = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if let Some(cached) = context.contents.get(&identity) {
            return cached.clone();
        }

        context.discovered.insert(identity.clone());
        context.audit.files_discovered = context.discovered.len();

        let result = (|| {
            if !Self::path_is_within_search_root(path, &identity, roots) {
                anyhow::bail!("Config path resolves outside configured scan roots");
            }

            // Pin the directory entry without following its final symlink or
            // opening a FIFO/device. Inspect that pinned inode before opening
            // its procfs descriptor for reading, avoiding pathname TOCTOU.
            let mut inspect_options = fs::OpenOptions::new();
            inspect_options.read(true);
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::OpenOptionsExt;
                inspect_options.custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            let inspect_file = inspect_options
                .open(path)
                .with_context(|| format!("Unable to inspect config file {}", path.display()))?;
            let metadata = inspect_file
                .metadata()
                .with_context(|| format!("Unable to stat config file {}", path.display()))?;
            if !metadata.is_file() {
                anyhow::bail!("Config path is not a regular file: {}", path.display());
            }

            #[cfg(target_os = "linux")]
            let descriptor_path = {
                use std::os::fd::AsRawFd;
                PathBuf::from(format!("/proc/self/fd/{}", inspect_file.as_raw_fd()))
            };
            #[cfg(not(target_os = "linux"))]
            let descriptor_path = path.to_path_buf();
            let opened_path = fs::canonicalize(&descriptor_path).with_context(|| {
                format!("Unable to resolve opened config file {}", path.display())
            })?;
            if !Self::path_is_within_search_root(&opened_path, &opened_path, roots) {
                anyhow::bail!("Opened config file resolves outside configured scan roots");
            }
            if metadata.len() > MAX_CONFIG_FILE_BYTES {
                anyhow::bail!(
                    "Config file exceeds {} byte limit: {}",
                    MAX_CONFIG_FILE_BYTES,
                    path.display()
                );
            }
            let mut file = fs::File::open(&descriptor_path)
                .with_context(|| format!("Unable to open pinned config file {}", path.display()))?;
            let mut content = String::new();
            file.by_ref()
                .take(MAX_CONFIG_FILE_BYTES + 1)
                .read_to_string(&mut content)
                .with_context(|| format!("Unable to read config file {}", path.display()))?;
            if content.len() as u64 > MAX_CONFIG_FILE_BYTES {
                anyhow::bail!(
                    "Config file exceeds {} byte limit while reading: {}",
                    MAX_CONFIG_FILE_BYTES,
                    path.display()
                );
            }
            Ok(content)
        })();

        match result {
            Ok(content) => {
                if context.parsed.insert(identity.clone()) {
                    context.audit.files_parsed += 1;
                    context.audit.bytes_scanned += content.len() as u64;
                }
                context.contents.insert(identity, Some(content.clone()));
                Some(content)
            }
            Err(error) => {
                context.record_file_error(path, &error);
                context.contents.insert(identity, None);
                None
            }
        }
    }

    fn strip_comments(content: &str, marker: char) -> String {
        content
            .lines()
            .map(|line| {
                let mut quoted = None;
                for (index, character) in line.char_indices() {
                    match character {
                        '\'' | '"' if quoted == Some(character) => quoted = None,
                        '\'' | '"' if quoted.is_none() => quoted = Some(character),
                        character if character == marker && quoted.is_none() => {
                            return &line[..index];
                        }
                        _ => {}
                    }
                }
                line
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigScanner, CONFIG_REGEX_PATTERNS, SCANNER_VERSION};
    use std::fs;
    use std::path::Path;

    #[test]
    fn unmeasured_syntax_support_is_unknown_and_old_counts_remain_readable() {
        let mut legacy = serde_json::to_value(crate::models::ConfigScanAudit::default()).unwrap();
        legacy["syntax_unsupported"] = serde_json::json!(0);
        let legacy: crate::models::ConfigScanAudit = serde_json::from_value(legacy).unwrap();
        assert_eq!(legacy.syntax_unsupported, Some(0));

        let mut current = serde_json::to_value(crate::models::ConfigScanAudit::default()).unwrap();
        current
            .as_object_mut()
            .unwrap()
            .remove("syntax_unsupported");
        let current: crate::models::ConfigScanAudit = serde_json::from_value(current).unwrap();
        assert_eq!(current.syntax_unsupported, None);
        assert_eq!(
            serde_json::to_value(current).unwrap()["syntax_unsupported"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn scan_audit_describes_actual_recursive_roots_and_config_globs() {
        let paths = ConfigScanner::searched_path_descriptions();
        assert!(paths.iter().any(|path| path.starts_with("/etc/nginx/**")));
        assert!(paths
            .iter()
            .any(|path| path.contains("/etc/apache2/** and /etc/httpd/**")));
        assert!(paths.iter().any(|path| path.contains("/etc/php/**/*.conf")));
        assert!(paths
            .iter()
            .any(|path| path.contains("/etc/postgresql/**/postgresql.conf")));
        assert!(paths
            .iter()
            .any(|path| path.contains("/etc/mysql/**/*.cnf")));
        assert!(paths.iter().any(|path| path.contains("/etc/my.cnf")));
        assert!(paths.contains(&"/var/www/*/wp-config.php"));
        assert!(!paths.contains(&"/var/www/*"));
        assert!(!paths.contains(&"/opt/*"));
    }

    #[test]
    fn scanner_version_identifies_current_database_discovery_rules() {
        assert_eq!(SCANNER_VERSION, "config-scanner/4");
    }

    #[test]
    fn fixed_parser_patterns_are_compiled_once_and_reused() {
        for pattern in CONFIG_REGEX_PATTERNS {
            assert!(std::ptr::eq(
                ConfigScanner::compiled_regex(pattern),
                ConfigScanner::compiled_regex(pattern)
            ));
        }
    }

    #[test]
    fn scan_metrics_count_unique_reads_and_record_skipped_files() {
        let root = std::env::temp_dir().join(format!(
            "screamless-scan-metrics-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&root).unwrap();
        let outside = root.with_extension("external");
        fs::create_dir_all(&outside).unwrap();
        let readable = root.join("readable.conf");
        let missing = root.join("missing.conf");
        let oversized = root.join("oversized.conf");
        let linked_directory = root.join("linked");
        let fifo = root.join("fifo.conf");
        fs::write(&readable, "backend = db01:5432\n").unwrap();
        fs::write(outside.join("outside.conf"), "DB_HOST=outside\n").unwrap();
        fs::File::create(&oversized)
            .unwrap()
            .set_len(super::MAX_CONFIG_FILE_BYTES + 1)
            .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &linked_directory).unwrap();
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        }

        let mut context = super::ScanContext::default();
        let roots = [root.to_str().unwrap()];
        assert!(
            ConfigScanner::read_config_file_with_roots(&readable, &mut context, &roots).is_some()
        );
        assert!(
            ConfigScanner::read_config_file_with_roots(&readable, &mut context, &roots).is_some()
        );
        assert!(
            ConfigScanner::read_config_file_with_roots(&missing, &mut context, &roots).is_none()
        );
        assert!(
            ConfigScanner::read_config_file_with_roots(&oversized, &mut context, &roots).is_none()
        );
        #[cfg(unix)]
        assert!(ConfigScanner::read_config_file_with_roots(
            &linked_directory.join("outside.conf"),
            &mut context,
            &roots
        )
        .is_none());
        #[cfg(target_os = "linux")]
        assert!(ConfigScanner::read_config_file_with_roots(&fifo, &mut context, &roots).is_none());

        #[cfg(target_os = "linux")]
        let expected_discovered = 5;
        #[cfg(all(unix, not(target_os = "linux")))]
        let expected_discovered = 4;
        #[cfg(not(unix))]
        let expected_discovered = 3;
        assert_eq!(context.audit.files_discovered, expected_discovered);
        assert_eq!(context.audit.files_parsed, 1);
        assert_eq!(context.audit.files_skipped, expected_discovered - 1);
        assert_eq!(
            context.audit.bytes_scanned,
            fs::metadata(&readable).unwrap().len()
        );
        assert_eq!(context.audit.errors.len(), expected_discovered - 1);

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn config_tree_traversal_stops_at_entry_and_depth_budgets() {
        let root = std::env::temp_dir().join(format!(
            "screamless-config-tree-limits-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("one.conf"), "one").unwrap();
        fs::write(root.join("two.conf"), "two").unwrap();
        fs::write(root.join("three.conf"), "three").unwrap();

        let entry_limit = ConfigScanner::config_files_under_with_limits(&root, 2, 32)
            .unwrap_err()
            .to_string();
        assert!(entry_limit.contains("entry scan limit"));

        let nested = root.join("level-one").join("level-two");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("deep.conf"), "deep").unwrap();
        let depth_limit = ConfigScanner::config_files_under_with_limits(&root, 100, 1)
            .unwrap_err()
            .to_string();
        assert!(depth_limit.contains("directory depth limit"));

        fs::remove_dir_all(root).unwrap();
    }

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
    fn nginx_site_without_listen_uses_default_http_port() {
        let refs = ConfigScanner::parse_nginx_config(
            Path::new("/etc/nginx/conf.d/default-port.conf"),
            "server { server_name default.example.com; }",
        )
        .unwrap();

        let site = refs
            .iter()
            .find(|reference| reference.hostname == "default.example.com")
            .expect("nginx site should be detected");
        assert!(site.context.contains("ports=80"));
    }

    #[test]
    fn nginx_unix_socket_listener_is_not_misreported_as_default_port_80() {
        let refs = ConfigScanner::parse_nginx_config(
            Path::new("/etc/nginx/conf.d/unix-socket.conf"),
            "server { listen unix:/run/site.sock; server_name socket.example.com; }",
        )
        .unwrap();

        let site = refs
            .iter()
            .find(|reference| reference.hostname == "socket.example.com")
            .expect("nginx site should be detected");
        assert!(!site.context.contains("ports=80"));
    }

    #[test]
    fn nginx_scanner_ignores_commented_directives() {
        let refs = ConfigScanner::parse_nginx_config(
            Path::new("/etc/nginx/conf.d/example.conf"),
            "# server_name disabled.example.com;\nserver { server_name live.example.com; }",
        )
        .unwrap();

        assert!(refs
            .iter()
            .any(|reference| reference.hostname == "live.example.com"));
        assert!(!refs
            .iter()
            .any(|reference| reference.hostname == "disabled.example.com"));
    }

    #[test]
    fn nginx_nested_location_does_not_truncate_or_override_server_directives() {
        let refs = ConfigScanner::parse_nginx_config(
            Path::new("/etc/nginx/sites-enabled/nested.conf"),
            r#"server {
                listen 443 ssl;
                root /srv/site;
                location /assets/ {
                    root /srv/assets;
                }
                server_name nested.example.test;
            }
            server {
                location / {
                    server_name not-a-site.example.test;
                    root /srv/location-only;
                }
            }"#,
        )
        .unwrap();

        let site = refs
            .iter()
            .find(|reference| reference.hostname == "nested.example.test")
            .expect("server_name after nested location should be discovered");
        assert!(site.context.contains("root=/srv/site"));
        assert!(site.context.contains("ports=443"));
        assert!(!refs
            .iter()
            .any(|reference| reference.hostname == "not-a-site.example.test"));
        assert!(!refs
            .iter()
            .any(|reference| reference.context.contains("root=/srv/location-only")));
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

    #[cfg(unix)]
    #[test]
    fn nginx_tree_includes_enabled_sites_but_excludes_disabled_and_external_files() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "screamless-nginx-symlink-test-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let available = root.join("sites-available");
        let enabled = root.join("sites-enabled");
        let outside = root.with_extension("outside");
        fs::create_dir_all(&available).unwrap();
        fs::create_dir_all(&enabled).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let active_config = available.join("active.conf");
        let disabled_config = available.join("disabled.conf");
        let external_config = outside.join("external.conf");
        fs::write(&active_config, "server {}").unwrap();
        fs::write(&disabled_config, "server {}").unwrap();
        fs::write(&external_config, "server {}").unwrap();
        symlink(&active_config, enabled.join("active.conf")).unwrap();
        symlink(&external_config, enabled.join("external.conf")).unwrap();

        let files = ConfigScanner::config_files_under(&root).unwrap();
        assert!(files.contains(&active_config.canonicalize().unwrap()));
        assert!(!files.contains(&disabled_config.canonicalize().unwrap()));
        assert!(!files.contains(&external_config.canonicalize().unwrap()));

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn apache_tree_excludes_disabled_sites_but_follows_enabled_symlinks() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "screamless-apache-enabled-sites-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let apache2 = root.join("apache2");
        let available = apache2.join("sites-available");
        let enabled = apache2.join("sites-enabled");
        let httpd = root.join("httpd");
        let conf_d = httpd.join("conf.d");
        fs::create_dir_all(&available).unwrap();
        fs::create_dir_all(&enabled).unwrap();
        fs::create_dir_all(&conf_d).unwrap();

        let active_config = available.join("active.conf");
        let disabled_config = available.join("disabled.conf");
        let httpd_config = conf_d.join("example.conf");
        fs::write(
            &active_config,
            "<VirtualHost *:80>\nServerName active.example\n</VirtualHost>",
        )
        .unwrap();
        fs::write(
            &disabled_config,
            "<VirtualHost *:80>\nServerName disabled.example\n</VirtualHost>",
        )
        .unwrap();
        fs::write(
            &httpd_config,
            "<VirtualHost *:80>\nServerName httpd.example\n</VirtualHost>",
        )
        .unwrap();
        symlink(&active_config, enabled.join("active.conf")).unwrap();

        let roots = ConfigScanner::apache_config_roots(&apache2, &httpd);
        let mut hostnames = Vec::new();
        for config_root in roots {
            for path in ConfigScanner::config_files_under(&config_root).unwrap() {
                let content = fs::read_to_string(path).unwrap();
                hostnames.extend(
                    ConfigScanner::parse_apache_config(&config_root, &content)
                        .unwrap()
                        .into_iter()
                        .map(|reference| reference.hostname),
                );
            }
        }

        assert!(hostnames
            .iter()
            .any(|hostname| hostname == "active.example"));
        assert!(hostnames.iter().any(|hostname| hostname == "httpd.example"));
        assert!(!hostnames
            .iter()
            .any(|hostname| hostname == "disabled.example"));

        fs::remove_dir_all(root).unwrap();
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

    #[test]
    fn app_config_parses_host_and_port_separately() {
        let refs =
            ConfigScanner::parse_app_config(Path::new("/tmp/config.env"), "DB_HOST=db01:3306\n")
                .unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].hostname, "db01");
        assert_eq!(refs[0].port, Some(3306));
    }

    #[test]
    fn endpoint_parser_handles_protocol_defaults_ipv6_and_unix_sockets() {
        assert_eq!(
            ConfigScanner::parse_endpoint("db01.internal:3306", None),
            Some(("db01.internal".to_string(), Some(3306)))
        );
        assert_eq!(
            ConfigScanner::parse_endpoint("postgres://[2001:db8::1]", None),
            Some(("2001:db8::1".to_string(), Some(5432)))
        );
        assert_eq!(
            ConfigScanner::parse_endpoint("[2001:db8::1]:5432", None),
            Some(("2001:db8::1".to_string(), Some(5432)))
        );
        assert_eq!(
            ConfigScanner::parse_endpoint("/var/run/postgresql/.s.PGSQL.5432", None),
            None
        );
        assert_eq!(
            ConfigScanner::parse_endpoint("https://user:secret@[2001:db8::2]:8443/path", None),
            Some(("2001:db8::2".to_string(), Some(8443)))
        );
        assert_eq!(
            ConfigScanner::parse_endpoint("http://example.internal/path", None),
            Some(("example.internal".to_string(), Some(80)))
        );
        assert_eq!(
            ConfigScanner::parse_endpoint("http://example.internal:invalid", None),
            None
        );
    }

    #[test]
    fn postgres_host_gets_postgres_default_port() {
        let refs = ConfigScanner::parse_app_config(
            Path::new("/tmp/config.env"),
            "postgres.host=db01.internal\n",
        )
        .unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].hostname, "db01.internal");
        assert_eq!(refs[0].port, Some(5432));
    }

    #[test]
    fn postgres_server_config_uses_nested_cluster_path_and_configured_port() {
        let refs = ConfigScanner::parse_database_config(
            Path::new("/etc/postgresql/17/main/postgresql.conf"),
            "listen_addresses = 'localhost, 192.0.2.44'\nport = 5433\n",
        )
        .unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].hostname, "192.0.2.44");
        assert_eq!(refs[0].port, Some(5433));
        assert_eq!(refs[0].context, "Database bind address");
    }

    #[test]
    fn wildcard_database_bind_is_not_misreported_as_a_host_dependency() {
        let refs = ConfigScanner::parse_database_config(
            Path::new("/etc/postgresql/17/main/postgresql.conf"),
            "listen_addresses = '*'\n",
        )
        .unwrap();

        assert!(refs.is_empty());
    }

    #[test]
    fn mysql_server_config_uses_configured_port_and_default_remains_mysql() {
        let refs = ConfigScanner::parse_database_config(
            Path::new("/etc/mysql/conf.d/server.cnf"),
            "[mysqld]\nbind-address = 192.0.2.45\nport = 3307\n",
        )
        .unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].port, Some(3307));

        let default_refs = ConfigScanner::parse_database_config(
            Path::new("/etc/mysql/my.cnf"),
            "[mysqld]\nbind-address = 192.0.2.45\n",
        )
        .unwrap();
        assert_eq!(default_refs[0].port, Some(3306));
    }

    #[test]
    fn mysql_client_options_do_not_override_server_listener_evidence() {
        let refs = ConfigScanner::parse_database_config(
            Path::new("/etc/mysql/my.cnf"),
            "[mysqld]\nbind-address = 192.0.2.46\nport = 3307\n[client]\nport = 3308\n",
        )
        .unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].hostname, "192.0.2.46");
        assert_eq!(refs[0].port, Some(3307));
    }

    #[test]
    fn database_config_discovery_accepts_common_mysql_and_postgres_layouts() {
        assert!(ConfigScanner::is_supported_database_config_file(
            Path::new("/etc/my.cnf"),
            false
        ));
        assert!(ConfigScanner::is_supported_database_config_file(
            Path::new("/etc/my.cnf.d/server.cnf"),
            false
        ));
        assert!(ConfigScanner::is_supported_database_config_file(
            Path::new("/etc/postgresql/17/main/postgresql.conf"),
            true
        ));
        assert!(!ConfigScanner::is_supported_database_config_file(
            Path::new("/etc/postgresql/17/main/pg_hba.conf"),
            true
        ));
    }
}
