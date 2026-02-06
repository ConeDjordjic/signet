//! Configuration management.

use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub security: SecurityConfig,
    pub cors: CorsConfig,
    pub logging: LoggingConfig,
    pub redis: RedisConfig,
    pub telemetry: TelemetryConfig,
    pub grpc: GrpcConfig,
}

#[derive(Debug, Clone)]
pub struct GrpcConfig {
    pub enabled: bool,
    pub port: u16,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

impl GrpcConfig {
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: Option<String>,
    pub pool_size: usize,
    pub connection_timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub otlp_endpoint: Option<String>,
    pub service_name: String,
    pub metrics_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub environment: Environment,
    pub request_timeout_secs: u64,
    pub max_body_size: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

impl Environment {
    pub fn is_production(&self) -> bool {
        matches!(self, Environment::Production)
    }

    pub fn is_development(&self) -> bool {
        matches!(self, Environment::Development)
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout_secs: u64,
    pub idle_timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub access_token_expiry_secs: i64,
    pub refresh_token_expiry_secs: i64,
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub rate_limiting_enabled: bool,
    pub rate_limit_requests_per_minute: u32,
    pub max_failed_login_attempts: u32,
    pub lockout_duration_mins: u32,
    pub min_password_length: usize,
    pub require_password_complexity: bool,
    pub rotate_refresh_tokens: bool,
    pub password_hash_cost: u32,
}

#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age_secs: u64,
}

#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub format: LogFormat,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogFormat {
    Json,
    Pretty,
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();

        let environment = Self::parse_environment();

        Self {
            server: ServerConfig {
                host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()
                    .expect("PORT must be a valid number"),
                environment: environment.clone(),
                request_timeout_secs: env::var("REQUEST_TIMEOUT_SECS")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()
                    .expect("REQUEST_TIMEOUT_SECS must be a valid number"),
                max_body_size: env::var("MAX_BODY_SIZE")
                    .unwrap_or_else(|_| "1048576".to_string())
                    .parse()
                    .expect("MAX_BODY_SIZE must be a valid number"),
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
                max_connections: env::var("DATABASE_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .expect("DATABASE_MAX_CONNECTIONS must be a valid number"),
                min_connections: env::var("DATABASE_MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "2".to_string())
                    .parse()
                    .expect("DATABASE_MIN_CONNECTIONS must be a valid number"),
                connection_timeout_secs: env::var("DATABASE_CONNECTION_TIMEOUT_SECS")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()
                    .expect("DATABASE_CONNECTION_TIMEOUT_SECS must be a valid number"),
                idle_timeout_secs: env::var("DATABASE_IDLE_TIMEOUT_SECS")
                    .unwrap_or_else(|_| "600".to_string())
                    .parse()
                    .expect("DATABASE_IDLE_TIMEOUT_SECS must be a valid number"),
            },
            jwt: Self::parse_jwt_config(&environment),
            security: Self::parse_security_config(&environment),
            cors: Self::parse_cors_config(&environment),
            logging: Self::parse_logging_config(&environment),
            redis: Self::parse_redis_config(),
            telemetry: Self::parse_telemetry_config(),
            grpc: Self::parse_grpc_config(),
        }
    }

    fn parse_grpc_config() -> GrpcConfig {
        GrpcConfig {
            enabled: env::var("GRPC_ENABLED")
                .map(|v| v.parse().unwrap_or(true))
                .unwrap_or(true),
            port: env::var("GRPC_PORT")
                .unwrap_or_else(|_| "50051".to_string())
                .parse()
                .expect("GRPC_PORT must be a valid number"),
            tls_cert_path: env::var("GRPC_TLS_CERT_PATH").ok(),
            tls_key_path: env::var("GRPC_TLS_KEY_PATH").ok(),
        }
    }

    fn parse_telemetry_config() -> TelemetryConfig {
        TelemetryConfig {
            otlp_endpoint: env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
            service_name: env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "signet".to_string()),
            metrics_enabled: env::var("METRICS_ENABLED")
                .map(|v| v.parse().unwrap_or(true))
                .unwrap_or(true),
        }
    }

    fn parse_redis_config() -> RedisConfig {
        RedisConfig {
            url: env::var("REDIS_URL").ok(),
            pool_size: env::var("REDIS_POOL_SIZE")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .expect("REDIS_POOL_SIZE must be a valid number"),
            connection_timeout_secs: env::var("REDIS_CONNECTION_TIMEOUT_SECS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .expect("REDIS_CONNECTION_TIMEOUT_SECS must be a valid number"),
        }
    }

    fn parse_environment() -> Environment {
        match env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .to_lowercase()
            .as_str()
        {
            "production" | "prod" => Environment::Production,
            "staging" | "stage" => Environment::Staging,
            _ => Environment::Development,
        }
    }

    fn parse_jwt_config(_environment: &Environment) -> JwtConfig {
        JwtConfig {
            access_token_expiry_secs: env::var("JWT_ACCESS_TOKEN_EXPIRY_SECS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .expect("JWT_ACCESS_TOKEN_EXPIRY_SECS must be a valid number"),
            refresh_token_expiry_secs: env::var("JWT_REFRESH_TOKEN_EXPIRY_SECS")
                .unwrap_or_else(|_| "604800".to_string())
                .parse()
                .expect("JWT_REFRESH_TOKEN_EXPIRY_SECS must be a valid number"),
            issuer: env::var("JWT_ISSUER").ok(),
            audience: env::var("JWT_AUDIENCE").ok(),
        }
    }

    fn parse_security_config(environment: &Environment) -> SecurityConfig {
        let is_prod = environment.is_production();

        SecurityConfig {
            rate_limiting_enabled: env::var("RATE_LIMITING_ENABLED")
                .map(|v| v.parse().unwrap_or(is_prod))
                .unwrap_or(is_prod),
            rate_limit_requests_per_minute: env::var("RATE_LIMIT_REQUESTS_PER_MINUTE")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .expect("RATE_LIMIT_REQUESTS_PER_MINUTE must be a valid number"),
            max_failed_login_attempts: env::var("MAX_FAILED_LOGIN_ATTEMPTS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .expect("MAX_FAILED_LOGIN_ATTEMPTS must be a valid number"),
            lockout_duration_mins: env::var("LOCKOUT_DURATION_MINS")
                .unwrap_or_else(|_| "15".to_string())
                .parse()
                .expect("LOCKOUT_DURATION_MINS must be a valid number"),
            min_password_length: env::var("MIN_PASSWORD_LENGTH")
                .unwrap_or_else(|_| "8".to_string())
                .parse()
                .expect("MIN_PASSWORD_LENGTH must be a valid number"),
            require_password_complexity: env::var("REQUIRE_PASSWORD_COMPLEXITY")
                .map(|v| v.parse().unwrap_or(is_prod))
                .unwrap_or(is_prod),
            rotate_refresh_tokens: env::var("ROTATE_REFRESH_TOKENS")
                .map(|v| v.parse().unwrap_or(true))
                .unwrap_or(true),
            password_hash_cost: env::var("PASSWORD_HASH_COST")
                .unwrap_or_else(|_| "12".to_string())
                .parse()
                .expect("PASSWORD_HASH_COST must be a valid number"),
        }
    }

    fn parse_cors_config(environment: &Environment) -> CorsConfig {
        let default_origins = if environment.is_development() {
            vec!["*".to_string()]
        } else {
            vec![]
        };

        let allowed_origins = env::var("CORS_ALLOWED_ORIGINS")
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or(default_origins);

        if environment.is_production() && allowed_origins.contains(&"*".to_string()) {
            eprintln!("WARNING: Using wildcard CORS origin in production is not recommended");
        }

        CorsConfig {
            allowed_origins,
            allowed_methods: env::var("CORS_ALLOWED_METHODS")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|_| {
                    vec![
                        "GET".to_string(),
                        "POST".to_string(),
                        "PUT".to_string(),
                        "DELETE".to_string(),
                        "OPTIONS".to_string(),
                    ]
                }),
            allowed_headers: env::var("CORS_ALLOWED_HEADERS")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|_| {
                    vec![
                        "Content-Type".to_string(),
                        "Authorization".to_string(),
                        "X-Request-ID".to_string(),
                    ]
                }),
            allow_credentials: env::var("CORS_ALLOW_CREDENTIALS")
                .map(|v| v.parse().unwrap_or(true))
                .unwrap_or(true),
            max_age_secs: env::var("CORS_MAX_AGE_SECS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .expect("CORS_MAX_AGE_SECS must be a valid number"),
        }
    }

    fn parse_logging_config(environment: &Environment) -> LoggingConfig {
        let is_dev = environment.is_development();

        LoggingConfig {
            level: env::var("LOG_LEVEL").unwrap_or_else(|_| {
                if is_dev {
                    "debug".to_string()
                } else {
                    "info".to_string()
                }
            }),
            format: match env::var("LOG_FORMAT")
                .unwrap_or_else(|_| {
                    if is_dev {
                        "pretty".to_string()
                    } else {
                        "json".to_string()
                    }
                })
                .to_lowercase()
                .as_str()
            {
                "json" => LogFormat::Json,
                _ => LogFormat::Pretty,
            },
        }
    }

    pub fn validate_for_production(&self) -> Vec<String> {
        let mut issues = Vec::new();

        if self.server.environment.is_production() {
            if self.jwt.access_token_expiry_secs > 3600 {
                issues
                    .push("Access token expiry should not exceed 1 hour in production".to_string());
            }

            if self.cors.allowed_origins.contains(&"*".to_string()) {
                issues.push("CORS should not allow all origins (*) in production".to_string());
            }

            if !self.security.rate_limiting_enabled {
                issues.push("Rate limiting should be enabled in production".to_string());
            }
            if self.security.min_password_length < 8 {
                issues.push("Minimum password length should be at least 8".to_string());
            }

            if self.database.url.contains("localhost") || self.database.url.contains("127.0.0.1") {
                issues.push("Database URL appears to be localhost in production".to_string());
            }
        }

        issues
    }

    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Config {
    pub fn default_for_testing() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                environment: Environment::Development,
                request_timeout_secs: 30,
                max_body_size: 1048576,
            },
            database: DatabaseConfig {
                url: "postgresql://test:test@localhost:5432/test".to_string(),
                max_connections: 5,
                min_connections: 1,
                connection_timeout_secs: 10,
                idle_timeout_secs: 300,
            },
            jwt: JwtConfig {
                access_token_expiry_secs: 3600,
                refresh_token_expiry_secs: 604800,
                issuer: Some("signet-test".to_string()),
                audience: None,
            },
            security: SecurityConfig {
                rate_limiting_enabled: false,
                rate_limit_requests_per_minute: 60,
                max_failed_login_attempts: 5,
                lockout_duration_mins: 15,
                min_password_length: 8,
                require_password_complexity: false,
                rotate_refresh_tokens: true,
                password_hash_cost: 4,
            },
            cors: CorsConfig {
                allowed_origins: vec!["*".to_string()],
                allowed_methods: vec![
                    "GET".to_string(),
                    "POST".to_string(),
                    "PUT".to_string(),
                    "DELETE".to_string(),
                ],
                allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
                allow_credentials: false,
                max_age_secs: 3600,
            },
            logging: LoggingConfig {
                level: "debug".to_string(),
                format: LogFormat::Pretty,
            },
            redis: RedisConfig {
                url: None,
                pool_size: 5,
                connection_timeout_secs: 5,
            },
            telemetry: TelemetryConfig {
                otlp_endpoint: None,
                service_name: "signet-test".to_string(),
                metrics_enabled: false,
            },
            grpc: GrpcConfig {
                enabled: false,
                port: 50051,
                tls_cert_path: None,
                tls_key_path: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_parsing() {
        assert!(Environment::Production.is_production());
        assert!(!Environment::Production.is_development());
        assert!(Environment::Development.is_development());
        assert!(!Environment::Development.is_production());
    }

    #[test]
    fn test_production_validation() {
        let config = Config {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                environment: Environment::Production,
                request_timeout_secs: 30,
                max_body_size: 1048576,
            },
            database: DatabaseConfig {
                url: "postgresql://localhost/test".to_string(),
                max_connections: 10,
                min_connections: 2,
                connection_timeout_secs: 30,
                idle_timeout_secs: 600,
            },
            jwt: JwtConfig {
                access_token_expiry_secs: 7200,
                refresh_token_expiry_secs: 604800,
                issuer: None,
                audience: None,
            },
            security: SecurityConfig {
                rate_limiting_enabled: false,
                rate_limit_requests_per_minute: 60,
                max_failed_login_attempts: 5,
                lockout_duration_mins: 15,
                min_password_length: 6,
                require_password_complexity: false,
                rotate_refresh_tokens: true,
                password_hash_cost: 12,
            },
            cors: CorsConfig {
                allowed_origins: vec!["*".to_string()],
                allowed_methods: vec!["GET".to_string()],
                allowed_headers: vec!["Content-Type".to_string()],
                allow_credentials: true,
                max_age_secs: 3600,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: LogFormat::Json,
            },
            redis: RedisConfig {
                url: None,
                pool_size: 10,
                connection_timeout_secs: 5,
            },
            telemetry: TelemetryConfig {
                otlp_endpoint: None,
                service_name: "signet".to_string(),
                metrics_enabled: true,
            },
            grpc: GrpcConfig {
                enabled: true,
                port: 50051,
                tls_cert_path: None,
                tls_key_path: None,
            },
        };

        let issues = config.validate_for_production();
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("CORS")));
        assert!(issues.iter().any(|i| i.contains("Rate limiting")));
    }

    #[test]
    fn test_grpc_config_defaults() {
        let config = Config::default_for_testing();
        assert!(!config.grpc.enabled);
        assert_eq!(config.grpc.port, 50051);
        assert!(!config.grpc.tls_enabled());
    }

    #[test]
    fn test_grpc_tls_enabled() {
        let config = GrpcConfig {
            enabled: true,
            port: 50051,
            tls_cert_path: Some("/path/to/cert.pem".to_string()),
            tls_key_path: Some("/path/to/key.pem".to_string()),
        };
        assert!(config.tls_enabled());

        let config_no_tls = GrpcConfig {
            enabled: true,
            port: 50051,
            tls_cert_path: None,
            tls_key_path: None,
        };
        assert!(!config_no_tls.tls_enabled());
    }

    #[test]
    fn test_redis_config_defaults() {
        let config = Config::default_for_testing();
        assert!(config.redis.url.is_none());
        assert_eq!(config.redis.pool_size, 5);
    }

    #[test]
    fn test_telemetry_config_defaults() {
        let config = Config::default_for_testing();
        assert!(config.telemetry.otlp_endpoint.is_none());
        assert_eq!(config.telemetry.service_name, "signet-test");
        assert!(!config.telemetry.metrics_enabled);
    }
}
