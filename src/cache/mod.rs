//! Caching and distributed state management via Redis.

pub mod permission_cache;
pub mod token_revocation;

use deadpool_redis::{Config as RedisPoolConfig, Pool, Runtime};
use std::sync::Arc;
use tracing::info;

use crate::config::RedisConfig;

pub use permission_cache::PermissionCache;
pub use token_revocation::TokenRevocationList;

pub fn create_redis_pool(config: &RedisConfig) -> Option<Pool> {
    let url = config.url.as_ref()?;

    let timeout = std::time::Duration::from_secs(config.connection_timeout_secs);
    let cfg = RedisPoolConfig::from_url(url);
    let pool = cfg.builder().ok().and_then(|b| {
        b.max_size(config.pool_size)
            .wait_timeout(Some(timeout))
            .create_timeout(Some(timeout))
            .runtime(Runtime::Tokio1)
            .build()
            .ok()
    });

    if pool.is_some() {
        info!(redis_url = %url.split('@').next_back().unwrap_or("***"), "Redis pool created");
    }

    pool
}

#[derive(Clone)]
pub struct CacheServices {
    pub token_revocation: Arc<TokenRevocationList>,
    pub permission_cache: Arc<PermissionCache>,
}

impl CacheServices {
    pub fn new(redis_pool: Option<Pool>) -> Self {
        Self {
            token_revocation: Arc::new(TokenRevocationList::new(redis_pool.clone())),
            permission_cache: Arc::new(PermissionCache::new(redis_pool)),
        }
    }

    pub fn disabled() -> Self {
        Self {
            token_revocation: Arc::new(TokenRevocationList::new(None)),
            permission_cache: Arc::new(PermissionCache::new(None)),
        }
    }
}
