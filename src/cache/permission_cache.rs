//! Redis-backed permission caching.
//!
//! Caches user permissions to avoid repeated database queries.

use deadpool_redis::Pool;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};
use uuid::Uuid;

const PERMISSION_CACHE_PREFIX: &str = "permissions:";
const DEFAULT_TTL_SECS: u64 = 300; // 5 minutes

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPermissions {
    pub user_id: Uuid,
    pub project_id: Uuid,
    pub permissions: Vec<String>,
    pub cached_at: i64,
}

#[derive(Clone)]
pub struct PermissionCache {
    pool: Option<Pool>,
    ttl_secs: u64,
}

impl PermissionCache {
    pub fn new(pool: Option<Pool>) -> Self {
        Self {
            pool,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    pub fn with_ttl(pool: Option<Pool>, ttl_secs: u64) -> Self {
        Self { pool, ttl_secs }
    }

    fn cache_key(user_id: Uuid, project_id: Uuid) -> String {
        format!("{}{}:{}", PERMISSION_CACHE_PREFIX, user_id, project_id)
    }

    pub async fn set(
        &self,
        user_id: Uuid,
        project_id: Uuid,
        permissions: Vec<String>,
    ) -> Result<(), CacheError> {
        let pool = self.pool.as_ref().ok_or(CacheError::NoRedis)?;
        let mut conn = pool.get().await.map_err(|e| {
            error!(error = %e, "Failed to get Redis connection");
            CacheError::ConnectionFailed
        })?;

        let entry = CachedPermissions {
            user_id,
            project_id,
            permissions,
            cached_at: chrono::Utc::now().timestamp(),
        };

        let key = Self::cache_key(user_id, project_id);
        let value = serde_json::to_string(&entry).map_err(|_| CacheError::SerializationFailed)?;

        conn.set_ex::<_, _, ()>(&key, value, self.ttl_secs)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to cache permissions");
                CacheError::OperationFailed
            })?;

        debug!(user_id = %user_id, project_id = %project_id, "Permissions cached");
        Ok(())
    }

    pub async fn get(&self, user_id: Uuid, project_id: Uuid) -> Option<CachedPermissions> {
        let pool = self.pool.as_ref()?;
        let mut conn = pool.get().await.ok()?;

        let key = Self::cache_key(user_id, project_id);
        let value: Option<String> = conn.get(&key).await.ok()?;

        value.and_then(|v| serde_json::from_str(&v).ok())
    }

    pub async fn has_permission(
        &self,
        user_id: Uuid,
        project_id: Uuid,
        permission: &str,
    ) -> Option<bool> {
        let cached = self.get(user_id, project_id).await?;
        Some(cached.permissions.contains(&permission.to_string()))
    }

    pub async fn invalidate(&self, user_id: Uuid, project_id: Uuid) -> Result<(), CacheError> {
        let pool = self.pool.as_ref().ok_or(CacheError::NoRedis)?;
        let mut conn = pool.get().await.map_err(|e| {
            error!(error = %e, "Failed to get Redis connection");
            CacheError::ConnectionFailed
        })?;

        let key = Self::cache_key(user_id, project_id);
        conn.del::<_, ()>(&key).await.map_err(|e| {
            error!(error = %e, "Failed to invalidate permission cache");
            CacheError::OperationFailed
        })?;

        debug!(user_id = %user_id, project_id = %project_id, "Permission cache invalidated");
        Ok(())
    }

    pub async fn invalidate_project(&self, project_id: Uuid) -> Result<(), CacheError> {
        let pool = self.pool.as_ref().ok_or(CacheError::NoRedis)?;
        let mut conn = pool.get().await.map_err(|e| {
            error!(error = %e, "Failed to get Redis connection");
            CacheError::ConnectionFailed
        })?;

        let pattern = format!("{}*:{}", PERMISSION_CACHE_PREFIX, project_id);

        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut *conn)
            .await
            .unwrap_or_default();

        if !keys.is_empty() {
            conn.del::<_, ()>(keys).await.map_err(|e| {
                error!(error = %e, "Failed to invalidate project permission cache");
                CacheError::OperationFailed
            })?;
        }

        debug!(project_id = %project_id, "Project permission cache invalidated");
        Ok(())
    }

    pub fn is_available(&self) -> bool {
        self.pool.is_some()
    }
}

#[derive(Debug, Clone)]
pub enum CacheError {
    NoRedis,
    ConnectionFailed,
    OperationFailed,
    SerializationFailed,
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::NoRedis => write!(f, "Redis not configured"),
            CacheError::ConnectionFailed => write!(f, "Redis connection failed"),
            CacheError::OperationFailed => write!(f, "Redis operation failed"),
            CacheError::SerializationFailed => write!(f, "Serialization failed"),
        }
    }
}

impl std::error::Error for CacheError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_cache_without_redis() {
        let cache = PermissionCache::new(None);
        assert!(!cache.is_available());
    }

    #[tokio::test]
    async fn test_get_without_redis() {
        let cache = PermissionCache::new(None);
        let result = cache.get(Uuid::new_v4(), Uuid::new_v4()).await;
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_key_format() {
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let project_id = Uuid::parse_str("660e8400-e29b-41d4-a716-446655440001").unwrap();
        let key = PermissionCache::cache_key(user_id, project_id);
        assert!(key.starts_with("permissions:"));
        assert!(key.contains(&user_id.to_string()));
        assert!(key.contains(&project_id.to_string()));
    }
}
