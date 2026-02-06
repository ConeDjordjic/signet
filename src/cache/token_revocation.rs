//! Redis-backed access token revocation list.
//!
//! Enables immediate token invalidation for logout-all and security incidents.

use deadpool_redis::Pool;
use redis::AsyncCommands;
use tracing::{debug, error};
use uuid::Uuid;

const REVOKED_TOKEN_PREFIX: &str = "revoked:token:";
const REVOKED_USER_PREFIX: &str = "revoked:user:";

#[derive(Clone)]
pub struct TokenRevocationList {
    pool: Option<Pool>,
}

impl TokenRevocationList {
    pub fn new(pool: Option<Pool>) -> Self {
        Self { pool }
    }

    pub async fn revoke_token(&self, token_id: &str, ttl_secs: u64) -> Result<(), RevocationError> {
        let pool = self.pool.as_ref().ok_or(RevocationError::NoRedis)?;
        let mut conn = pool.get().await.map_err(|e| {
            error!(error = %e, "Failed to get Redis connection");
            RevocationError::ConnectionFailed
        })?;

        let key = format!("{}{}", REVOKED_TOKEN_PREFIX, token_id);
        conn.set_ex::<_, _, ()>(&key, "1", ttl_secs)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to revoke token");
                RevocationError::OperationFailed
            })?;

        debug!(token_id = %token_id, ttl_secs = ttl_secs, "Token revoked");
        Ok(())
    }

    pub async fn is_token_revoked(&self, token_id: &str) -> bool {
        let Some(pool) = &self.pool else {
            return false;
        };

        let Ok(mut conn) = pool.get().await else {
            return false;
        };

        let key = format!("{}{}", REVOKED_TOKEN_PREFIX, token_id);
        conn.exists::<_, bool>(&key).await.unwrap_or(false)
    }

    pub async fn revoke_all_user_tokens(
        &self,
        user_id: Uuid,
        ttl_secs: u64,
    ) -> Result<(), RevocationError> {
        let pool = self.pool.as_ref().ok_or(RevocationError::NoRedis)?;
        let mut conn = pool.get().await.map_err(|e| {
            error!(error = %e, "Failed to get Redis connection");
            RevocationError::ConnectionFailed
        })?;

        let key = format!("{}{}", REVOKED_USER_PREFIX, user_id);
        let revoked_at = chrono::Utc::now().timestamp();

        conn.set_ex::<_, _, ()>(&key, revoked_at, ttl_secs)
            .await
            .map_err(|e| {
                error!(error = %e, user_id = %user_id, "Failed to revoke user tokens");
                RevocationError::OperationFailed
            })?;

        debug!(user_id = %user_id, "All user tokens revoked");
        Ok(())
    }

    pub async fn is_user_token_revoked(&self, user_id: Uuid, token_iat: i64) -> bool {
        let Some(pool) = &self.pool else {
            return false;
        };

        let Ok(mut conn) = pool.get().await else {
            return false;
        };

        let key = format!("{}{}", REVOKED_USER_PREFIX, user_id);
        let revoked_at: Option<i64> = conn.get(&key).await.ok();

        match revoked_at {
            Some(ts) => token_iat < ts,
            None => false,
        }
    }

    pub fn is_available(&self) -> bool {
        self.pool.is_some()
    }

    pub fn pool(&self) -> Option<&Pool> {
        self.pool.as_ref()
    }
}

#[derive(Debug, Clone)]
pub enum RevocationError {
    NoRedis,
    ConnectionFailed,
    OperationFailed,
}

impl std::fmt::Display for RevocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevocationError::NoRedis => write!(f, "Redis not configured"),
            RevocationError::ConnectionFailed => write!(f, "Redis connection failed"),
            RevocationError::OperationFailed => write!(f, "Redis operation failed"),
        }
    }
}

impl std::error::Error for RevocationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_list_without_redis() {
        let list = TokenRevocationList::new(None);
        assert!(!list.is_available());
    }

    #[tokio::test]
    async fn test_is_token_revoked_without_redis() {
        let list = TokenRevocationList::new(None);

        assert!(!list.is_token_revoked("some-token-id").await);
    }

    #[tokio::test]
    async fn test_is_user_token_revoked_without_redis() {
        let list = TokenRevocationList::new(None);
        let user_id = Uuid::new_v4();

        assert!(!list.is_user_token_revoked(user_id, 12345).await);
    }
}
