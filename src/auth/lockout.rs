//! Account lockout management using Redis.
//!
//! Tracks failed login attempts and locks accounts after exceeding thresholds.

use deadpool_redis::Pool;
use redis::AsyncCommands;
use tracing::{debug, info, warn};

const FAILED_ATTEMPTS_PREFIX: &str = "lockout:attempts:";
const LOCKED_ACCOUNT_PREFIX: &str = "lockout:locked:";

#[derive(Clone)]
pub struct LockoutManager {
    pool: Option<Pool>,
    max_attempts: u32,
    lockout_duration_secs: u64,
    attempt_window_secs: u64,
}

impl LockoutManager {
    pub fn new(pool: Option<Pool>, max_attempts: u32, lockout_duration_mins: u32) -> Self {
        Self {
            pool,
            max_attempts,
            lockout_duration_secs: lockout_duration_mins as u64 * 60,
            attempt_window_secs: lockout_duration_mins as u64 * 60, // Same as lockout for simplicity
        }
    }

    fn attempts_key(email: &str) -> String {
        format!("{}{}", FAILED_ATTEMPTS_PREFIX, email.to_lowercase())
    }

    fn locked_key(email: &str) -> String {
        format!("{}{}", LOCKED_ACCOUNT_PREFIX, email.to_lowercase())
    }

    pub async fn is_locked(&self, email: &str) -> bool {
        let Some(pool) = &self.pool else {
            return false;
        };

        let Ok(mut conn) = pool.get().await else {
            return false;
        };

        let key = Self::locked_key(email);
        conn.exists::<_, bool>(&key).await.unwrap_or(false)
    }

    pub async fn get_lockout_remaining(&self, email: &str) -> Option<u64> {
        let pool = self.pool.as_ref()?;
        let mut conn = pool.get().await.ok()?;

        let key = Self::locked_key(email);
        let ttl: i64 = conn.ttl(&key).await.ok()?;

        if ttl > 0 {
            Some(ttl as u64)
        } else {
            None
        }
    }

    pub async fn record_failed_attempt(&self, email: &str) -> Result<bool, LockoutError> {
        let pool = self.pool.as_ref().ok_or(LockoutError::NoRedis)?;
        let mut conn = pool
            .get()
            .await
            .map_err(|_| LockoutError::ConnectionFailed)?;

        let attempts_key = Self::attempts_key(email);

        let attempts: u32 = conn
            .incr(&attempts_key, 1)
            .await
            .map_err(|_| LockoutError::OperationFailed)?;

        if attempts == 1 {
            let _ = conn
                .expire::<_, ()>(&attempts_key, self.attempt_window_secs as i64)
                .await;
        }

        debug!(
            email = %email,
            attempts = attempts,
            max_attempts = self.max_attempts,
            "Recorded failed login attempt"
        );

        if attempts >= self.max_attempts {
            let locked_key = Self::locked_key(email);
            let _: () = conn
                .set_ex(&locked_key, "1", self.lockout_duration_secs)
                .await
                .map_err(|_| LockoutError::OperationFailed)?;

            let _: () = conn
                .del(&attempts_key)
                .await
                .map_err(|_| LockoutError::OperationFailed)?;

            warn!(
                email = %email,
                lockout_duration_secs = self.lockout_duration_secs,
                "Account locked due to too many failed attempts"
            );

            return Ok(true);
        }

        Ok(false)
    }

    pub async fn clear_failed_attempts(&self, email: &str) -> Result<(), LockoutError> {
        let pool = self.pool.as_ref().ok_or(LockoutError::NoRedis)?;
        let mut conn = pool
            .get()
            .await
            .map_err(|_| LockoutError::ConnectionFailed)?;

        let attempts_key = Self::attempts_key(email);
        let _: () = conn
            .del(&attempts_key)
            .await
            .map_err(|_| LockoutError::OperationFailed)?;

        debug!(email = %email, "Cleared failed login attempts");
        Ok(())
    }

    pub async fn unlock_account(&self, email: &str) -> Result<(), LockoutError> {
        let pool = self.pool.as_ref().ok_or(LockoutError::NoRedis)?;
        let mut conn = pool
            .get()
            .await
            .map_err(|_| LockoutError::ConnectionFailed)?;

        let locked_key = Self::locked_key(email);
        let attempts_key = Self::attempts_key(email);

        let _: () = conn
            .del(&locked_key)
            .await
            .map_err(|_| LockoutError::OperationFailed)?;
        let _: () = conn
            .del(&attempts_key)
            .await
            .map_err(|_| LockoutError::OperationFailed)?;

        info!(email = %email, "Account manually unlocked");
        Ok(())
    }

    pub fn is_available(&self) -> bool {
        self.pool.is_some()
    }
}

#[derive(Debug, Clone)]
pub enum LockoutError {
    NoRedis,
    ConnectionFailed,
    OperationFailed,
}

impl std::fmt::Display for LockoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockoutError::NoRedis => write!(f, "Redis not configured"),
            LockoutError::ConnectionFailed => write!(f, "Redis connection failed"),
            LockoutError::OperationFailed => write!(f, "Redis operation failed"),
        }
    }
}

impl std::error::Error for LockoutError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockout_manager_without_redis() {
        let manager = LockoutManager::new(None, 5, 15);
        assert!(!manager.is_available());
    }

    #[tokio::test]
    async fn test_is_locked_without_redis() {
        let manager = LockoutManager::new(None, 5, 15);
        assert!(!manager.is_locked("test@example.com").await);
    }

    #[test]
    fn test_key_formats() {
        let attempts_key = LockoutManager::attempts_key("Test@Example.COM");
        assert_eq!(attempts_key, "lockout:attempts:test@example.com");

        let locked_key = LockoutManager::locked_key("Test@Example.COM");
        assert_eq!(locked_key, "lockout:locked:test@example.com");
    }
}
