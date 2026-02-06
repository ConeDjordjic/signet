//! JWT token generation and verification.

use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub email: String,
    pub project_id: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshCustomClaims {
    pub token_id: String,
}

#[derive(Debug, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub project_id: Option<String>,
    pub role: Option<String>,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Clone)]
pub struct RefreshClaims {
    pub sub: String,
    pub token_id: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Clone)]
pub struct JwtConfig {
    key_pair: Arc<Ed25519KeyPair>,
    public_key: Arc<Ed25519PublicKey>,
    pub access_token_expiry: i64,
    pub refresh_token_expiry: i64,
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

impl JwtConfig {
    /// Expects JWT_PRIVATE_KEY env var (base64-encoded Ed25519 key).
    pub fn from_env() -> Self {
        Self::from_env_with_expiry(3600, 604800, None, None)
    }

    /// Creates JwtConfig from environment with custom expiry times.
    pub fn from_env_with_expiry(
        access_token_expiry: i64,
        refresh_token_expiry: i64,
        issuer: Option<String>,
        audience: Option<String>,
    ) -> Self {
        use base64::Engine;

        let private_key_b64 =
            std::env::var("JWT_PRIVATE_KEY").expect("JWT_PRIVATE_KEY must be set");

        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&private_key_b64)
            .expect("JWT_PRIVATE_KEY must be valid base64");

        let key_pair = Ed25519KeyPair::from_bytes(&key_bytes)
            .expect("JWT_PRIVATE_KEY must be a valid Ed25519 key");

        let public_key = key_pair.public_key();

        Self {
            key_pair: Arc::new(key_pair),
            public_key: Arc::new(public_key),
            access_token_expiry,
            refresh_token_expiry,
            issuer,
            audience,
        }
    }

    pub fn from_key_pair(key_pair: Ed25519KeyPair) -> Self {
        let public_key = key_pair.public_key();
        Self {
            key_pair: Arc::new(key_pair),
            public_key: Arc::new(public_key),
            access_token_expiry: 3600,
            refresh_token_expiry: 604800,
            issuer: None,
            audience: None,
        }
    }

    pub fn generate_key_pair() -> (String, String) {
        use base64::Engine;

        let key_pair = Ed25519KeyPair::generate();
        let private_b64 = base64::engine::general_purpose::STANDARD.encode(key_pair.to_bytes());
        let public_b64 =
            base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().to_bytes());
        (private_b64, public_b64)
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    pub fn generate_access_token(
        &self,
        user_id: Uuid,
        email: &str,
        project_id: Option<Uuid>,
        role: Option<String>,
    ) -> Result<String, jwt_simple::Error> {
        let custom_claims = AccessClaims {
            email: email.to_string(),
            project_id: project_id.map(|id| id.to_string()),
            role,
        };

        let mut claims = jwt_simple::claims::Claims::with_custom_claims(
            custom_claims,
            Duration::from_secs(self.access_token_expiry as u64),
        )
        .with_subject(user_id.to_string());

        if let Some(issuer) = &self.issuer {
            claims = claims.with_issuer(issuer);
        }
        if let Some(audience) = &self.audience {
            claims = claims.with_audience(audience);
        }

        self.key_pair.sign(claims)
    }

    pub fn generate_refresh_token(&self, user_id: Uuid) -> Result<String, jwt_simple::Error> {
        let custom_claims = RefreshCustomClaims {
            token_id: Uuid::new_v4().to_string(),
        };

        let mut claims = jwt_simple::claims::Claims::with_custom_claims(
            custom_claims,
            Duration::from_secs(self.refresh_token_expiry as u64),
        )
        .with_subject(user_id.to_string());

        if let Some(issuer) = &self.issuer {
            claims = claims.with_issuer(issuer);
        }
        if let Some(audience) = &self.audience {
            claims = claims.with_audience(audience);
        }

        self.key_pair.sign(claims)
    }

    pub fn verify_access_token(&self, token: &str) -> Result<Claims, jwt_simple::Error> {
        let mut options = VerificationOptions::default();
        if let Some(issuer) = &self.issuer {
            options.allowed_issuers = Some(std::collections::HashSet::from([issuer.clone()]));
        }
        if let Some(audience) = &self.audience {
            options.allowed_audiences = Some(std::collections::HashSet::from([audience.clone()]));
        }

        let token_data = self
            .public_key
            .verify_token::<AccessClaims>(token, Some(options))?;

        Ok(Claims {
            sub: token_data.subject.unwrap_or_default(),
            email: token_data.custom.email,
            project_id: token_data.custom.project_id,
            role: token_data.custom.role,
            exp: token_data
                .expires_at
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0),
            iat: token_data
                .issued_at
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0),
        })
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<RefreshClaims, jwt_simple::Error> {
        let mut options = VerificationOptions::default();
        if let Some(issuer) = &self.issuer {
            options.allowed_issuers = Some(std::collections::HashSet::from([issuer.clone()]));
        }
        if let Some(audience) = &self.audience {
            options.allowed_audiences = Some(std::collections::HashSet::from([audience.clone()]));
        }

        let token_data = self
            .public_key
            .verify_token::<RefreshCustomClaims>(token, Some(options))?;

        Ok(RefreshClaims {
            sub: token_data.subject.unwrap_or_default(),
            token_id: token_data.custom.token_id,
            exp: token_data
                .expires_at
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0),
            iat: token_data
                .issued_at
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> JwtConfig {
        let key_pair = Ed25519KeyPair::generate();
        JwtConfig::from_key_pair(key_pair)
    }

    #[test]
    fn test_generate_and_verify_access_token() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";

        let token = config
            .generate_access_token(user_id, email, None, None)
            .expect("Token generation should succeed");

        let claims = config
            .verify_access_token(&token)
            .expect("Token verification should succeed");

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        assert!(claims.project_id.is_none());
        assert!(claims.role.is_none());
    }

    #[test]
    fn test_generate_and_verify_refresh_token() {
        let config = test_config();
        let user_id = Uuid::new_v4();

        let token = config
            .generate_refresh_token(user_id)
            .expect("Token generation should succeed");

        let claims = config
            .verify_refresh_token(&token)
            .expect("Token verification should succeed");

        assert_eq!(claims.sub, user_id.to_string());
    }

    #[test]
    fn test_access_token_with_project_context() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let role = "admin".to_string();

        let token = config
            .generate_access_token(
                user_id,
                "test@example.com",
                Some(project_id),
                Some(role.clone()),
            )
            .expect("Token generation should succeed");

        let claims = config
            .verify_access_token(&token)
            .expect("Token verification should succeed");

        assert_eq!(claims.project_id, Some(project_id.to_string()));
        assert_eq!(claims.role, Some(role));
    }

    #[test]
    fn test_invalid_token_fails_verification() {
        let config = test_config();
        let result = config.verify_access_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let config1 = test_config();
        let config2 = test_config(); // Different key pair

        let user_id = Uuid::new_v4();
        let token = config1
            .generate_access_token(user_id, "test@example.com", None, None)
            .expect("Token generation should succeed");

        let result = config2.verify_access_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_can_verify() {
        let config = test_config();
        let user_id = Uuid::new_v4();

        let token = config
            .generate_access_token(user_id, "test@example.com", None, None)
            .expect("Token generation should succeed");

        let public_key = config.public_key();
        let options = VerificationOptions::default();
        let result = public_key.verify_token::<AccessClaims>(&token, Some(options));
        assert!(result.is_ok());
    }

    #[test]
    fn test_key_generation() {
        let (private_b64, public_b64) = JwtConfig::generate_key_pair();

        assert!(!private_b64.is_empty());
        assert!(!public_b64.is_empty());

        use base64::Engine;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&private_b64)
            .unwrap();
        let key_pair = Ed25519KeyPair::from_bytes(&key_bytes).unwrap();
        let config = JwtConfig::from_key_pair(key_pair);

        let token = config
            .generate_access_token(Uuid::new_v4(), "test@test.com", None, None)
            .unwrap();
        assert!(config.verify_access_token(&token).is_ok());
    }
}
