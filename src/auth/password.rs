//! Password hashing with Argon2id.

use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher as Argon2PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2, Params,
};
use rand::rngs::OsRng;

#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
        }
    }
}

impl PasswordPolicy {
    pub fn complex(min_length: usize) -> Self {
        Self {
            min_length,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
        }
    }

    pub fn validate(&self, password: &str) -> Result<(), PasswordPolicyError> {
        if password.len() < self.min_length {
            return Err(PasswordPolicyError::TooShort {
                min_length: self.min_length,
            });
        }

        if self.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(PasswordPolicyError::MissingUppercase);
        }

        if self.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
            return Err(PasswordPolicyError::MissingLowercase);
        }

        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(PasswordPolicyError::MissingDigit);
        }

        if self.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err(PasswordPolicyError::MissingSpecial);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum PasswordPolicyError {
    TooShort { min_length: usize },
    MissingUppercase,
    MissingLowercase,
    MissingDigit,
    MissingSpecial,
}

impl std::fmt::Display for PasswordPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordPolicyError::TooShort { min_length } => {
                write!(f, "Password must be at least {} characters", min_length)
            }
            PasswordPolicyError::MissingUppercase => {
                write!(f, "Password must contain at least one uppercase letter")
            }
            PasswordPolicyError::MissingLowercase => {
                write!(f, "Password must contain at least one lowercase letter")
            }
            PasswordPolicyError::MissingDigit => {
                write!(f, "Password must contain at least one digit")
            }
            PasswordPolicyError::MissingSpecial => {
                write!(f, "Password must contain at least one special character")
            }
        }
    }
}

impl std::error::Error for PasswordPolicyError {}

pub struct PasswordService;

impl PasswordService {
    pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
        Self::hash_password_with_cost(password, 12)
    }

    /// Hashes a password using Argon2id with configurable memory cost.
    ///
    /// The cost parameter controls the memory usage (in KiB = 2^cost).
    /// Recommended values:
    /// - 12: ~4MB memory, suitable for development/testing
    /// - 16: ~64MB memory, suitable for production
    /// - 19: ~512MB memory, high security requirements
    pub fn hash_password_with_cost(
        password: &str,
        memory_cost_log2: u32,
    ) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);

        let m_cost = 1u32 << memory_cost_log2.min(22); // Cap at 4GB

        let params =
            Params::new(m_cost, 3, 1, None).map_err(|_| argon2::password_hash::Error::Algorithm)?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(password_hash.to_string())
    }

    pub fn verify_password(
        password: &str,
        password_hash: &str,
    ) -> Result<bool, argon2::password_hash::Error> {
        let parsed_hash = PasswordHash::new(password_hash)?;
        let argon2 = Argon2::default();
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let password = "secure_password_123";
        let hash = PasswordService::hash_password(password).expect("Hashing should succeed");

        let is_valid =
            PasswordService::verify_password(password, &hash).expect("Verification should succeed");
        assert!(is_valid);
    }

    #[test]
    fn test_wrong_password_fails() {
        let password = "correct_password";
        let hash = PasswordService::hash_password(password).expect("Hashing should succeed");

        let is_valid = PasswordService::verify_password("wrong_password", &hash)
            .expect("Verification should succeed");
        assert!(!is_valid);
    }

    #[test]
    fn test_unique_salts() {
        let password = "same_password";
        let hash1 = PasswordService::hash_password(password).expect("Hashing should succeed");
        let hash2 = PasswordService::hash_password(password).expect("Hashing should succeed");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_format() {
        let hash = PasswordService::hash_password("test").expect("Hashing should succeed");
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_password_policy_default() {
        let policy = PasswordPolicy::default();
        assert!(policy.validate("password").is_ok());
        assert!(policy.validate("short").is_err());
    }

    #[test]
    fn test_password_policy_complex() {
        let policy = PasswordPolicy::complex(8);

        assert!(policy.validate("password1!").is_err());

        assert!(policy.validate("PASSWORD1!").is_err());

        assert!(policy.validate("Password!").is_err());

        assert!(policy.validate("Password1").is_err());

        assert!(policy.validate("Password1!").is_ok());
    }

    #[test]
    fn test_password_policy_error_messages() {
        let policy = PasswordPolicy::complex(10);

        let err = policy.validate("short").unwrap_err();
        assert!(err.to_string().contains("10 characters"));

        let policy = PasswordPolicy::complex(8);
        let err = policy.validate("password1!").unwrap_err();
        assert!(err.to_string().contains("uppercase"));
    }

    #[test]
    fn test_hash_with_custom_cost() {
        let password = "test_password";
        let hash =
            PasswordService::hash_password_with_cost(password, 4).expect("Hashing should succeed");

        assert!(hash.starts_with("$argon2id$"));
        let is_valid =
            PasswordService::verify_password(password, &hash).expect("Verification should succeed");
        assert!(is_valid);
    }
}
