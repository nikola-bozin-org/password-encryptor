# Password Encryptor

This crate provides a secure way to encrypt and validate passwords using HMAC with SHA-512 hashing and base64 URL-safe encoding. This crate is designed to help developers protect user passwords effectively in their applications.

# Installation

```
cargo add password_encryptor
```

or add it to the dependencies

```rust
[dependencies]
password_encryptor = "1.0.0"
```

# Usage

## Import 

```rust
use password_encryptor::{EncryptionData, PasswordEncryptor};
```

## Example functions 

### Note: Make sure that `encryption_prefix` is the same for encryption and validation. If you dont want to use prefix, just pass `None` instead.

```rust
pub fn encrypt_password(password: String, salt: String) -> String {
    let encryptor = PasswordEncryptor::new(b"secret_key", Some("prefix_"));
    let data = EncryptionData {
        content: password,
        salt,
    };

    let encrypted_password = encryptor.encrypt_password(&data);
    match encrypted_password {
        Ok(result) => result,
        Err(e) => {
            format!("Unable to encrypt password. {:?}", e)
        }
    }
}

pub fn validate_password(password: String, encrypted_password: String, salt: String) -> bool {
    let encryptor = PasswordEncryptor::new(b"secret_key", Some("prefix_"));
    let data = EncryptionData {
        content: password,
        salt,
    };
    let is_valid_password = encryptor.validate_password(&data, &encrypted_password);
    is_valid_password.is_ok()
}
```

# Test cases

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_password() {
        let password = "test_password".to_string();
        let salt = "random_salt".to_string();

        let encrypted_password = encrypt_password(password.clone(), salt.clone());
        assert!(!encrypted_password.contains("Unable to encrypt password."), "Encryption should succeed without errors.");
    }

    #[test]
    fn test_validate_password_success() {
        let password = "test_password".to_string();
        let salt = "random_salt".to_string();
        let encrypted_password = encrypt_password(password.clone(), salt.clone());

        assert!(validate_password(password, encrypted_password, salt), "Password validation should succeed.");
    }

    #[test]
    fn test_validate_password_failure() {
        let password = "test_password".to_string();
        let wrong_password = "wrong_password".to_string();
        let salt = "random_salt".to_string();
        let encrypted_password = encrypt_password(password, salt.clone());

        assert!(!validate_password(wrong_password, encrypted_password, salt), "Password validation should fail with incorrect password.");
    }
}

```
