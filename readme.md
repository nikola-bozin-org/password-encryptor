# Password Encryptor

This crate provides a secure way to encrypt and validate passwords using HMAC with SHA-512 hashing and base64 URL-safe encoding. This crate is designed to help developers protect user passwords effectively in their applications.

# Installation

`cargo add password_encryptor`

or add it to the dependencies

```rust
[dependencies]
password_encryptor = "0.1.3"
```

# Usage

## Import 

```rust
use password_encryptor::{EncryptionData, PasswordEncryptor};
```

## Example functions 


```rust
pub fn encrypt_password(password: String, salt: String) -> String {
    let encryptor = PasswordEncryptor::new(b"secret_key", Some("prefix_".to_string()));
    let data = EncryptionData {
        content: password,
        salt,
    };

    let encrypted_password = encryptor.encrypt_pwd(&data);
    match encrypted_password {
        Ok(result) => result,
        Err(e) => {
            format!("Unable to encrypt password. {:?}", e)
        }
    }
}

pub fn validate_password(password: String, encrypted_password: String, salt: String) -> bool {
    let encryptor = PasswordEncryptor::new(b"secret_key", Some("prefix_".to_string()));
    let data = EncryptionData {
        content: password,
        salt,
    };
    let is_valid_password = encryptor.validate_pwd(&data, &encrypted_password);
    is_valid_password.is_ok()
}
```