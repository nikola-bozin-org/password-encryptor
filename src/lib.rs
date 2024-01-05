mod error;

use error::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::Sha512;

pub struct EncryptionData {
    pub content: String,
    pub salt: String,
}

pub struct PasswordEncryptor<'a> {
    pub key: &'a [u8],
    pub encryption_prefix: String,
}

impl<'a> PasswordEncryptor<'a> {
    pub fn new(key: &'a [u8], encryption_prefix: Option<String>) -> Self {
        Self {
            key,
            encryption_prefix: encryption_prefix.unwrap_or("".to_string()),
        }
    }
}

impl<'a> PasswordEncryptor<'a> {
    fn encrypt_into_b64u(&self, key: &'a [u8], encryption_data: &EncryptionData) -> Result<String> {
        let EncryptionData { content, salt } = encryption_data;

        let mut hmac_sha512 =
            Hmac::<Sha512>::new_from_slice(key).map_err(|_| Error::KeyFailHmac)?;

        hmac_sha512.update(content.as_bytes());
        hmac_sha512.update(salt.as_bytes());

        let hmac_result = hmac_sha512.finalize();
        let result_bytes = hmac_result.into_bytes();

        let result = base64_url::encode(&result_bytes);

        Ok(result)
    }

    pub fn encrypt_pwd(&self, encryption_data: &EncryptionData) -> Result<String> {
        let encrypted = self.encrypt_into_b64u(self.key, encryption_data)?;
        let final_prefix = &self.encryption_prefix;
        Ok(format!("{final_prefix}{encrypted}"))
    }

    pub fn validate_pwd(
        &self,
        encryption_data: &EncryptionData,
        encrypted_password: &str,
    ) -> Result<()> {
        let inner_encrypted_password = self.encrypt_pwd(encryption_data)?;
        if inner_encrypted_password == encrypted_password {
            Ok(())
        } else {
            Err(Error::PasswordsDontMatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_successful_encryption() {
        let encryptor = PasswordEncryptor::new(b"secret_key", Some("prefix_".to_string()));
        let data = EncryptionData {
            content: "password123".to_string(),
            salt: "salt".to_string(),
        };

        let encrypted = encryptor.encrypt_pwd(&data).unwrap();
        assert!(encrypted.starts_with("prefix_"));
    }

    #[test]
    fn test_validation_success() {
        let encryptor = PasswordEncryptor::new(b"secret_key", Some("prefix_".to_string()));
        let data = EncryptionData {
            content: "password123".to_string(),
            salt: "salt".to_string(),
        };

        let encrypted = encryptor.encrypt_pwd(&data).unwrap();
        assert!(encryptor.validate_pwd(&data, &encrypted).is_ok());
    }

    #[test]
    fn test_validation_failure() {
        let encryptor = PasswordEncryptor::new(b"secret_key", Some("prefix_".to_string()));
        let data = EncryptionData {
            content: "password123".to_string(),
            salt: "salt".to_string(),
        };

        assert!(encryptor.validate_pwd(&data, "wrong_password").is_err());
    }

    #[test]
    fn test_password_mismatch_error() {
        let encryptor = PasswordEncryptor::new(b"secret_key", Some("prefix_".to_string()));
        let data = EncryptionData {
            content: "password123".to_string(),
            salt: "salt".to_string(),
        };

        let wrong_data = EncryptionData {
            content: "wrong_password".to_string(),
            salt: "salt".to_string(),
        };

        let encrypted = encryptor.encrypt_pwd(&data).unwrap();
        match encryptor.validate_pwd(&wrong_data, &encrypted) {
            Err(Error::PasswordsDontMatch) => (),
            _ => panic!("Expected PasswordsDontMatch error"),
        }
    }
}
