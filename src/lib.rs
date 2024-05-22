mod error;

use error::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::Sha512;


#[derive(Clone)]
pub struct EncryptionData<'a> {
    pub content: &'a str,
    pub salt: &'a str,
}

#[derive(Clone)]
pub struct PasswordEncryptor {
    key: Vec<u8>,
    encryption_prefix: Option<String>,
}

impl PasswordEncryptor {
    pub fn new(key: Vec<u8>, encryption_prefix: Option<String>) -> Self {
        Self {
            key,
            encryption_prefix,
        }
    }
}

impl PasswordEncryptor {
    fn encrypt_into_base64url(
        &self,
        key: &[u8],
        encryption_data: &EncryptionData,
    ) -> Result<String> {
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

    pub fn encrypt_password(&self, encryption_data: &EncryptionData) -> Result<String> {
        let encrypted = self.encrypt_into_base64url(&self.key, encryption_data)?;
        let final_prefix = self.encryption_prefix.clone().unwrap_or("".to_string());
        Ok(format!("{final_prefix}{encrypted}"))
    }

    pub fn validate_password(
        &self,
        encryption_data: &EncryptionData,
        encrypted_password: &str,
    ) -> Result<()> {
        let inner_encrypted_password = self.encrypt_password(encryption_data)?;
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
        let encryptor = PasswordEncryptor::new(vec![1,2,3], None);
        let data = EncryptionData {
            content: "password123",
            salt: "salt",
        };

        let encrypted = encryptor.encrypt_password(&data).unwrap();
        assert!(!encrypted.is_empty())
    }

    #[test]
    fn test_validation_success() {
        let encryptor = PasswordEncryptor::new(vec![1,2,3], None);
        let data = EncryptionData {
            content: "password123",
            salt: "salt",
        };

        let encrypted = encryptor.encrypt_password(&data).unwrap();
        assert!(encryptor.validate_password(&data, &encrypted).is_ok());
    }

    #[test]
    fn test_validation_failure() {
        let encryptor = PasswordEncryptor::new(vec![1,2,3], Some("prefix_".to_string()));
        let data = EncryptionData {
            content: "password123",
            salt: "salt",
        };

        assert!(encryptor
            .validate_password(&data, "wrong_password")
            .is_err());
    }

    #[test]
    fn test_password_mismatch_error() {
        let encryptor = PasswordEncryptor::new(vec![1,2,3], Some("prefix_".to_string()));
        let data = EncryptionData {
            content: "password123",
            salt: "salt",
        };

        let wrong_data = EncryptionData {
            content: "wrong_password",
            salt: "salt",
        };

        let encrypted = encryptor.encrypt_password(&data).unwrap();
        match encryptor.validate_password(&wrong_data, &encrypted) {
            Err(Error::PasswordsDontMatch) => (),
            _ => panic!("Expected PasswordsDontMatch error"),
        }
    }
}
