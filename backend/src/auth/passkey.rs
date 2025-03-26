use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use mongodb::bson::DateTime;
use rocket::tokio::{spawn, time::sleep};
use std::time::Duration;
use mongodb::bson::Uuid;

use crate::{models::{user::User, passkey_error::PasskeyError}, PASSKEY_SESSIONS};

/// Structure to hold passkey challenge data
#[derive(Debug, Clone)]
pub struct PasskeyChallenge {
    pub challenge_id: String,
    pub challenge: String,
    pub user: Option<User>,
    pub created_at: DateTime,
    pub expires_at: DateTime,
}

#[derive(Debug, Clone)]
pub enum PasskeyOperation {
    Registration,
    Authentication,
}

/// Handler struct for passkey operations
pub struct PasskeyHandler;

impl PasskeyHandler {
    /// Generate a challenge for passkey registration or authentication
    pub async fn generate_challenge(
        _operation: PasskeyOperation,
        user: Option<User>,
    ) -> Result<PasskeyChallenge, PasskeyError> {
        // Generate a cryptographically secure random challenge
        let mut challenge_bytes = [0u8; 32];
        rand::Rng::fill(&mut rand::rng(), &mut challenge_bytes);
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);
        
        let now = DateTime::now();
        // Challenge expires after 5 minutes
        let expires_at = DateTime::from_millis(now.timestamp_millis() + 5 * 60 * 1000);
        
        let challenge_data = PasskeyChallenge {
            challenge_id: Uuid::new().to_string(),
            challenge,
            user,
            created_at: now,
            expires_at,
        };

        // Store challenge in memory
        let mut passkey_sessions = PASSKEY_SESSIONS.lock().await;
        passkey_sessions.insert(challenge_data.challenge_id.clone(), challenge_data.clone());
        drop(passkey_sessions);

        // Schedule cleanup of expired challenge
        let challenge_id = challenge_data.challenge_id.clone();
        spawn(async move {
            sleep(Duration::from_secs(300)).await;
            
            let mut passkey_sessions = PASSKEY_SESSIONS.lock().await;
            passkey_sessions.remove(&challenge_id);
        });

        Ok(challenge_data)
    }
    
    /// Get stored challenge by ID
    pub async fn get_challenge_by_id(challenge_id: &str) -> Option<PasskeyChallenge> {
        let passkey_sessions = PASSKEY_SESSIONS.lock().await;
        passkey_sessions.get(challenge_id).cloned()
    }
    
    /// Remove challenge from storage
    pub async fn remove_challenge(challenge_id: &str) {
        let mut passkey_sessions = PASSKEY_SESSIONS.lock().await;
        passkey_sessions.remove(challenge_id);
    }
    
    /// Check if challenge is valid (not expired and matches)
    pub fn is_challenge_valid(challenge: &PasskeyChallenge, challenge_response: &str) -> bool {
        if DateTime::now() > challenge.expires_at {
            return false;
        }
        
        challenge.challenge == challenge_response
    }
    
    /// Verify a WebAuthn attestation from registration
    pub fn verify_registration(
        credential_id: &str,
        public_key: &str,
        _challenge: &str,
        _client_data: &str,
        _attestation_object: &str,
    ) -> Result<bool, PasskeyError> {
        // In a real implementation, this would verify the WebAuthn attestation
        // But for now we'll accept all registrations with valid challenge
        
        // Check public key format
        if public_key.is_empty() {
            return Err(PasskeyError::InvalidPublicKey);
        }
        
        // Check credential ID
        if credential_id.is_empty() {
            return Err(PasskeyError::InvalidCredentialId);
        }
        
        // We're accepting all registrations with a valid challenge for now
        Ok(true)
    }
    
    /// Verify a WebAuthn assertion from authentication
    pub fn verify_authentication(
        credential_id: &str,
        _challenge: &str,
        _signature: &str,
        _client_data: &str,
        _authenticator_data: &str,
        user: &User,
        counter: u32,
    ) -> Result<bool, PasskeyError> {
        // In a real implementation, this would verify the WebAuthn assertion
        // But for now we'll just check if the passkey exists for this user
        
        // Find the passkey with the matching credential ID
        let passkey = match user.get_passkey_by_credential_id(credential_id) {
            Some(pk) => pk,
            None => return Err(PasskeyError::CredentialNotFound),
        };
        
        // Check for replay attacks (counter should be greater than stored counter)
        if counter <= passkey.counter {
            return Err(PasskeyError::ReplayAttack);
        }
        
        // We're accepting all authentications with a valid challenge for now
        Ok(true)
    }
} 