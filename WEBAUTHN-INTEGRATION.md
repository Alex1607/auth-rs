# WebAuthn Integration Guide

This guide explains how to integrate passkey (WebAuthn) authentication with the Auth-RS backend in your frontend application.

## Overview

Auth-RS supports three authentication methods:
1. Traditional username/password authentication
2. Passkey (WebAuthn) authentication
3. Multi-factor authentication (MFA)

Passkeys provide a more secure alternative to passwords, using public key cryptography and biometric verification.

## Authentication Flows

### 1. Traditional Password Flow

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "user-password"
}
```

### 2. Passkey Authentication Flow

When a user wants to authenticate with a passkey, the process involves two steps:

#### Step 1: Initiate Authentication Challenge

```http
POST /auth/passkey/login/start
Content-Type: application/json

{
  "email": "user@example.com"
}
```

Response:
```json
{
  "status": 200,
  "message": "Authentication challenge created",
  "data": {
    "challenge": "base64-encoded-challenge-string",
    "rpId": "your-domain.com",
    "timeout": 60000,
    "userVerification": "preferred",
    "allowCredentials": [
      {
        "id": "base64-credential-id",
        "type": "public-key"
      }
    ]
  }
}
```

#### Step 2: Complete Authentication

After the user completes the challenge with their authenticator:

```http
POST /auth/passkey/login/finish
Content-Type: application/json

{
  "id": "credential-id",
  "rawId": "base64-encoded-raw-id",
  "response": {
    "clientDataJSON": "base64-encoded-client-data",
    "authenticatorData": "base64-encoded-authenticator-data",
    "signature": "base64-encoded-signature",
    "userHandle": "base64-encoded-user-handle"
  },
  "type": "public-key"
}
```

Response (successful authentication):
```json
{
  "status": 200,
  "message": "Authentication successful",
  "data": {
    "user": {
      "_id": "user-uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "roles": ["uuid-1", "uuid-2"],
      "has_passkeys": true,
      "mfa": false,
      "disabled": false,
      "createdAt": "2023-10-01T12:00:00Z"
    },
    "token": "user-auth-token"
  }
}
```

## Registering Passkeys

Users must be authenticated to register passkeys. The process is similar to authentication:

### 1. Start Registration

```http
POST /auth/passkey/register/start
Content-Type: application/json

{
  "name": "My Passkey" 
}
```

Response:
```json
{
  "status": 200,
  "message": "Registration options created",
  "data": {
    "rp": {
      "name": "Your Application",
      "id": "your-domain.com"
    },
    "user": {
      "id": "base64-encoded-user-id",
      "name": "user@example.com",
      "displayName": "John Doe"
    },
    "challenge": "base64-encoded-challenge",
    "pubKeyCredParams": [
      {
        "type": "public-key",
        "alg": -7
      }
    ],
    "timeout": 60000,
    "attestation": "none",
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "requireResidentKey": true,
      "userVerification": "preferred"
    }
  }
}
```

### 2. Complete Registration

```http
POST /auth/passkey/register/finish
Content-Type: application/json

{
  "id": "credential-id",
  "rawId": "base64-encoded-raw-id",
  "response": {
    "clientDataJSON": "base64-encoded-client-data",
    "attestationObject": "base64-encoded-attestation-object"
  },
  "type": "public-key"
}
```

## Frontend Implementation

### Required Libraries

For WebAuthn in the browser, we recommend using the `@simplewebauthn/browser` library:

```bash
npm install @simplewebauthn/browser
```

### Example Implementation

```javascript
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

// For passkey registration (user must be logged in)
async function registerPasskey() {
  try {
    // 1. Get registration options from server
    const nameForPasskey = "My Work Laptop";
    const optionsResponse = await fetch('/auth/passkey/register/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({ name: nameForPasskey })
    });
    
    const optionsData = await optionsResponse.json();
    
    // 2. Pass options to browser API
    const registrationResponse = await startRegistration(optionsData.data);
    
    // 3. Send response to server for verification
    const verificationResponse = await fetch('/auth/passkey/register/finish', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify(registrationResponse)
    });
    
    const verificationResult = await verificationResponse.json();
    
    if (verificationResult.status === 200) {
      alert('Passkey registered successfully!');
    } else {
      alert(`Error: ${verificationResult.message}`);
    }
  } catch (error) {
    console.error('Passkey registration failed:', error);
    alert('Passkey registration failed. See console for details.');
  }
}

// For passkey authentication
async function authenticateWithPasskey(email) {
  try {
    // 1. Get authentication options from server
    const optionsResponse = await fetch('/auth/passkey/login/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email })
    });
    
    const optionsData = await optionsResponse.json();
    
    // 2. Pass options to browser API
    const authenticationResponse = await startAuthentication(optionsData.data);
    
    // 3. Send response to server for verification
    const verificationResponse = await fetch('/auth/passkey/login/finish', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(authenticationResponse)
    });
    
    const verificationResult = await verificationResponse.json();
    
    if (verificationResult.status === 200) {
      // Store token and redirect to authenticated area
      localStorage.setItem('authToken', verificationResult.data.token);
      window.location.href = '/dashboard';
    } else {
      alert(`Authentication error: ${verificationResult.message}`);
    }
  } catch (error) {
    console.error('Passkey authentication failed:', error);
    alert('Passkey authentication failed. See console for details.');
  }
}

// Login flow example
async function login() {
  const email = document.getElementById('email').value;
  
  // Offer both authentication options directly without checking /auth/options
  const usePasskey = document.getElementById('use-passkey').checked;
  
  if (usePasskey) {
    await authenticateWithPasskey(email);
    return;
  }
  
  // Otherwise, continue with password login
  const password = document.getElementById('password').value;
  
  try {
    const response = await fetch('/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, password })
    });
    
    const result = await response.json();
    
    if (result.status === 200) {
      if (result.data.mfa_required) {
        // Redirect to MFA verification flow
        handleMfaFlow(result.data.mfa_flow_id);
      } else if (result.data.use_passkey) {
        // User has passkeys, suggest using them
        if (confirm('Would you like to use a passkey for more secure login?')) {
          await authenticateWithPasskey(email);
        } else {
          // User declined to use passkey, proceed with password login
          // (You may need to handle this case depending on your backend configuration)
        }
      } else {
        // Traditional login successful
        localStorage.setItem('authToken', result.data.token);
        window.location.href = '/dashboard';
      }
    } else {
      alert(`Authentication error: ${result.message}`);
    }
  } catch (error) {
    console.error('Login failed:', error);
    alert('Login failed. See console for details.');
  }
}
```

## Managing Passkeys

Authenticated users can manage their passkeys through these endpoints:

### List Passkeys

```http
GET /auth/passkey
```

### Delete a Passkey

```http
DELETE /auth/passkey/{passkey_id}
```

## Security Considerations

1. Always use HTTPS for WebAuthn operations
2. Set appropriate timeouts for challenges (default is 60 seconds)
3. Implement proper error handling for all authentication scenarios
4. Consider the user experience when transitioning between authentication methods
5. Store tokens securely (HttpOnly cookies or secure local storage)

## Browser Support

WebAuthn is supported in all major browsers:
- Chrome 67+
- Firefox 60+
- Safari 13+
- Edge 79+

For older browsers, always fall back to password authentication.

## Testing

For local development testing:
1. Configure your application to use `localhost` as the RP ID
2. Most browsers allow registering test authenticators on localhost
3. Use security keys or biometric authentication if available on your device

For production testing:
1. Use actual security keys or platform authenticators
2. Test across different devices and browsers
3. Verify that credential exclusion works properly when registering multiple passkeys

## Resources

- [W3C WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [SimpleWebAuthn Documentation](https://simplewebauthn.dev/)
- [Auth-RS API Documentation](/api-docs) 