# OIDC/OAuth Authentication Setup for AdminUI

This document describes the OIDC/OAuth authentication integration between the GoSignals Admin UI, goSignalsServer, and Keycloak.

## Overview

The adminUI now includes:
- OIDC/OAuth login integration with Keycloak
- Federated sign-in support across multiple goSignalsServer instances
- Login state tracking with automatic token renewal
- Login/logout UI with user display in the header
- Authorization token handling for API requests

## Architecture

### Components

1. **Keycloak** (port 8080): Identity provider (IdP)
   - Realm: `gosignals`
   - Client: `adminui`
   - Default users: admin/admin, user/user

2. **goSignalsServer** (ports 8888, 8889): Resource server
   - Provides OIDC discovery endpoint: `/.well-known/openid-configuration`
   - Validates OIDC tokens from adminUI via `internal/authUtil`

3. **AdminUI** (port 8899): Client application
   - Single Page Application with OIDC authentication
   - Automatically attaches bearer tokens to API requests

## Setup Instructions

### 1. Start the Services

```bash
# Start all services with docker-compose
docker-compose up -d

# This will start:
# - Keycloak on http://localhost:8080
# - goSignalsServer instances on http://localhost:8888 and http://localhost:8889
# - AdminUI on http://localhost:8899
```

### 2. Verify Keycloak Configuration

Access Keycloak Admin Console:
- URL: http://localhost:8080/admin
- Username: admin
- Password: (from .env file - KEYCLOAK_ADMIN_PASSWORD)

The `gosignals` realm should be automatically imported with:
- Client `adminui` configured for authorization code flow with PKCE
- Users `admin` and `user` with passwords
- Roles `admin` and `user`

### 3. Access AdminUI

Navigate to http://localhost:8899

- Click "Login" button in the top-right corner
- You'll be redirected to Keycloak login page
- Enter credentials (admin/admin or user/user)
- After successful login, you'll be redirected back to adminUI
- Your user information will be displayed in the top-right corner

### 4. Environment Variables

The following environment variables can be configured:

**For AdminUI** (via `.env` or Vite environment):
```
VITE_KEYCLOAK_URL=http://localhost:8080/realms/gosignals
VITE_GOSIGNALS_SERVER_URL=http://localhost:8888
```

**For goSignalsServer**:
```
KEYCLOAK_URL=http://localhost:8080/realms/gosignals
```

## Features

### 1. OIDC Discovery

The goSignalsServer provides an OIDC discovery endpoint that the adminUI uses to automatically configure authentication:

```
GET /.well-known/openid-configuration
```

This returns the Keycloak endpoints for authorization, token, userinfo, etc.

### 2. Login State Tracking

- Tokens are stored in browser's sessionStorage
- Automatic silent token renewal before expiration
- Token refresh handled transparently by oidc-client-ts

### 3. Federated Sign-In

Multiple goSignalsServer instances can share the same Keycloak realm:
- Single sign-on across all instances
- Tokens issued by Keycloak are valid for all instances
- User identity is consistent across the federation

### 4. API Authorization

The adminUI automatically includes bearer tokens in API requests:

```javascript
import { useAuth } from './lib/auth/AuthContext';
import { createApiClient, createApiService } from './lib/apiClient';

function MyComponent() {
  const { getAccessToken } = useAuth();
  const apiClient = createApiClient(getAccessToken);
  const api = createApiService(apiClient);
  
  // API calls automatically include Authorization: Bearer <token>
  const streams = await api.getStreams();
}
```

### 5. Token Validation

The goSignalsServer validates OIDC tokens using `internal/authUtil`:

```go
// Validate OIDC token from adminUI
claims, err := authIssuer.ValidateOidcToken(tokenString)
if err != nil {
    // Handle invalid token
}

// Use middleware for protected endpoints
router.Use(authIssuer.ValidateOidcAuthorizationMiddleware)
```

## Security Considerations

1. **PKCE**: The adminUI uses PKCE (Proof Key for Code Exchange) for additional security
2. **Public Client**: The adminUI is configured as a public client (no client secret)
3. **HTTPS**: For production, all services should use HTTPS
4. **CORS**: Configure appropriate CORS settings for production
5. **Token Storage**: Tokens are stored in sessionStorage (cleared on browser close)

## Testing

### Test Login Flow

1. Navigate to http://localhost:8899
2. Click "Login"
3. Enter credentials on Keycloak page
4. Verify redirect back to adminUI
5. Check that user menu shows user information

### Test Token Refresh

1. Login to adminUI
2. Wait for token to approach expiration (default: 1 hour)
3. Token should automatically refresh via silent iframe
4. API calls should continue to work without re-login

### Test Logout

1. Click on user avatar in top-right corner
2. Select "Log out"
3. Verify redirect to Keycloak logout
4. Verify redirect back to adminUI
5. Verify "Login" button is shown again

## Troubleshooting

### Login Fails

1. Check Keycloak is running: http://localhost:8080
2. Verify realm `gosignals` exists
3. Check client `adminui` is enabled
4. Verify redirect URIs include `http://localhost:8899/*`

### Token Validation Fails

1. Check goSignalsServer can access Keycloak
2. Verify KEYCLOAK_URL environment variable
3. Check token expiration
4. Verify JWT signature matches Keycloak's signing key

### CORS Errors

1. Verify Keycloak client has correct web origins
2. Check goSignalsServer CORS configuration
3. Ensure all URLs use same protocol (http/https)

## Development

### Running AdminUI in Dev Mode

```bash
cd adminUI
npm install
npm run dev
```

This starts Vite dev server on http://localhost:5173

Update Keycloak client redirect URIs to include:
- http://localhost:5173/*

### Building for Production

```bash
cd adminUI
npm run build
```

Built files are placed in `adminUI/build/` directory and served by goSignalsServer on port 8899.

## API Reference

### OIDC Discovery Endpoint

**GET** `/.well-known/openid-configuration`

Returns OIDC provider metadata including:
- issuer
- authorization_endpoint
- token_endpoint
- userinfo_endpoint
- end_session_endpoint
- jwks_uri

### Auth Context Hook

```typescript
const {
  user,              // User object with profile information
  isAuthenticated,   // Boolean: is user logged in
  isLoading,         // Boolean: is auth state loading
  login,             // Function: initiate login flow
  logout,            // Function: initiate logout flow
  getAccessToken,    // Function: get current access token
} = useAuth();
```

### API Client

```typescript
import { createApiClient, createApiService } from './lib/apiClient';

const apiClient = createApiClient(getAccessToken);
const api = createApiService(apiClient);

// Available methods:
api.getStreams()
api.getStream(streamId)
api.createStream(streamData)
api.updateStream(streamData)
api.deleteStream(streamId)
api.getStatus(streamId)
api.updateStatus(streamId, statusData)
api.triggerEvent(eventData)
api.registerClient(clientData)
api.getSsfConfiguration()
```

## Additional Resources

- [OIDC Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [oidc-client-ts Library](https://github.com/authts/oidc-client-ts)
