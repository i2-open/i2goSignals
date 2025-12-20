# OIDC/OAuth Implementation Summary

This document summarizes the OIDC/OAuth authentication integration implemented for the GoSignals administrative interface.

## What Was Implemented

### 1. Backend (goSignalsServer)

#### OIDC Discovery Endpoint
- **File**: `pkg/goSSEF/server/api_stream_management.go`
- **Endpoint**: `GET /.well-known/openid-configuration`
- **Route**: Added to `pkg/goSSEF/server/routers.go`
- **Purpose**: Provides OIDC provider metadata for adminUI to discover Keycloak endpoints

#### Token Validation
- **File**: `internal/authUtil/auth_token.go`
- **Added**:
  - `OidcClaims` struct for OIDC token claims
  - `ValidateOidcToken()` function to validate Keycloak tokens
  - `ValidateOidcAuthorizationMiddleware()` for protected endpoints
- **Purpose**: Validates OIDC tokens from adminUI and extracts user information

### 2. Keycloak Configuration

#### Realm Configuration
- **File**: `config/keycloak/realm/gosignals-realm.json`
- **Realm**: `gosignals`
- **Client**: `adminui` (public client with PKCE)
- **Users**: 
  - admin/admin (admin role)
  - user/user (user role)
- **Purpose**: Pre-configured realm for easy setup

### 3. Frontend (adminUI)

#### Authentication Library
- **Added**: `oidc-client-ts@3.2.1` to package.json
- **Added**: `axios@1.7.2` for API client

#### Auth Configuration
- **File**: `adminUI/src/lib/auth/authConfig.ts`
- **Purpose**: OIDC client configuration with Keycloak endpoints

#### Auth Context
- **File**: `adminUI/src/lib/auth/AuthContext.tsx`
- **Exports**: 
  - `AuthProvider` component
  - `useAuth()` hook
  - `handleCallback()` and `handleSilentCallback()` utilities
- **Features**:
  - Login state management
  - Automatic token renewal
  - Token storage in sessionStorage

#### UI Components
- **File**: `adminUI/src/components/UserMenu.tsx`
- **Features**:
  - Login button when not authenticated
  - User avatar with dropdown menu when authenticated
  - Displays username and email
  - Logout functionality

#### Callback Page
- **File**: `adminUI/src/components/AuthCallback.tsx`
- **Purpose**: Handles OAuth redirect after Keycloak authentication

#### Silent Callback
- **File**: `adminUI/public/silent-callback.html`
- **Purpose**: Handles silent token renewal in iframe

#### API Client
- **File**: `adminUI/src/lib/apiClient.ts`
- **Features**:
  - Axios instance with bearer token interceptor
  - Automatic token attachment to requests
  - Error handling for 401 responses
  - Pre-configured API service methods

#### Application Updates
- **File**: `adminUI/src/App.tsx`
- **Changes**: Added UserMenu component to header
- **File**: `adminUI/src/main.tsx`
- **Changes**: 
  - Wrapped App with AuthProvider
  - Added simple routing for callback page

### 4. Documentation
- **File**: `adminUI/OIDC_SETUP.md`
- **Content**: Complete setup guide, usage instructions, and API reference

## Key Features

### 1. OIDC/OAuth Login Integration
- Authorization Code Flow with PKCE (most secure for SPAs)
- Integration with Keycloak as identity provider
- Automatic token management

### 2. Federated Sign-In
- Multiple goSignalsServer instances can share the same Keycloak realm
- Single sign-on across all instances
- Consistent user identity across federation

### 3. Login State Tracking
- Tokens stored in sessionStorage (cleared on browser close)
- Automatic silent token renewal before expiration
- Persistent login across page refreshes (within session)

### 4. Login/Logout UI
- Login button in header when not authenticated
- User avatar with dropdown menu showing:
  - Username
  - Email
  - Logout option
- Located in upper right corner of adminUI

### 5. Authorization Token Handling
- Automatic bearer token attachment to all API requests
- Token interceptor in axios client
- Error handling for expired/invalid tokens

### 6. OIDC Discovery
- goSignalsServer provides OIDC discovery endpoint
- adminUI can dynamically discover authentication endpoints
- Supports standard OIDC discovery protocol

### 7. Token Validation
- goSignalsServer validates OIDC tokens from Keycloak
- Middleware available for protecting API endpoints
- Extracts user information from validated tokens

## Architecture Flow

```
1. User accesses adminUI (http://localhost:8899)
2. User clicks "Login" button
3. adminUI redirects to Keycloak (http://localhost:8080/realms/gosignals)
4. User enters credentials on Keycloak page
5. Keycloak redirects back to adminUI with authorization code
6. adminUI exchanges code for tokens (access_token, refresh_token, id_token)
7. adminUI stores tokens in sessionStorage
8. User info displayed in header
9. API requests to goSignalsServer include bearer token
10. goSignalsServer validates token with Keycloak's public key
11. Before token expiration, adminUI silently refreshes token
12. On logout, adminUI clears tokens and redirects to Keycloak logout
```

## Environment Variables

### goSignalsServer
- `KEYCLOAK_URL`: Keycloak realm URL (default: http://localhost:8080/realms/gosignals)

### adminUI (Vite)
- `VITE_KEYCLOAK_URL`: Keycloak realm URL (default: http://localhost:8080/realms/gosignals)
- `VITE_GOSIGNALS_SERVER_URL`: goSignalsServer URL (default: http://localhost:8888)

## Files Created/Modified

### Created
1. `pkg/goSSEF/server/api_stream_management.go` - Added OidcConfiguration handler
2. `internal/authUtil/auth_token.go` - Added OIDC token validation
3. `config/keycloak/realm/gosignals-realm.json` - Keycloak realm configuration
4. `adminUI/src/lib/auth/authConfig.ts` - OIDC client configuration
5. `adminUI/src/lib/auth/AuthContext.tsx` - Auth state management
6. `adminUI/src/lib/apiClient.ts` - API client with token interceptor
7. `adminUI/src/components/UserMenu.tsx` - Login/logout UI component
8. `adminUI/src/components/AuthCallback.tsx` - OAuth callback handler
9. `adminUI/public/silent-callback.html` - Silent token renewal page
10. `adminUI/OIDC_SETUP.md` - Setup and usage documentation
11. `OIDC_IMPLEMENTATION.md` - This summary document

### Modified
1. `pkg/goSSEF/server/routers.go` - Added OIDC discovery route
2. `adminUI/package.json` - Added oidc-client-ts and axios dependencies
3. `adminUI/src/App.tsx` - Added UserMenu to header
4. `adminUI/src/main.tsx` - Added AuthProvider wrapper and routing

## Testing

To test the implementation:

1. **Start services**:
   ```bash
   docker-compose up -d
   ```

2. **Access adminUI**: http://localhost:8899

3. **Test login**:
   - Click "Login" button
   - Enter credentials: admin/admin
   - Verify redirect back to adminUI
   - Check user avatar shows in header

4. **Test API calls**:
   - Open browser dev tools
   - Navigate to different sections
   - Check Network tab for API requests
   - Verify Authorization header includes bearer token

5. **Test logout**:
   - Click user avatar
   - Select "Log out"
   - Verify redirect to login page

## Security Notes

1. **PKCE enabled**: Protects against authorization code interception
2. **Public client**: No client secret (appropriate for SPA)
3. **Token storage**: sessionStorage (cleared on browser close)
4. **HTTPS recommended**: For production deployments
5. **CORS configuration**: Ensure proper CORS settings for production

## Next Steps

For production deployment:

1. Configure HTTPS for all services
2. Use production-grade Keycloak configuration
3. Set up proper database for Keycloak (not included in basic setup)
4. Configure appropriate token lifetimes
5. Set up proper CORS policies
6. Configure rate limiting and brute force protection
7. Review and harden Keycloak security settings
8. Set up monitoring and logging for authentication events

## Support

For detailed setup instructions and troubleshooting, see `adminUI/OIDC_SETUP.md`.
