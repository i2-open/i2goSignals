import { UserManagerSettings } from 'oidc-client-ts';

// Get the base URL for the adminUI
const getAdminUIUrl = () => {
  if (typeof window !== 'undefined') {
    return window.location.origin;
  }
  return 'http://localhost:8899';
};

// Get the goSignalsServer URL from environment or default
const getGoSignalsServerUrl = () => {
  return import.meta.env.VITE_GOSIGNALS_SERVER_URL || 'http://localhost:8888';
};

// Get the Keycloak URL from environment or default
const getKeycloakUrl = () => {
  return import.meta.env.VITE_KEYCLOAK_URL || 'http://localhost:8080/realms/gosignals';
};

export const oidcConfig: UserManagerSettings = {
  authority: getKeycloakUrl(),
  client_id: 'adminui',
  redirect_uri: `${getAdminUIUrl()}/callback`,
  post_logout_redirect_uri: `${getAdminUIUrl()}/`,
  response_type: 'code',
  scope: 'openid profile email',
  automaticSilentRenew: true,
  silent_redirect_uri: `${getAdminUIUrl()}/silent-callback.html`,
  loadUserInfo: true,
};

export const goSignalsServerUrl = getGoSignalsServerUrl();
