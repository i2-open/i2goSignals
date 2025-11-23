import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { User, UserManager } from 'oidc-client-ts';
import { oidcConfig } from './authConfig';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: () => Promise<void>;
  logout: () => Promise<void>;
  getAccessToken: () => string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

let userManager: UserManager | null = null;

const getUserManager = (): UserManager => {
  if (!userManager) {
    userManager = new UserManager(oidcConfig);
  }
  return userManager;
};

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const manager = getUserManager();

    // Check if user is already authenticated
    const loadUser = async () => {
      try {
        const storedUser = await manager.getUser();
        if (storedUser && !storedUser.expired) {
          setUser(storedUser);
        }
      } catch (error) {
        console.error('Error loading user:', error);
      } finally {
        setIsLoading(false);
      }
    };

    loadUser();

    // Handle token renewal
    manager.events.addUserLoaded((loadedUser) => {
      setUser(loadedUser);
    });

    manager.events.addUserUnloaded(() => {
      setUser(null);
    });

    manager.events.addAccessTokenExpired(() => {
      console.log('Access token expired');
      setUser(null);
    });

    manager.events.addSilentRenewError((error) => {
      console.error('Silent renew error:', error);
    });

    return () => {
      // Cleanup event listeners
      manager.events.removeUserLoaded(() => {});
      manager.events.removeUserUnloaded(() => {});
      manager.events.removeAccessTokenExpired(() => {});
      manager.events.removeSilentRenewError(() => {});
    };
  }, []);

  const login = async () => {
    const manager = getUserManager();
    await manager.signinRedirect();
  };

  const logout = async () => {
    const manager = getUserManager();
    await manager.signoutRedirect();
    setUser(null);
  };

  const getAccessToken = (): string | null => {
    return user?.access_token || null;
  };

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user && !user.expired,
    isLoading,
    login,
    logout,
    getAccessToken,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Handle the callback after login
export const handleCallback = async (): Promise<User | null> => {
  const manager = getUserManager();
  try {
    const user = await manager.signinRedirectCallback();
    return user;
  } catch (error) {
    console.error('Error handling callback:', error);
    return null;
  }
};

// Handle silent callback for token renewal
export const handleSilentCallback = async (): Promise<void> => {
  const manager = getUserManager();
  try {
    await manager.signinSilentCallback();
  } catch (error) {
    console.error('Error handling silent callback:', error);
  }
};
