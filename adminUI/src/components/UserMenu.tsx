import { LogIn, LogOut } from 'lucide-react';
import { useAuth } from '../lib/auth/AuthContext';
import { Button } from './ui/button';

export const UserMenu = () => {
  const { user, isAuthenticated, isLoading, login, logout } = useAuth();

  if (isLoading) {
    return (
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Loading...</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <Button onClick={login} variant="outline" size="sm" className="gap-2">
        <LogIn className="h-4 w-4" />
        Login
      </Button>
    );
  }

  const userName = user?.profile?.preferred_username || user?.profile?.name || 'User';

  return (
    <div className="flex items-center gap-3">
      <span className="text-sm font-medium">{userName}</span>
      <Button onClick={logout} variant="outline" size="sm" className="gap-2">
        <LogOut className="h-4 w-4" />
        Logout
      </Button>
    </div>
  );
};
