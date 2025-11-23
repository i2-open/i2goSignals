import { useEffect, useState } from 'react';
import { handleCallback } from '../lib/auth/AuthContext';

export const AuthCallback = () => {
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const processCallback = async () => {
      try {
        const user = await handleCallback();
        if (user) {
          // Redirect to the original page or home
          window.location.href = '/';
        } else {
          setError('Authentication failed. Please try again.');
        }
      } catch (err) {
        console.error('Callback error:', err);
        setError('An error occurred during authentication.');
      }
    };

    processCallback();
  }, []);

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-4">Authentication Error</h1>
          <p className="text-red-500">{error}</p>
          <button
            onClick={() => window.location.href = '/'}
            className="mt-4 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
          >
            Return to Home
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="text-center">
        <h1 className="text-2xl font-bold mb-4">Processing authentication...</h1>
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto"></div>
      </div>
    </div>
  );
};
