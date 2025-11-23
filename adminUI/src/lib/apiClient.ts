import axios, { AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import { goSignalsServerUrl } from './auth/authConfig';

// Create axios instance with default config
export const createApiClient = (getAccessToken: () => string | null): AxiosInstance => {
  const apiClient = axios.create({
    baseURL: goSignalsServerUrl,
    headers: {
      'Content-Type': 'application/json',
    },
  });

  // Add request interceptor to attach bearer token
  apiClient.interceptors.request.use(
    (config: InternalAxiosRequestConfig) => {
      const token = getAccessToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    },
    (error) => {
      return Promise.reject(error);
    }
  );

  // Add response interceptor to handle errors
  apiClient.interceptors.response.use(
    (response) => {
      return response;
    },
    (error) => {
      if (error.response?.status === 401) {
        // Token expired or invalid - could trigger re-login here
        console.error('Unauthorized - token may be expired');
        // You could dispatch an event or call a callback to trigger login
      }
      return Promise.reject(error);
    }
  );

  return apiClient;
};

// Example API functions using the client
export const createApiService = (apiClient: AxiosInstance) => ({
  // Stream management
  getStreams: () => apiClient.get('/stream'),
  getStream: (streamId: string) => apiClient.get(`/stream?stream_id=${streamId}`),
  createStream: (streamData: any) => apiClient.post('/stream', streamData),
  updateStream: (streamData: any) => apiClient.put('/stream', streamData),
  deleteStream: (streamId: string) => apiClient.delete(`/stream?stream_id=${streamId}`),
  
  // Status
  getStatus: (streamId: string) => apiClient.get(`/status?stream_id=${streamId}`),
  updateStatus: (streamId: string, statusData: any) => 
    apiClient.post(`/status?stream_id=${streamId}`, statusData),
  
  // Events
  triggerEvent: (eventData: any) => apiClient.post('/trigger-event', eventData),
  
  // Client registration
  registerClient: (clientData: any) => apiClient.post('/register', clientData),
  
  // Configuration
  getSsfConfiguration: () => apiClient.get('/.well-known/ssf-configuration'),
});
