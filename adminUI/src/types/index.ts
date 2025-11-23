export type StreamStatus = 'enabled' | 'paused' | 'disabled';
export type DeliveryMethod = 'urn:ietf:rfc:8935' | 'urn:ietf:rfc:8936'; // Push vs Poll

export interface StreamConfiguration {
  iss: string;
  aud: string[];
  delivery: {
    method: DeliveryMethod;
    endpoint_url?: string;
  };
  events_supported: string[];
  events_requested?: string[];
  format?: 'json' | 'jwt';
  min_verification_interval?: number;
}

export interface Stream {
  id: string;
  status: StreamStatus;
  configuration: StreamConfiguration;
  createdAt: string;
  updatedAt: string;
  eventsDelivered: number;
  lastEventAt?: string;
  errors: number;
}

export interface EventFamily {
  uri: string;
  name: string;
  description: string;
  events: EventDefinition[];
}

export interface EventDefinition {
  uri: string;
  name: string;
  description: string;
  schema?: any;
  enabled: boolean;
}

export interface Transmitter {
  id: string;
  issuer: string;
  jwks_uri?: string;
  configuration_endpoint?: string;
  status_endpoint?: string;
  add_subject_endpoint?: string;
  remove_subject_endpoint?: string;
  verification_endpoint?: string;
  delivery_methods_supported: DeliveryMethod[];
  events_supported: string[];
  critical_extensions?: string[];
  lastSync?: string;
}

export interface Receiver {
  id: string;
  name: string;
  description?: string;
  endpoint_url: string;
  verification_method: 'jwks_uri' | 'mtls';
  jwks_uri?: string;
  status: 'active' | 'inactive' | 'error';
  streams: string[];
  lastVerified?: string;
  totalEventsReceived: number;
}

export interface SecurityEventToken {
  jti: string;
  iss: string;
  aud: string[];
  iat: number;
  events: {
    [eventType: string]: any;
  };
  txn?: string;
  toe?: number;
}

export interface EventTransmission {
  id: string;
  streamId: string;
  set: SecurityEventToken;
  timestamp: string;
  status: 'pending' | 'delivered' | 'failed' | 'acknowledged';
  deliveryAttempts: number;
  lastError?: string;
  responseCode?: number;
}
