import { Stream, EventFamily, EventDefinition, Transmitter, Receiver, SecurityEventToken, EventTransmission } from '../types';

export const mockEventFamilies: EventFamily[] = [
  {
    uri: 'https://schemas.openid.net/secevent/caep/event-type/',
    name: 'CAEP Events',
    description: 'Continuous Access Evaluation Protocol',
    events: [
      {
        uri: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        name: 'Session Revoked',
        description: 'Indicates that a user session has been revoked',
        enabled: true,
      },
      {
        uri: 'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
        name: 'Token Claims Change',
        description: 'Indicates that claims in a token have changed',
        enabled: true,
      },
      {
        uri: 'https://schemas.openid.net/secevent/caep/event-type/credential-change',
        name: 'Credential Change',
        description: 'Indicates that user credentials have changed',
        enabled: true,
      },
      {
        uri: 'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change',
        name: 'Assurance Level Change',
        description: 'Indicates a change in authentication assurance level',
        enabled: false,
      },
      {
        uri: 'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
        name: 'Device Compliance Change',
        description: 'Indicates a change in device compliance status',
        enabled: true,
      },
    ],
  },
  {
    uri: 'https://schemas.openid.net/secevent/risc/event-type/',
    name: 'RISC Events',
    description: 'Risk and Incident Sharing and Coordination',
    events: [
      {
        uri: 'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
        name: 'Account Disabled',
        description: 'Indicates that an account has been disabled',
        enabled: true,
      },
      {
        uri: 'https://schemas.openid.net/secevent/risc/event-type/account-enabled',
        name: 'Account Enabled',
        description: 'Indicates that an account has been enabled',
        enabled: true,
      },
      {
        uri: 'https://schemas.openid.net/secevent/risc/event-type/account-purged',
        name: 'Account Purged',
        description: 'Indicates that an account has been permanently deleted',
        enabled: false,
      },
      {
        uri: 'https://schemas.openid.net/secevent/risc/event-type/identifier-changed',
        name: 'Identifier Changed',
        description: 'Indicates that an account identifier has changed',
        enabled: true,
      },
      {
        uri: 'https://schemas.openid.net/secevent/risc/event-type/identifier-recycled',
        name: 'Identifier Recycled',
        description: 'Indicates that an identifier has been recycled',
        enabled: false,
      },
      {
        uri: 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
        name: 'Credential Compromise',
        description: 'Indicates that credentials may have been compromised',
        enabled: true,
      },
    ],
  },
  {
    uri: 'https://schemas.openid.net/secevent/sse/event-type/',
    name: 'SSE Core Events',
    description: 'Shared Signals and Events Core',
    events: [
      {
        uri: 'https://schemas.openid.net/secevent/sse/event-type/verification',
        name: 'Stream Verification',
        description: 'Event used to verify stream configuration',
        enabled: true,
      },
      {
        uri: 'https://schemas.openid.net/secevent/sse/event-type/stream-updated',
        name: 'Stream Updated',
        description: 'Indicates the stream configuration has changed',
        enabled: true,
      },
    ],
  },
];

export const mockStreams: Stream[] = [
  {
    id: 'stream-1',
    status: 'enabled',
    configuration: {
      iss: 'https://transmitter.example.com',
      aud: ['https://receiver.example.com'],
      delivery: {
        method: 'urn:ietf:rfc:8935',
        endpoint_url: 'https://receiver.example.com/events',
      },
      events_supported: [
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        'https://schemas.openid.net/secevent/caep/event-type/credential-change',
        'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
      ],
      events_requested: [
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        'https://schemas.openid.net/secevent/caep/event-type/credential-change',
      ],
      format: 'jwt',
      min_verification_interval: 3600,
    },
    createdAt: '2025-10-15T10:30:00Z',
    updatedAt: '2025-11-04T14:22:00Z',
    eventsDelivered: 45623,
    lastEventAt: '2025-11-05T09:45:12Z',
    errors: 12,
  },
  {
    id: 'stream-2',
    status: 'enabled',
    configuration: {
      iss: 'https://transmitter.example.com',
      aud: ['https://partner.example.com'],
      delivery: {
        method: 'urn:ietf:rfc:8936',
      },
      events_supported: [
        'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
        'https://schemas.openid.net/secevent/risc/event-type/account-enabled',
        'https://schemas.openid.net/secevent/risc/event-type/identifier-changed',
      ],
      format: 'json',
    },
    createdAt: '2025-09-20T14:22:00Z',
    updatedAt: '2025-11-05T08:15:00Z',
    eventsDelivered: 8234,
    lastEventAt: '2025-11-05T09:12:33Z',
    errors: 5,
  },
  {
    id: 'stream-3',
    status: 'paused',
    configuration: {
      iss: 'https://transmitter.example.com',
      aud: ['https://dev.example.com'],
      delivery: {
        method: 'urn:ietf:rfc:8935',
        endpoint_url: 'https://dev.example.com/sse-events',
      },
      events_supported: [
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
      ],
      format: 'jwt',
    },
    createdAt: '2025-11-01T09:00:00Z',
    updatedAt: '2025-11-04T16:30:00Z',
    eventsDelivered: 234,
    errors: 3,
  },
];

export const mockTransmitters: Transmitter[] = [
  {
    id: 'tx-1',
    issuer: 'https://transmitter.example.com',
    jwks_uri: 'https://transmitter.example.com/.well-known/jwks.json',
    configuration_endpoint: 'https://transmitter.example.com/.well-known/sse-configuration',
    status_endpoint: 'https://transmitter.example.com/sse/stream',
    add_subject_endpoint: 'https://transmitter.example.com/sse/subjects:add',
    remove_subject_endpoint: 'https://transmitter.example.com/sse/subjects:remove',
    verification_endpoint: 'https://transmitter.example.com/sse/verification',
    delivery_methods_supported: [
      'urn:ietf:rfc:8935',
      'urn:ietf:rfc:8936',
    ],
    events_supported: [
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
      'https://schemas.openid.net/secevent/caep/event-type/credential-change',
      'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
      'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
      'https://schemas.openid.net/secevent/risc/event-type/identifier-changed',
    ],
    lastSync: '2025-11-05T09:30:00Z',
  },
  {
    id: 'tx-2',
    issuer: 'https://idp.partner.com',
    jwks_uri: 'https://idp.partner.com/.well-known/jwks.json',
    configuration_endpoint: 'https://idp.partner.com/.well-known/sse-configuration',
    delivery_methods_supported: [
      'urn:ietf:rfc:8935',
    ],
    events_supported: [
      'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
      'https://schemas.openid.net/secevent/risc/event-type/account-enabled',
    ],
    lastSync: '2025-11-05T08:15:00Z',
  },
];

export const mockReceivers: Receiver[] = [
  {
    id: 'rx-1',
    name: 'Production Receiver',
    description: 'Main production event receiver',
    endpoint_url: 'https://receiver.example.com/events',
    verification_method: 'jwks_uri',
    jwks_uri: 'https://receiver.example.com/.well-known/jwks.json',
    status: 'active',
    streams: ['stream-1'],
    lastVerified: '2025-11-05T06:00:00Z',
    totalEventsReceived: 45623,
  },
  {
    id: 'rx-2',
    name: 'Partner Integration',
    description: 'Partner event receiver endpoint',
    endpoint_url: 'https://partner.example.com/sse/receive',
    verification_method: 'mtls',
    status: 'active',
    streams: ['stream-2'],
    lastVerified: '2025-11-05T05:45:00Z',
    totalEventsReceived: 8234,
  },
  {
    id: 'rx-3',
    name: 'Development Receiver',
    endpoint_url: 'https://dev.example.com/sse-events',
    verification_method: 'jwks_uri',
    jwks_uri: 'https://dev.example.com/.well-known/jwks.json',
    status: 'inactive',
    streams: ['stream-3'],
    totalEventsReceived: 234,
  },
];

export const mockEventTransmissions: EventTransmission[] = [
  {
    id: 'evt-1',
    streamId: 'stream-1',
    set: {
      jti: '756E69717565206964656E746966696572',
      iss: 'https://transmitter.example.com',
      aud: ['https://receiver.example.com'],
      iat: 1730797512,
      events: {
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked': {
          subject: {
            format: 'opaque',
            id: 'user-12345',
          },
          initiating_entity: 'admin',
          reason_admin: 'User violated security policy',
          event_timestamp: 1730797500,
        },
      },
    },
    timestamp: '2025-11-05T09:45:12Z',
    status: 'delivered',
    deliveryAttempts: 1,
    responseCode: 202,
  },
  {
    id: 'evt-2',
    streamId: 'stream-1',
    set: {
      jti: '4A2B3C4D5E6F7890ABCDEF123456',
      iss: 'https://transmitter.example.com',
      aud: ['https://receiver.example.com'],
      iat: 1730797452,
      events: {
        'https://schemas.openid.net/secevent/caep/event-type/credential-change': {
          subject: {
            format: 'email',
            email: 'user@example.com',
          },
          credential_type: 'password',
          change_type: 'update',
          event_timestamp: 1730797440,
        },
      },
    },
    timestamp: '2025-11-05T09:42:33Z',
    status: 'delivered',
    deliveryAttempts: 1,
    responseCode: 202,
  },
  {
    id: 'evt-3',
    streamId: 'stream-2',
    set: {
      jti: 'ABC123DEF456GHI789JKL012',
      iss: 'https://transmitter.example.com',
      aud: ['https://partner.example.com'],
      iat: 1730797400,
      events: {
        'https://schemas.openid.net/secevent/risc/event-type/account-disabled': {
          subject: {
            format: 'opaque',
            id: 'account-67890',
          },
          reason: 'suspicious-activity',
          event_timestamp: 1730797380,
        },
      },
    },
    timestamp: '2025-11-05T09:40:15Z',
    status: 'failed',
    deliveryAttempts: 3,
    lastError: 'Connection timeout',
    responseCode: 504,
  },
  {
    id: 'evt-4',
    streamId: 'stream-1',
    set: {
      jti: 'XYZ789ABC123DEF456GHI012',
      iss: 'https://transmitter.example.com',
      aud: ['https://receiver.example.com'],
      iat: 1730797308,
      events: {
        'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change': {
          subject: {
            format: 'opaque',
            id: 'device-54321',
          },
          previous_status: 'compliant',
          current_status: 'not-compliant',
          event_timestamp: 1730797300,
        },
      },
    },
    timestamp: '2025-11-05T09:35:08Z',
    status: 'delivered',
    deliveryAttempts: 1,
    responseCode: 202,
  },
  {
    id: 'evt-5',
    streamId: 'stream-2',
    set: {
      jti: 'MNO456PQR789STU012VWX345',
      iss: 'https://transmitter.example.com',
      aud: ['https://partner.example.com'],
      iat: 1730797211,
      events: {
        'https://schemas.openid.net/secevent/risc/event-type/identifier-changed': {
          subject: {
            format: 'email',
            email: 'olduser@example.com',
          },
          new_value: 'newuser@example.com',
          event_timestamp: 1730797200,
        },
      },
    },
    timestamp: '2025-11-05T09:20:11Z',
    status: 'delivered',
    deliveryAttempts: 1,
    responseCode: 202,
  },
];

export function getAllEvents(): EventDefinition[] {
  return mockEventFamilies.flatMap(family => family.events);
}

export function getEventByUri(uri: string): EventDefinition | undefined {
  return getAllEvents().find(event => event.uri === uri);
}
