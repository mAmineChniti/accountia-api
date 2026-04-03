# WebSocket & Real-Time Notifications Guide

## Overview

The Accountia API uses Socket.IO for real-time, bi-directional notifications. Users receive instant updates about invoices, business activities, and system events without polling.

## Architecture

### Room System

Notifications are organized into rooms for efficient delivery:

| Room                    | Members               | Use Case                                               |
| ----------------------- | --------------------- | ------------------------------------------------------ |
| `admin`                 | Platform owner/admins | System-wide notifications                              |
| `client:{email}`        | Individual users      | Personal notifications (invoices issued to them)       |
| `business:{businessId}` | Business owner/admins | Team notifications (invoices issued to their business) |

### Connection Flow

```
User connects
    ↓
Authentication via JWT token
    ↓
Verify user role & permissions
    ↓
Join appropriate rooms
    ├─ Personal room: client:{email}
    ├─ Admin room: admin (if platform admin)
    └─ Business rooms: business:{businessId} (for each business they manage)
    ↓
Listen for notifications
```

## Frontend Implementation

### Installation

```bash
npm install socket.io-client
```

### Basic Connection

```typescript
import { io } from 'socket.io-client';

const socket = io(process.env.REACT_APP_API_URL || 'http://localhost:3000', {
  query: { token: accessToken },
  reconnection: true,
  reconnectionDelay: 1000,
  reconnectionAttempts: 5,
});

socket.on('connect', () => {
  console.log('✅ Connected to notifications');
});

socket.on('notification', (data) => {
  console.log('📬 New notification:', data);
});

socket.on('connect_error', (error) => {
  console.error('Connection failed:', error);
});
```

### React Hook Pattern

```typescript
import { useEffect, useState } from 'react';
import { io, Socket } from 'socket.io-client';

export interface Notification {
  id: string;
  type: 'INVOICE_CREATED' | 'BUSINESS_APPROVED' | 'USER_BANNED';
  message: string;
  payload: Record<string, unknown>;
  createdAt: string;
}

export function useNotifications(token: string) {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    if (!token) return;

    const newSocket = io(
      process.env.REACT_APP_API_URL || 'http://localhost:3000',
      {
        query: { token },
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 5,
      }
    );

    newSocket.on('connect', () => {
      setIsConnected(true);
    });

    newSocket.on('notification', (notification: Notification) => {
      setNotifications((prev) => [notification, ...prev]);

      // Optional: Show browser notification
      if (Notification.permission === 'granted') {
        new Notification(notification.message);
      }
    });

    newSocket.on('connect_error', (error) => {
      console.error('Connection error:', error);
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, [token]);

  return { socket, notifications, isConnected, setNotifications };
}
```

## Notification Types

### INVOICE_CREATED

Sent when an invoice is created and issued to a client.

**Payload:**

```json
{
  "type": "INVOICE_CREATED",
  "message": "New invoice INV-001 from Tech Solutions",
  "payload": {
    "invoiceId": "507f1f77bcf86cd799439015",
    "businessName": "Tech Solutions",
    "amount": 1500.0,
    "currency": "TND",
    "dueDate": "2024-03-17T00:00:00.000Z"
  }
}
```

**Delivered to:**

- `client:{email}` - For personal invoices (issued to individual)
- `business:{businessId}` - For company invoices (issued to business)

### BUSINESS_APPROVED

Sent when a business application is approved.

**Payload:**

```json
{
  "type": "BUSINESS_APPROVED",
  "message": "Your business 'Acme Corp' has been approved",
  "payload": {
    "businessId": "507f1f77bcf86cd799439011",
    "businessName": "Acme Corp"
  }
}
```

**Delivered to:**

- `admin` - Platform admins

### BUSINESS_REJECTED

Sent when a business application is rejected.

**Payload:**

```json
{
  "type": "BUSINESS_REJECTED",
  "message": "Your business 'Acme Corp' application was rejected",
  "payload": {
    "businessId": "507f1f77bcf86cd799439011",
    "businessName": "Acme Corp",
    "reason": "Incomplete documentation"
  }
}
```

**Delivered to:**

- `admin` - Platform admins

## Use Cases

### 1. Personal Invoice Notifications

Individual receives an invoice:

```typescript
function PersonalNotifications() {
  const { token } = useAuth();
  const { notifications } = useNotifications(token);

  // Connected to client:{email} room
  // Receives personal invoices in real-time
  const personalNotifications = notifications.filter(
    (n) => n.type === 'INVOICE_CREATED'
  );

  return (
    <div>
      {personalNotifications.map((notif) => (
        <div key={notif.id}>
          {notif.message}
          <p>Due: {notif.payload.dueDate}</p>
        </div>
      ))}
    </div>
  );
}
```

### 2. Business Team Notifications

All admins/owners of a business receive team notifications:

```typescript
function BusinessNotifications({ businessId }) {
  const { token } = useAuth();
  const { notifications } = useNotifications(token);

  // Automatically joins business:{businessId} room
  // All team members receive same notifications
  const businessNotifications = notifications.filter(
    (n) => n.payload.businessId === businessId
  );

  return (
    <div>
      <h2>Team Notifications</h2>
      {businessNotifications.map((notif) => (
        <div key={notif.id}>
          {notif.message}
          <p>Amount: {notif.payload.amount} {notif.payload.currency}</p>
        </div>
      ))}
    </div>
  );
}
```

### 3. Multi-Business Dashboard

Admin managing multiple businesses:

```typescript
function Dashboard() {
  const { token, user } = useAuth();
  const { notifications } = useNotifications(token);

  // User automatically joined all business rooms they manage
  // Single connection, multiple notification streams

  return (
    <div>
      <PersonalNotifications notifications={notifications} />
      {userBusinesses.map((business) => (
        <BusinessNotifications
          key={business.id}
          businessId={business.id}
          notifications={notifications}
        />
      ))}
    </div>
  );
}
```

## Connection Parameters

### Query Parameters

| Parameter    | Type   | Required | Description                                            |
| ------------ | ------ | -------- | ------------------------------------------------------ |
| `token`      | string | Yes      | JWT access token for authentication                    |
| `businessId` | string | No       | Join additional business room (deprecated - automatic) |

**Example:**

```typescript
const socket = io(API_URL, {
  query: {
    token: 'eyJhbGc...',
    // businessId is optional - user auto-joins all their business rooms
  },
});
```

## Error Handling

### Connection Errors

```typescript
socket.on('connect_error', (error) => {
  if (error.message === 'Missing token') {
    // Redirect to login
  } else if (error.message === 'Invalid token') {
    // Token expired, refresh and reconnect
  } else if (error.message === 'Insufficient role') {
    // User not authorized
  }
  console.error('Connection failed:', error);
});
```

### Reconection

Socket.IO automatically handles reconnection:

```typescript
const socket = io(API_URL, {
  query: { token },
  reconnection: true,
  reconnectionDelay: 1000, // Start at 1 second
  reconnectionDelayMax: 5000, // Max 5 seconds
  reconnectionAttempts: 5, // Try 5 times
});

socket.on('reconnect', () => {
  console.log('✅ Reconnected');
});

socket.on('reconnect_attempt', () => {
  console.log('🔄 Attempting to reconnect...');
});

socket.on('disconnect', () => {
  console.log('❌ Disconnected');
});
```

## Best Practices

### 1. Single Connection Instance

Create one connection per user, not per component:

```typescript
// ❌ Bad - Multiple connections
function Component1() {
  const socket = io(API_URL, { query: { token } });
}

function Component2() {
  const socket = io(API_URL, { query: { token } });
}

// ✅ Good - Shared hook
export function useNotifications(token) {
  const [socket] = useState(() => io(API_URL, { query: { token } }));
  return socket;
}
```

### 2. Cleanup on Unmount

Always disconnect when component unmounts:

```typescript
useEffect(() => {
  const socket = io(API_URL, { query: { token } });

  return () => {
    socket.disconnect(); // Clean cleanup
  };
}, [token]);
```

### 3. Handle Offline Gracefully

```typescript
const { isConnected } = useNotifications(token);

return (
  <div>
    {isConnected ? (
      <span>● Live notifications</span>
    ) : (
      <span>● Offline - notifications will sync when reconnected</span>
    )}
  </div>
);
```

### 4. Deduplicate Notifications

```typescript
const [notifications, setNotifications] = useState<Notification[]>([]);

const handleNewNotification = (notif: Notification) => {
  setNotifications((prev) => {
    // Prevent duplicates
    if (prev.some((n) => n.id === notif.id)) {
      return prev;
    }
    return [notif, ...prev];
  });
};
```

## Debugging

### Check Room Membership

Backend endpoint to view connection stats:

```typescript
// In gateway
getConnectionStats() {
  return {
    'admin': 5,
    'client:user@example.com': 2,
    'business:507f1f77bcf86cd799439011': 3,
  };
}
```

### Browser DevTools

```typescript
// Enable debug logs
localStorage.setItem('debug', 'socket.io-client:*');

// View all events
socket.onAny((event, ...args) => {
  console.log(event, args);
});
```

## API Reference

### Events

#### Emit (Client → Server)

```typescript
// Subscribe to notification types
socket.emit('subscribe', { types: ['INVOICE_CREATED', 'BUSINESS_APPROVED'] });
```

#### Listen (Server → Client)

```typescript
// Receive notification
socket.on('notification', (data: Notification) => {
  // Handle notification
});

// Connection events
socket.on('connect', () => {});
socket.on('disconnect', () => {});
socket.on('connect_error', (error) => {});
socket.on('reconnect', () => {});
```

## Testing

```typescript
import { io } from 'socket.io-client';

describe('Notifications', () => {
  it('receives invoice notification', (done) => {
    const socket = io(API_URL, { query: { token: TEST_TOKEN } });

    socket.on('notification', (notif) => {
      expect(notif.type).toBe('INVOICE_CREATED');
      socket.disconnect();
      done();
    });
  });
});
```

## Troubleshooting

| Issue                       | Solution                                                              |
| --------------------------- | --------------------------------------------------------------------- |
| Not receiving notifications | Verify token is valid, check user permissions, verify room membership |
| Frequent disconnections     | Check network stability, increase reconnectionAttempts                |
| Duplicate notifications     | Add deduplication logic by notification ID                            |
| Memory leaks                | Always disconnect socket on component unmount                         |

## Performance Considerations

- Each user maintains a single WebSocket connection
- Notifications are filtered server-side by room, not client-side
- Maximum 20 notifications stored in state (configure in hook)
- Pagination recommended for historical notifications

---

For more details, see the main [README.md](README.md) or contact the development team.
