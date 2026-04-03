# Frontend Implementation Guide

Complete guide for implementing real-time notifications in your Next.js frontend.

## Installation

```bash
npm install socket.io-client
```

## Architecture

### Components Structure

```
app/
├── notifications/
│   ├── hooks/
│   │   └── useNotifications.ts      # Core WebSocket hook
│   ├── components/
│   │   ├── NotificationItem.tsx     # Reusable notification card
│   │   ├── PersonalNotifications.tsx # Personal notifications
│   │   └── BusinessNotifications.tsx # Business team notifications
│   └── context/
│       └── NotificationsContext.tsx  # Optional: global context
```

## Implementation

### 1. WebSocket Hook

**`hooks/useNotifications.ts`**

```typescript
import { useEffect, useState } from 'react';
import { io, Socket } from 'socket.io-client';

export interface Notification {
  id: string;
  type: 'INVOICE_CREATED' | 'BUSINESS_APPROVED' | 'BUSINESS_REJECTED';
  message: string;
  payload: Record<string, unknown>;
  createdAt: string;
}

interface UseNotificationsReturn {
  socket: Socket | null;
  notifications: Notification[];
  isConnected: boolean;
  setNotifications: (notifs: Notification[]) => void;
}

export function useNotifications(token?: string): UseNotificationsReturn {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    if (!token) return;

    // Create socket connection
    const newSocket = io(
      process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000',
      {
        query: { token },
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: 5,
      }
    );

    // Connection established
    newSocket.on('connect', () => {
      console.log('✅ Connected to notifications');
      setIsConnected(true);
    });

    // Receive notification
    newSocket.on('notification', (notification: Notification) => {
      console.log('📬 New notification:', notification);
      setNotifications((prev) => {
        // Prevent duplicates
        if (prev.some((n) => n.id === notification.id)) {
          return prev;
        }
        return [notification, ...prev];
      });

      // Browser notification (if permitted)
      if (typeof window !== 'undefined' && 'Notification' in window) {
        if (Notification.permission === 'granted') {
          new Notification(notification.message, {
            body:
              (notification.payload.businessName as string) ||
              'New notification',
            tag: notification.id,
          });
        }
      }
    });

    // Disconnected
    newSocket.on('disconnect', () => {
      console.log('❌ Disconnected from notifications');
      setIsConnected(false);
    });

    // Connection error
    newSocket.on('connect_error', (error) => {
      console.error('Connection error:', error);
    });

    setSocket(newSocket);

    // Cleanup
    return () => {
      newSocket.disconnect();
    };
  }, [token]);

  return { socket, notifications, isConnected, setNotifications };
}
```

### 2. Notification Item Component

**`components/notifications/NotificationItem.tsx`**

```typescript
'use client';

import Link from 'next/link';
import { Notification } from '@/hooks/useNotifications';

interface NotificationItemProps {
  notification: Notification;
}

export function NotificationItem({ notification }: NotificationItemProps) {
  if (notification.type === 'INVOICE_CREATED') {
    const payload = notification.payload;
    const dueDate = new Date(payload.dueDate as string).toLocaleDateString(
      'en-US',
      { year: 'numeric', month: 'short', day: 'numeric' }
    );

    return (
      <div className="notification-card invoice-notification">
        <div className="notification-header">
          <h4 className="notification-title">{notification.message}</h4>
          <span className="notification-time">
            {new Date(notification.createdAt).toLocaleTimeString()}
          </span>
        </div>

        <div className="notification-details">
          <div className="detail-row">
            <span className="label">Invoice ID:</span>
            <span className="value">
              {(notification.id as string).slice(-8)}
            </span>
          </div>
          <div className="detail-row">
            <span className="label">Amount:</span>
            <span className="value amount">
              {payload.amount} {payload.currency}
            </span>
          </div>
          <div className="detail-row">
            <span className="label">Due Date:</span>
            <span className="value">{dueDate}</span>
          </div>
        </div>

        <Link
          href={`/invoices/${notification.id}`}
          className="notification-action"
        >
          View Invoice →
        </Link>
      </div>
    );
  }

  if (notification.type === 'BUSINESS_APPROVED') {
    return (
      <div className="notification-card approval-notification">
        <h4>{notification.message}</h4>
        <p className="notification-text">
          Your business has been approved and is now active.
        </p>
      </div>
    );
  }

  // Default
  return (
    <div className="notification-card">
      <p>{notification.message}</p>
    </div>
  );
}
```

### 3. Personal Notifications Component

**`components/notifications/PersonalNotifications.tsx`**

```typescript
'use client';

import { useAuth } from '@/hooks/useAuth';
import { useNotifications } from '@/hooks/useNotifications';
import { NotificationItem } from './NotificationItem';

export function PersonalNotifications() {
  const { user, token } = useAuth();
  const { notifications, isConnected } = useNotifications(token);

  // Filter personal notifications (not business-specific)
  const personalNotifications = notifications.filter((notif) => {
    // Exclude business notifications
    if (notif.payload?.businessId) {
      return false;
    }
    return true;
  });

  return (
    <section className="notifications-section personal-section">
      <div className="section-header">
        <h2>Your Notifications</h2>
        <div className="connection-status">
          {isConnected ? (
            <span className="status connected">● Live</span>
          ) : (
            <span className="status offline">● Offline</span>
          )}
        </div>
      </div>

      {personalNotifications.length === 0 ? (
        <div className="empty-state">
          <p>No new notifications</p>
        </div>
      ) : (
        <div className="notifications-list">
          {personalNotifications.map((notif) => (
            <NotificationItem key={notif.id} notification={notif} />
          ))}
        </div>
      )}
    </section>
  );
}
```

### 4. Business Notifications Component

**`components/notifications/BusinessNotifications.tsx`**

```typescript
'use client';

import { useAuth } from '@/hooks/useAuth';
import { useNotifications } from '@/hooks/useNotifications';
import { NotificationItem } from './NotificationItem';

interface BusinessNotificationsProps {
  businessId: string;
  businessName: string;
}

export function BusinessNotifications({
  businessId,
  businessName,
}: BusinessNotificationsProps) {
  const { token } = useAuth();
  const { notifications, isConnected } = useNotifications(token);

  // Filter notifications for this specific business
  const businessNotifications = notifications.filter(
    (notif) => notif.payload?.businessId === businessId
  );

  return (
    <section className="notifications-section business-section">
      <div className="section-header">
        <h2>{businessName}</h2>
        <div className="team-status">
          {isConnected ? (
            <span className="status connected">● Team Connected</span>
          ) : (
            <span className="status offline">● Team Offline</span>
          )}
        </div>
      </div>

      <p className="section-description">
        All team admins receive notifications in real-time.
      </p>

      {businessNotifications.length === 0 ? (
        <div className="empty-state">
          <p>No team notifications yet</p>
        </div>
      ) : (
        <div className="notifications-list">
          {businessNotifications.map((notif) => (
            <NotificationItem key={notif.id} notification={notif} />
          ))}
        </div>
      )}
    </section>
  );
}
```

### 5. Dashboard Integration

**`app/dashboard/page.tsx`**

```typescript
'use client';

import { useAuth } from '@/hooks/useAuth';
import { useQuery } from '@tanstack/react-query';
import { PersonalNotifications } from '@/components/notifications/PersonalNotifications';
import { BusinessNotifications } from '@/components/notifications/BusinessNotifications';

interface Business {
  _id: string;
  name: string;
  email: string;
}

export default function DashboardPage() {
  const { user, token } = useAuth();

  // Fetch user's businesses
  const { data: businesses = [] } = useQuery<Business[]>({
    queryKey: ['user-businesses'],
    queryFn: async () => {
      const res = await fetch('/api/business/my-businesses', {
        headers: { Authorization: `Bearer ${token}` },
      });
      return res.json();
    },
  });

  return (
    <main className="dashboard">
      <div className="dashboard-container">
        {/* Personal notifications - top */}
        <PersonalNotifications />

        {/* Business notifications - one per business */}
        <div className="businesses-notifications">
          {businesses.length > 0 ? (
            <div>
              <h2 className="section-title">Teams</h2>
              {businesses.map((business) => (
                <BusinessNotifications
                  key={business._id}
                  businessId={business._id}
                  businessName={business.name}
                />
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <p>No businesses yet</p>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
```

## Styling Example

**`styles/notifications.css`**

```css
.notifications-section {
  padding: 24px;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  background: white;
  margin-bottom: 24px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 2px solid #f3f4f6;
}

.section-header h2 {
  font-size: 18px;
  font-weight: 600;
  margin: 0;
}

.connection-status,
.team-status {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
}

.status {
  display: flex;
  align-items: center;
  gap: 4px;
}

.status.connected {
  color: #16a34a;
}

.status.offline {
  color: #dc2626;
}

.notifications-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.notification-card {
  padding: 16px;
  border: 1px solid #e5e7eb;
  border-left: 4px solid #8b0000;
  border-radius: 6px;
  background: #fafafa;
  transition: all 0.2s;
}

.notification-card:hover {
  background: white;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
}

.notification-header {
  display: flex;
  justify-content: space-between;
  align-items: start;
  gap: 12px;
  margin-bottom: 12px;
}

.notification-title {
  font-weight: 600;
  font-size: 14px;
  margin: 0;
  color: #1f2937;
}

.notification-time {
  font-size: 12px;
  color: #9ca3af;
  white-space: nowrap;
}

.notification-details {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 12px;
  padding: 8px 0;
}

.detail-row {
  display: flex;
  justify-content: space-between;
  font-size: 13px;
}

.detail-row .label {
  color: #6b7280;
  font-weight: 500;
}

.detail-row .value {
  color: #1f2937;
  font-family: 'Monaco', 'Courier New', monospace;
}

.detail-row .value.amount {
  color: #16a34a;
  font-weight: 600;
}

.notification-action {
  display: inline-block;
  padding: 8px 16px;
  background: #8b0000;
  color: white;
  border-radius: 4px;
  font-size: 13px;
  font-weight: 600;
  text-decoration: none;
  transition: background 0.2s;
  cursor: pointer;
}

.notification-action:hover {
  background: #a00000;
}

.empty-state {
  padding: 32px;
  text-align: center;
  color: #9ca3af;
}

.personal-section {
  border-left-color: #3b82f6;
}

.business-section {
  border-left-color: #ec4899;
}

.approval-notification {
  border-left-color: #10b981;
}

.approval-notification .notification-text {
  margin: 8px 0 0 0;
  color: #6b7280;
  font-size: 13px;
}
```

## Usage in Other Components

### In a Sidebar

```typescript
export function NotificationBell() {
  const { token } = useAuth();
  const { notifications, isConnected } = useNotifications(token);

  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <button className="notification-bell">
      🔔
      {unreadCount > 0 && <span className="badge">{unreadCount}</span>}
    </button>
  );
}
```

### Real-time Invoice Counter

```typescript
export function InvoiceStats() {
  const { token } = useAuth();
  const { notifications } = useNotifications(token);

  const invoiceCount = notifications.filter(
    (n) => n.type === 'INVOICE_CREATED'
  ).length;

  return (
    <div className="stat">
      <h3>New Invoices</h3>
      <p className="stat-value">{invoiceCount}</p>
    </div>
  );
}
```

## Best Practices

### 1. Request Browser Notification Permission

```typescript
useEffect(() => {
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
  }
}, []);
```

### 2. Handle Offline State

```typescript
const { isConnected } = useNotifications(token);

if (!isConnected) {
  return <div className="offline-banner">You're offline</div>;
}
```

### 3. Persist Notifications

```typescript
const [notifications, setNotifications] = useState(() => {
  // Load from localStorage on mount
  const stored = localStorage.getItem('notifications');
  return stored ? JSON.parse(stored) : [];
});

// Save to localStorage on change
useEffect(() => {
  localStorage.setItem('notifications', JSON.stringify(notifications));
}, [notifications]);
```

### 4. Add Pagination

```typescript
const NOTIFS_PER_PAGE = 20;

const paginatedNotifications = notifications.slice(0, NOTIFS_PER_PAGE);

const hasMore = notifications.length > NOTIFS_PER_PAGE;
```

## Environment Variables

**.env.local**

```env
NEXT_PUBLIC_API_URL=http://localhost:3000
```

## Testing

```typescript
import { render, screen, waitFor } from '@testing-library/react';
import { PersonalNotifications } from '@/components/notifications/PersonalNotifications';

jest.mock('@/hooks/useNotifications', () => ({
  useNotifications: () => ({
    socket: null,
    notifications: [
      {
        id: 'test-1',
        type: 'INVOICE_CREATED',
        message: 'Test invoice',
        payload: { amount: 100, currency: 'TND' },
        createdAt: new Date().toISOString(),
      },
    ],
    isConnected: true,
  }),
}));

describe('PersonalNotifications', () => {
  it('renders notifications', () => {
    render(<PersonalNotifications />);
    expect(screen.getByText('Test invoice')).toBeInTheDocument();
  });
});
```

---

For WebSocket API details, see [WEBSOCKET_GUIDE.md](WEBSOCKET_GUIDE.md)
