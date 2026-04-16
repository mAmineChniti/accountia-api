# Accountia Chat API Documentation

## Overview

The Accountia Chat API provides **real-time AI-powered financial assistance** via WebSocket. The AI uses Groq's `llama-3.3-70b-versatile` model with streaming responses for immediate feedback.

**Key Features:**

- WebSocket-only streaming interface (no REST polling)
- Immediate token-by-token response streaming
- Business mode (analyzes invoices you issue) or Individual mode (analyzes invoices you receive)
- Multi-language support (AI responds in user's language)

---

## Connection

### WebSocket Endpoint

```
ws://<host>/chat
```

### Authentication

Pass your JWT token in the connection options:

```javascript
import { io } from 'socket.io-client';

const socket = io('ws://localhost:3000/chat', {
  auth: {
    token: 'your_jwt_token_here',
  },
  transports: ['websocket', 'polling'],
});
```

Or via query parameter:

```javascript
const socket = io('ws://localhost:3000/chat?token=your_jwt_token_here', {
  transports: ['websocket', 'polling'],
});
```

### Connection Events

| Event           | Direction       | Data                                      | Description            |
| --------------- | --------------- | ----------------------------------------- | ---------------------- |
| `connected`     | Server → Client | `{ status: 'connected', userId: string }` | Successful connection  |
| `connect_error` | Server → Client | `{ message: string }`                     | Connection/auth failed |
| `disconnect`    | Bidirectional   | -                                         | Connection closed      |

---

## Sending Messages

### Event: `chat_message`

**Direction:** Client → Server

**Payload:**

```typescript
{
  messageId: string;        // Client-generated unique ID for tracking
  query: string;            // User's question/message
  businessId?: string;      // Optional: if provided, analyzes business invoices
  history?: Array<{         // Optional: previous messages for context
    role: 'user' | 'assistant';
    content: string;
  }>;
}
```

**Example:**

```javascript
const messageId = crypto.randomUUID(); // or any unique ID

socket.emit('chat_message', {
  messageId,
  query: 'How much revenue did I make this month?',
  businessId: 'business_123', // Omit for individual mode
  history: [
    { role: 'user', content: 'Show me my finances' },
    { role: 'assistant', content: 'Here is your summary...' },
  ],
});
```

**Modes:**

- **With `businessId`**: AI analyzes invoices your business issued (revenue, debtors, overdue)
- **Without `businessId`**: AI analyzes invoices you received as an individual (what you owe, upcoming payments)

---

## Receiving Responses

### Streaming Events

| Event              | Direction       | Data                                                                           | Description                                       |
| ------------------ | --------------- | ------------------------------------------------------------------------------ | ------------------------------------------------- |
| `message_start`    | Server → Client | `{ messageId: string, timestamp: string }`                                     | Streaming begins                                  |
| `message_chunk`    | Server → Client | `{ messageId: string, chunk: string }`                                         | Token from AI (volatile, may drop if client slow) |
| `message_complete` | Server → Client | `{ messageId: string, response: string, duration: number, timestamp: string }` | Full response received                            |
| `message_error`    | Server → Client | `{ messageId: string, message: string }`                                       | Error occurred                                    |

### Example: Receiving Stream

```javascript
const activeMessages = new Map();

// Streaming started
socket.on('message_start', ({ messageId, timestamp }) => {
  console.log(`Message ${messageId} started at ${timestamp}`);

  // Initialize message container in UI
  activeMessages.set(messageId, {
    content: '',
    element: createMessageElement(messageId),
  });
});

// Receive chunks (append immediately for live typing effect)
socket.on('message_chunk', ({ messageId, chunk }) => {
  const msg = activeMessages.get(messageId);
  if (msg) {
    msg.content += chunk;
    msg.element.textContent = msg.content;

    // Optional: Auto-scroll to bottom
    scrollToBottom();
  }
});

// Streaming complete
socket.on('message_complete', ({ messageId, response, duration }) => {
  console.log(`Message ${messageId} completed in ${duration}ms`);

  const msg = activeMessages.get(messageId);
  if (msg) {
    // Final content (in case any chunks were dropped)
    msg.content = response;
    msg.element.textContent = response;

    // Mark as complete in UI
    msg.element.classList.add('complete');
  }

  activeMessages.delete(messageId);
});

// Error handling
socket.on('message_error', ({ messageId, message }) => {
  console.error(`Message ${messageId} failed:`, message);

  const msg = activeMessages.get(messageId);
  if (msg) {
    msg.element.textContent = `Error: ${message}`;
    msg.element.classList.add('error');
  }

  activeMessages.delete(messageId);
});
```

---

## Utility Events

### Ping/Pong (Connection Health)

```javascript
// Check connection latency
socket.emit('ping');

socket.on('pong', ({ timestamp }) => {
  const latency = Date.now() - timestamp;
  console.log(`Latency: ${latency}ms`);
});
```

---

## Complete Frontend Example

```typescript
import { io, Socket } from 'socket.io-client';

interface ChatMessage {
  messageId: string;
  query: string;
  businessId?: string;
  history?: Array<{ role: 'user' | 'assistant'; content: string }>;
}

class ChatClient {
  private socket: Socket;
  private messageHandlers: Map<
    string,
    {
      onChunk: (chunk: string) => void;
      onComplete: (response: string) => void;
      onError: (error: string) => void;
    }
  >;

  constructor(jwtToken: string, baseUrl: string = 'ws://localhost:3000') {
    this.socket = io(`${baseUrl}/chat`, {
      auth: { token: jwtToken },
      transports: ['websocket', 'polling'],
    });

    this.messageHandlers = new Map();
    this.setupListeners();
  }

  private setupListeners(): void {
    this.socket.on('connected', ({ userId }) => {
      console.log('Connected as:', userId);
    });

    this.socket.on('message_start', ({ messageId }) => {
      console.log('Streaming started:', messageId);
    });

    this.socket.on('message_chunk', ({ messageId, chunk }) => {
      const handler = this.messageHandlers.get(messageId);
      if (handler) {
        handler.onChunk(chunk);
      }
    });

    this.socket.on('message_complete', ({ messageId, response }) => {
      const handler = this.messageHandlers.get(messageId);
      if (handler) {
        handler.onComplete(response);
        this.messageHandlers.delete(messageId);
      }
    });

    this.socket.on('message_error', ({ messageId, message }) => {
      const handler = this.messageHandlers.get(messageId);
      if (handler) {
        handler.onError(message);
        this.messageHandlers.delete(messageId);
      }
    });

    this.socket.on('connect_error', (error) => {
      console.error('Connection failed:', error.message);
    });
  }

  sendMessage(
    query: string,
    options: {
      businessId?: string;
      history?: ChatMessage['history'];
      onChunk?: (chunk: string) => void;
      onComplete?: (response: string) => void;
      onError?: (error: string) => void;
    } = {}
  ): string {
    const messageId = crypto.randomUUID();

    this.messageHandlers.set(messageId, {
      onChunk: options.onChunk || (() => {}),
      onComplete: options.onComplete || (() => {}),
      onError: options.onError || (() => {}),
    });

    this.socket.emit('chat_message', {
      messageId,
      query,
      businessId: options.businessId,
      history: options.history,
    });

    return messageId;
  }

  disconnect(): void {
    this.socket.disconnect();
  }
}

// Usage
const chat = new ChatClient('your_jwt_token');

// Business mode (analyze invoices you issue)
chat.sendMessage('What is my total revenue?', {
  businessId: 'your_business_id',
  onChunk: (chunk) => {
    // Append to UI immediately for typing effect
    document.getElementById('response')!.textContent += chunk;
  },
  onComplete: (response) => {
    console.log('Complete response:', response);
  },
  onError: (error) => {
    console.error('Error:', error);
  },
});

// Individual mode (analyze invoices you received)
chat.sendMessage('How much do I owe?', {
  onChunk: (chunk) => {
    document.getElementById('response')!.textContent += chunk;
  },
  onComplete: (response) => {
    console.log('Complete response:', response);
  },
});
```

---

## Error Handling

### Common Errors

| Error                                     | Cause                       | Solution                            |
| ----------------------------------------- | --------------------------- | ----------------------------------- |
| `Not authenticated`                       | Missing/invalid JWT         | Check token validity and expiration |
| `You do not have access to this business` | Not OWNER/ADMIN of business | Verify business membership          |
| `AI service is not configured`            | GROQ_API_KEY missing        | Contact admin                       |
| `Rate limit exceeded`                     | Too many requests           | Wait and retry                      |
| `Query is required`                       | Empty query                 | Provide non-empty query string      |

---

## Modes Explained

### Business Mode (with `businessId`)

AI acts as a **virtual CFO** analyzing:

- Total revenue and monthly trends
- Overdue invoices and amounts
- Top debtors (clients who owe the most)
- Average payment delay
- Client count
- Revenue growth

**Example queries:**

- "What is my total revenue this month?"
- "Who owes me the most money?"
- "How many invoices are overdue?"
- "Calculate my collection rate"

### Individual Mode (without `businessId`)

AI acts as a **financial assistant** analyzing:

- Invoices you've received
- Total amount due vs paid
- Overdue invoices
- Upcoming payments (next 14 days)
- Recent invoice history

**Example queries:**

- "How much do I owe?"
- "What invoices are due soon?"
- "Show my payment history"
- "Do I have any overdue bills?"

---

## REST Status Endpoint

For connection info only:

```
GET /chat/status
Authorization: Bearer <jwt_token>
```

**Response:**

```json
{
  "websocket": "ws://host/chat",
  "namespace": "/chat",
  "events": {
    "connect": "Send JWT token in auth.token or query.token",
    "chat_message": "Send: { query, businessId?, history?[] }",
    "message_start": "Streaming started",
    "message_chunk": "Response text chunk (streamed from Groq)",
    "message_complete": "Full response received",
    "message_error": "Error occurred"
  }
}
```

---

## Performance Notes

1. **Streaming is volatile**: `message_chunk` events use volatile emit for speed - chunks may be dropped if the client connection is slow. Always use `message_complete` for the definitive response.

2. **Message IDs**: Always generate a unique `messageId` per message to track concurrent requests.

3. **History**: Include previous messages in `history` for conversational context, but limit to last 10-15 exchanges.

4. **Connection**: Use `transports: ['websocket', 'polling']` for best compatibility.
