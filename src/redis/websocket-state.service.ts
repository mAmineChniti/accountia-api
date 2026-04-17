import { Injectable, Inject } from '@nestjs/common';
import Redis from 'ioredis';

interface ConnectionState {
  userId: string;
  socketId: string;
  connectedAt: string;
  lastPingAt: string;
  metadata?: Record<string, unknown>;
}

@Injectable()
export class WebSocketStateService {
  private readonly KEY_PREFIX = 'ws:connections';
  private readonly USER_INDEX_PREFIX = 'ws:user';
  private readonly TTL_SECONDS = 300; // 5 minutes (refreshed on each ping)

  constructor(@Inject('REDIS_CLIENT') private readonly redis: Redis) {}

  /**
   * Store connection state when user connects
   */
  async recordConnection(
    socketId: string,
    userId: string,
    metadata?: Record<string, unknown>
  ): Promise<void> {
    const now = new Date().toISOString();
    const state: ConnectionState = {
      userId,
      socketId,
      connectedAt: now,
      lastPingAt: now,
      metadata,
    };

    const pipeline = this.redis.pipeline();

    // Store connection state
    pipeline.setex(
      `${this.KEY_PREFIX}:${socketId}`,
      this.TTL_SECONDS,
      JSON.stringify(state)
    );

    // Add to user's connection index (set of socket IDs)
    pipeline.sadd(`${this.USER_INDEX_PREFIX}:${userId}`, socketId);
    // Expire the index key at the same time
    pipeline.expire(`${this.USER_INDEX_PREFIX}:${userId}`, this.TTL_SECONDS);

    await pipeline.exec();
  }

  /**
   * Update last ping time to keep connection alive
   */
  async recordPing(socketId: string): Promise<void> {
    const key = `${this.KEY_PREFIX}:${socketId}`;
    const data = await this.redis.get(key);

    if (!data) return;

    const state = JSON.parse(data) as ConnectionState;
    state.lastPingAt = new Date().toISOString();

    await this.redis.setex(key, this.TTL_SECONDS, JSON.stringify(state));

    // Also refresh user index TTL
    await this.redis.expire(
      `${this.USER_INDEX_PREFIX}:${state.userId}`,
      this.TTL_SECONDS
    );
  }

  /**
   * Remove connection state when user disconnects
   */
  async recordDisconnection(socketId: string): Promise<void> {
    const key = `${this.KEY_PREFIX}:${socketId}`;
    const data = await this.redis.get(key);

    if (data) {
      const state = JSON.parse(data) as ConnectionState;

      const pipeline = this.redis.pipeline();
      pipeline.del(key);
      pipeline.srem(`${this.USER_INDEX_PREFIX}:${state.userId}`, socketId);
      await pipeline.exec();
    }
  }

  /**
   * Get connection state by socket ID
   */
  async getConnection(socketId: string): Promise<ConnectionState | undefined> {
    const data = await this.redis.get(`${this.KEY_PREFIX}:${socketId}`);
    if (!data) return undefined;

    return JSON.parse(data) as ConnectionState;
  }

  /**
   * Get all active socket IDs for a user
   */
  async getUserConnections(userId: string): Promise<string[]> {
    return this.redis.smembers(`${this.USER_INDEX_PREFIX}:${userId}`);
  }

  /**
   * Check if user has any active connections
   */
  async isUserOnline(userId: string): Promise<boolean> {
    const count = await this.redis.scard(`${this.USER_INDEX_PREFIX}:${userId}`);
    return count > 0;
  }

  /**
   * Get total number of active connections
   */
  async getTotalConnections(): Promise<number> {
    const keys = await this.redis.keys(`${this.KEY_PREFIX}:*`);
    return keys.length;
  }

  /**
   * Broadcast message to all connections of a user (returns count of notified sockets)
   */
  async notifyUser<T>(
    userId: string,
    event: string,
    payload: T
  ): Promise<number> {
    // Store notification for each socket to be picked up
    const socketIds = await this.getUserConnections(userId);

    if (socketIds.length === 0) return 0;

    const pipeline = this.redis.pipeline();
    for (const socketId of socketIds) {
      pipeline.lpush(
        `${this.KEY_PREFIX}:${socketId}:notifications`,
        JSON.stringify({ event, payload, timestamp: Date.now() })
      );
      pipeline.ltrim(`${this.KEY_PREFIX}:${socketId}:notifications`, 0, 99); // Keep last 100
      pipeline.expire(
        `${this.KEY_PREFIX}:${socketId}:notifications`,
        this.TTL_SECONDS
      );
    }
    await pipeline.exec();

    return socketIds.length;
  }

  /**
   * Get pending notifications for a socket
   */
  async getNotifications<T>(
    socketId: string
  ): Promise<Array<{ event: string; payload: T; timestamp: number }>> {
    const key = `${this.KEY_PREFIX}:${socketId}:notifications`;
    const data = await this.redis.lrange(key, 0, -1);
    await this.redis.del(key); // Clear after reading

    return data.map(
      (item: string) =>
        JSON.parse(item) as { event: string; payload: T; timestamp: number }
    );
  }

  /**
   * Get online users count
   */
  async getOnlineUsersCount(): Promise<number> {
    const keys = await this.redis.keys(`${this.USER_INDEX_PREFIX}:*`);
    let count = 0;
    for (const key of keys) {
      const members = await this.redis.scard(key);
      if (members > 0) count++;
    }
    return count;
  }
}
