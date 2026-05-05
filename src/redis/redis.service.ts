import { Injectable, Inject, OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleDestroy {
  constructor(@Inject('REDIS_CLIENT') private readonly redis: Redis) {}

  async get(key: string): Promise<string | null> {
    return this.redis.get(key);
  }

  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (ttl === undefined) {
      await this.redis.set(key, value);
    } else if (ttl > 0) {
      await this.redis.setex(key, ttl, value);
    } else {
      throw new Error('TTL must be a positive integer or undefined');
    }
  }

  async del(key: string): Promise<void> {
    await this.redis.del(key);
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.redis.exists(key);
    return result === 1;
  }

  async expire(key: string, seconds: number): Promise<void> {
    await this.redis.expire(key, seconds);
  }

  async increment(key: string): Promise<number> {
    return this.redis.incr(key);
  }

  async decrement(key: string): Promise<number> {
    return this.redis.decr(key);
  }

  async getKeys(pattern: string): Promise<string[]> {
    // Use SCAN instead of KEYS to avoid blocking Redis
    const keys: string[] = [];
    let cursor = '0';
    do {
      const result = await this.redis.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        100
      );
      cursor = result[0];
      keys.push(...result[1]);
    } while (cursor !== '0');
    return keys;
  }

  async flushAll(force = false): Promise<void> {
    // Safety check: only allow in non-production or with explicit force flag
    if (!force && process.env.NODE_ENV === 'production') {
      throw new Error(
        'flushAll is not allowed in production. Use force=true to override.'
      );
    }
    await this.redis.flushall();
  }

  getClient(): Redis {
    return this.redis;
  }

  onModuleDestroy() {
    this.redis.disconnect();
  }
}
