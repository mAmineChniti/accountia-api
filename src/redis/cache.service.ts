import { Injectable, Inject } from '@nestjs/common';
import Redis from 'ioredis';

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}

@Injectable()
export class CacheService {
  private readonly DEFAULT_TTL = 300; // 5 minutes

  constructor(@Inject('REDIS_CLIENT') private readonly redis: Redis) {}

  /**
   * Get cached data by key
   */
  async get<T>(key: string): Promise<T | undefined> {
    const data = await this.redis.get(`cache:${key}`);
    if (!data) return undefined;

    try {
      const parsed: unknown = JSON.parse(data);
      const entry = parsed as CacheEntry<T>;
      if (entry.expiresAt && Date.now() > entry.expiresAt) {
        await this.redis.del(`cache:${key}`);
        return undefined;
      }
      return entry.data;
    } catch {
      return undefined;
    }
  }

  /**
   * Set cached data with optional TTL (in seconds)
   */
  async set<T>(
    key: string,
    data: T,
    ttlSeconds: number = this.DEFAULT_TTL
  ): Promise<void> {
    const entry: CacheEntry<T> = {
      data,
      expiresAt: Date.now() + ttlSeconds * 1000,
    };
    await this.redis.setex(`cache:${key}`, ttlSeconds, JSON.stringify(entry));
  }

  /**
   * Delete cached data by key
   */
  async del(key: string): Promise<void> {
    await this.redis.del(`cache:${key}`);
  }

  /**
   * Delete multiple keys by pattern
   */
  async delPattern(pattern: string): Promise<void> {
    const keys = await this.redis.keys(`cache:${pattern}`);
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }

  /**
   * Check if key exists
   */
  async exists(key: string): Promise<boolean> {
    const result = await this.redis.exists(`cache:${key}`);
    return result === 1;
  }

  /**
   * Get or set cache - executes factory function only if cache miss
   */
  async getOrSet<T>(
    key: string,
    factory: () => Promise<T>,
    ttlSeconds: number = this.DEFAULT_TTL
  ): Promise<T> {
    const cached = await this.get<T>(key);
    if (cached !== undefined) {
      return cached;
    }

    const data = await factory();
    await this.set(key, data, ttlSeconds);
    return data;
  }

  /**
   * Increment counter (useful for rate limiting or statistics)
   */
  async increment(
    key: string,
    ttlSeconds: number = this.DEFAULT_TTL
  ): Promise<number> {
    const fullKey = `cache:counter:${key}`;
    const multi = await this.redis
      .multi()
      .incr(fullKey)
      .expire(fullKey, ttlSeconds)
      .exec();
    return (multi?.[0]?.[1] as number) ?? 0;
  }

  /**
   * Clear all cache entries
   */
  async flush(): Promise<void> {
    const keys = await this.redis.keys('cache:*');
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }
}
