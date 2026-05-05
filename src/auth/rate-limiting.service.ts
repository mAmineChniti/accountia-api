import { Injectable, Inject } from '@nestjs/common';
import Redis from 'ioredis';

@Injectable()
export class RateLimitingService {
  private readonly maxLoginAttempts = 5;
  private readonly loginWindowSeconds = 10 * 60; // 10 minutes
  private readonly blockDurationSeconds = 15 * 60; // 15 minutes
  private readonly maxEmailAttempts = 5;
  private readonly emailWindowSeconds = 5 * 60; // 5 minutes
  private readonly maxOAuthStateRequests = 10;
  private readonly oauthStateWindowSeconds = 60; // 1 minute

  constructor(@Inject('REDIS_CLIENT') private readonly redis: Redis) {}

  async checkLoginAttempts(
    identifier: string,
    ip: string
  ): Promise<{ allowed: boolean; blockedUntil?: Date }> {
    const key = `rate_limit:login:${ip}:${identifier}`;
    const now = Date.now();

    // Get all attempts
    const attempts = await this.redis.lrange(key, 0, -1);
    if (attempts.length === 0) {
      return { allowed: true };
    }

    const allTimestamps = attempts.map((ts) => Number.parseInt(ts, 10));
    const lastAttempt = Math.max(...allTimestamps);
    const blockedUntil = lastAttempt + this.blockDurationSeconds * 1000;

    // Check if still within block duration from last attempt
    if (now < blockedUntil) {
      const windowStart = now - this.loginWindowSeconds * 1000;
      const recentAttempts = allTimestamps.filter((ts) => ts > windowStart);

      if (recentAttempts.length >= this.maxLoginAttempts) {
        return {
          allowed: false,
          blockedUntil: new Date(blockedUntil),
        };
      }
    }

    // Block expired, clear the list
    await this.redis.del(key);
    return { allowed: true };
  }

  async recordFailedLogin(identifier: string, ip: string): Promise<void> {
    const key = `rate_limit:login:${ip}:${identifier}`;
    const now = Date.now();

    // Use pipeline for atomic batch operation
    await this.redis
      .pipeline()
      .lpush(key, now.toString())
      .ltrim(key, 0, this.maxLoginAttempts - 1)
      .expire(key, this.loginWindowSeconds + this.blockDurationSeconds)
      .exec();
  }

  async clearLoginAttempts(identifier: string, ip: string): Promise<void> {
    const key = `rate_limit:login:${ip}:${identifier}`;
    await this.redis.del(key);
  }

  async checkEmailAttempts(
    userId: string
  ): Promise<{ allowed: boolean; waitTime?: number }> {
    const key = `rate_limit:email:${userId}`;
    const now = Date.now();

    const data = await this.redis.get(key);
    if (!data) {
      return { allowed: true };
    }

    const { count, lastAttempt } = JSON.parse(data) as {
      count: number;
      lastAttempt: number;
    };
    const timeSinceLastAttempt = now - lastAttempt;

    if (
      count >= this.maxEmailAttempts &&
      timeSinceLastAttempt < this.emailWindowSeconds * 1000
    ) {
      const waitTime = this.emailWindowSeconds * 1000 - timeSinceLastAttempt;
      return { allowed: false, waitTime };
    }

    if (timeSinceLastAttempt >= this.emailWindowSeconds * 1000) {
      // Window expired, reset counter
      await this.redis.del(key);
      return { allowed: true };
    }

    return { allowed: true };
  }

  async recordEmailAttempt(userId: string): Promise<void> {
    const key = `rate_limit:email:${userId}`;
    const now = Date.now();

    const data = await this.redis.get(key);
    const attempts = data
      ? (JSON.parse(data) as { count: number; lastAttempt: number })
      : { count: 0, lastAttempt: now };

    attempts.count += 1;
    attempts.lastAttempt = now;

    await this.redis.setex(
      key,
      this.emailWindowSeconds,
      JSON.stringify(attempts)
    );
  }

  /**
   * Decrement email attempt counter (refund) - used when email sending fails
   */
  async refundEmailAttempt(userId: string): Promise<void> {
    const key = `rate_limit:email:${userId}`;

    const data = await this.redis.get(key);
    if (!data) return;

    const attempts = JSON.parse(data) as { count: number; lastAttempt: number };
    if (attempts.count > 0) {
      attempts.count -= 1;
      if (attempts.count === 0) {
        await this.redis.del(key);
      } else {
        // Preserve TTL, but if key has no TTL or doesn't exist, use default window
        const ttl = await this.redis.ttl(key);
        const effectiveTtl = ttl > 0 ? ttl : this.emailWindowSeconds;
        await this.redis.setex(key, effectiveTtl, JSON.stringify(attempts));
      }
    }
  }

  async checkOAuthStateRequests(ip: string): Promise<{ allowed: boolean }> {
    const key = `rate_limit:oauth:${ip}`;
    const now = Date.now();

    const attempts = await this.redis.lrange(key, 0, -1);
    const windowStart = now - this.oauthStateWindowSeconds * 1000;

    const recentAttempts = attempts
      .map((ts) => Number.parseInt(ts, 10))
      .filter((ts) => ts > windowStart);

    if (recentAttempts.length >= this.maxOAuthStateRequests) {
      return { allowed: false };
    }

    return { allowed: true };
  }

  async recordOAuthStateRequest(ip: string): Promise<void> {
    const key = `rate_limit:oauth:${ip}`;
    const now = Date.now();

    // Use pipeline for atomic batch operation
    await this.redis
      .pipeline()
      .lpush(key, now.toString())
      .ltrim(key, 0, this.maxOAuthStateRequests - 1)
      .expire(key, this.oauthStateWindowSeconds)
      .exec();
  }
}
