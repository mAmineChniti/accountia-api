import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';

@Injectable()
export class RateLimitingService implements OnModuleInit, OnModuleDestroy {
  private loginAttempts = new Map<string, Date[]>();
  private emailAttempts = new Map<
    string,
    { count: number; lastAttempt: Date }
  >();
  private cleanupInterval: NodeJS.Timeout;

  private readonly maxLoginAttempts = 5;
  private readonly loginWindow = 10 * 60 * 1000;
  private readonly blockDuration = 15 * 60 * 1000;
  private readonly maxEmailAttempts = 5;
  private readonly emailWindow = 5 * 60 * 1000;
  private readonly cleanupIntervalMs = 5 * 60 * 1000;

  onModuleInit() {
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredEntries();
    }, this.cleanupIntervalMs);
  }

  onModuleDestroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }

  private cleanupExpiredEntries() {
    const now = new Date();
    const maxWindow = Math.max(this.loginWindow, this.blockDuration);

    for (const [key, attempts] of this.loginAttempts.entries()) {
      const recentAttempts = attempts.filter(
        (attempt) => now.getTime() - attempt.getTime() < maxWindow
      );

      if (recentAttempts.length === 0) {
        this.loginAttempts.delete(key);
      } else {
        this.loginAttempts.set(key, recentAttempts);
      }
    }

    for (const [userId, attempts] of this.emailAttempts.entries()) {
      const timeSinceLastAttempt =
        now.getTime() - attempts.lastAttempt.getTime();

      if (timeSinceLastAttempt > this.emailWindow) {
        this.emailAttempts.delete(userId);
      }
    }
  }

  checkLoginAttempts(
    identifier: string,
    ip: string
  ): { allowed: boolean; blockedUntil?: Date } {
    const key = `${ip}:${identifier}`;
    const now = new Date();
    const attempts = this.loginAttempts.get(key) ?? [];

    const maxWindow = Math.max(this.loginWindow, this.blockDuration);
    const recentAttempts = attempts.filter(
      (attempt) => now.getTime() - attempt.getTime() < maxWindow
    );

    if (recentAttempts.length >= this.maxLoginAttempts) {
      const lastAttempt = attempts.at(-1);
      if (
        lastAttempt &&
        now.getTime() - lastAttempt.getTime() < this.blockDuration
      ) {
        return {
          allowed: false,
          blockedUntil: new Date(lastAttempt.getTime() + this.blockDuration),
        };
      }
      this.loginAttempts.delete(key);
      return { allowed: true };
    }

    this.loginAttempts.set(key, recentAttempts);
    return { allowed: true };
  }

  recordFailedLogin(identifier: string, ip: string): void {
    const key = `${ip}:${identifier}`;
    const attempts = this.loginAttempts.get(key) ?? [];
    attempts.push(new Date());
    this.loginAttempts.set(key, attempts);
  }

  clearLoginAttempts(identifier: string, ip: string): void {
    const key = `${ip}:${identifier}`;
    this.loginAttempts.delete(key);
  }

  checkEmailAttempts(userId: string): { allowed: boolean; waitTime?: number } {
    const now = new Date();
    const attempts = this.emailAttempts.get(userId);

    if (!attempts) {
      return { allowed: true };
    }

    const timeSinceLastAttempt = now.getTime() - attempts.lastAttempt.getTime();

    if (
      attempts.count >= this.maxEmailAttempts &&
      timeSinceLastAttempt < this.emailWindow
    ) {
      const waitTime = this.emailWindow - timeSinceLastAttempt;
      return { allowed: false, waitTime };
    }

    if (timeSinceLastAttempt >= this.emailWindow) {
      this.emailAttempts.delete(userId);
      return { allowed: true };
    }

    return { allowed: true };
  }

  recordEmailAttempt(userId: string): void {
    const now = new Date();
    const attempts = this.emailAttempts.get(userId) ?? {
      count: 0,
      lastAttempt: now,
    };

    attempts.count += 1;
    attempts.lastAttempt = now;

    this.emailAttempts.set(userId, attempts);
  }
}
