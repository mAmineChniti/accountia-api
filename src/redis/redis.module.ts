import { Module, Global, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { RedisService } from './redis.service';
import { CacheService } from './cache.service';
import { WebSocketStateService } from './websocket-state.service';

const logger = new Logger('RedisModule');

@Global()
@Module({
  providers: [
    {
      provide: 'REDIS_CLIENT',
      useFactory: (config: ConfigService) => {
        const url = config.get<string>('REDIS_URL') ?? 'redis://localhost:6379';
        const client = new Redis(url);

        // Attach error handler to prevent unhandled exceptions
        client.on('error', (err) => {
          logger.error(`Redis connection error: ${err.message}`, err.stack);
        });

        client.on('connect', () => {
          logger.log('Redis client connected');
        });

        return client;
      },
      inject: [ConfigService],
    },
    RedisService,
    CacheService,
    WebSocketStateService,
  ],
  exports: ['REDIS_CLIENT', RedisService, CacheService, WebSocketStateService],
})
export class RedisModule {}
