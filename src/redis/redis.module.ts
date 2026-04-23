import { Module, Global, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis, { RedisOptions } from 'ioredis';
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
        // Allow explicit opt-in for rejecting unauthorized TLS certs when using rediss://
        const allowInsecureTls =
          config.get<boolean>('REDIS_TLS_REJECT_UNAUTHORIZED') ?? false;

        // Use an explicit redis options object. For secure redis (rediss://) we
        // provide a tls object but do NOT disable certificate verification by
        // default. Only set `rejectUnauthorized: false` when the environment
        // flag explicitly allows insecure/self-signed certs.
        const redisOptions: RedisOptions = {};
        if (url.startsWith('rediss://')) {
          // keep empty tls by default to enable verification
          redisOptions.tls = {};
          if (allowInsecureTls) {
            // opt-in: allow insecure/self-signed certs
            (redisOptions.tls as Record<string, unknown>).rejectUnauthorized =
              false;
            logger.warn(
              'REDIS_TLS_REJECT_UNAUTHORIZED is enabled — certificate verification disabled'
            );
          }
        }

        const client = new Redis(url, redisOptions);

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
