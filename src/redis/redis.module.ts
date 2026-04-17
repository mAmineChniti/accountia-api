import { Module, Global } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { RedisService } from './redis.service';
import { CacheService } from './cache.service';
import { WebSocketStateService } from './websocket-state.service';

@Global()
@Module({
  providers: [
    {
      provide: 'REDIS_CLIENT',
      useFactory: (config: ConfigService) => {
        const url = config.get<string>('REDIS_URL') ?? 'redis://localhost:6379';
        return new Redis(url);
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
