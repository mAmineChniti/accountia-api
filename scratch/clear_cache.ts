import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { CacheService } from '../src/redis/cache.service';

async function clearCache() {
  const app = await NestFactory.createApplicationContext(AppModule);
  const cacheService = app.get(CacheService);
  const businessId = '69db8f1ac8c5af43af0f0ca9';
  const cacheKey = `chat:business_context:${businessId}`;

  console.log(`Clearing cache for ${cacheKey}...`);
  await cacheService.del(cacheKey);
  console.log('Cache cleared successfully.');

  await app.close();
}

clearCache().catch(console.error);
