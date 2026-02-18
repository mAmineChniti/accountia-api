import { NestFactory } from '@nestjs/core';
import { AppModule } from '@/app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ConflictExceptionFilter } from '@/common/filters/conflict-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.setGlobalPrefix('api');

  app.enableCors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      forbidUnknownValues: true,
      transform: true,
    })
  );

  app.useGlobalFilters(new ConflictExceptionFilter());

  if (process.env.NODE_ENV !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('Accountia API')
      .setDescription(
        'Business Management SaaS Platform – Multitenant System for Financial Operations and Team Collaboration'
      )
      .setVersion('1.0')
      .addBearerAuth(
        {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
        'access-token'
      )
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document);
  }

  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);

  const docsUrl =
    process.env.NODE_ENV === 'production'
      ? `Port ${port} - /api/docs`
      : `http://localhost:${String(port)}/api/docs`;
  console.log(`🚀 API running on ${docsUrl}`);
}
/* eslint-disable unicorn/prefer-top-level-await */
bootstrap().catch((error: unknown) => {
  console.error(error);
});
