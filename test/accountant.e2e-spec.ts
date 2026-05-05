import { Test, type TestingModule } from '@nestjs/testing';
import { type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';

jest.setTimeout(30_000);

describe('Accountant (e2e)', () => {
  let app: INestApplication;
  let jwtToken: string;
  const businessId = '69d969f17a9661afc2afbb2f';

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    // Authenticate with credentials from environment for CI determinism
    const email = process.env.TEST_USER_EMAIL;
    const password = process.env.TEST_USER_PASSWORD;
    if (!email || !password) {
      throw new Error(
        'Set TEST_USER_EMAIL and TEST_USER_PASSWORD env vars for e2e tests'
      );
    }

    const loginResponse = await request(app.getHttpServer() as string)
      .post('/auth/login')
      .send({ email, password });

    if (loginResponse.status !== 200) {
      throw new Error(
        `Auth failed during setup: ${loginResponse.status} ${JSON.stringify(loginResponse.body)}`
      );
    }

    const token = (loginResponse.body as { accessToken?: string }).accessToken;
    if (typeof token !== 'string') {
      throw new TypeError('Auth response did not contain accessToken');
    }
    jwtToken = token;
  });

  afterAll(async () => {
    await app.close();
  });

  it('/accountant/health (GET) - Should return health status', async () => {
    const response = await request(app.getHttpServer() as string)
      .get(`/accountant/health?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    expect(response.body).toHaveProperty('service', 'ai-accountant');
    expect(response.body).toHaveProperty('success');
  });

  it('/accountant/jobs (GET) - Should attempt to list jobs (handling unconfigured state)', async () => {
    const response = await request(app.getHttpServer() as string)
      .get(`/accountant/jobs?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`);

    // Expect 200 if configured, or 503 if not configured
    if (response.status === 503) {
      expect((response.body as { message: string }).message).toContain(
        'not configured'
      );
    } else {
      expect(response.status).toBe(200);
      expect((response.body as { success: boolean }).success).toBe(true);
      expect(Array.isArray((response.body as { data?: unknown }).data)).toBe(
        true
      );
      if ((response.body as { meta?: { total?: number } }).meta) {
        expect(
          typeof (response.body as { meta: { total: number } }).meta.total
        ).toBe('number');
      }
    }
  });

  it('/accountant/history (GET) - Should return 404 for non-existent business', async () => {
    const otherBusinessId = '600000000000000000000000';
    await request(app.getHttpServer() as string)
      .get(`/accountant/history?businessId=${otherBusinessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(404);
  });
});
