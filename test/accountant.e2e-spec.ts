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

    // Authenticate with user's credentials
    const loginResponse = await request(app.getHttpServer() as string)
      .post('/auth/login')
      .send({
        email: 'grajawiem@gmail.com',
        password: '000000000000',
      });

    if (loginResponse.status === 200) {
      jwtToken = (loginResponse.body as { accessToken: string }).accessToken;
    }
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
    if (!jwtToken) return;

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
    }
  });

  it('/accountant/history (GET) - Should return 404 for non-existent business', async () => {
    if (!jwtToken) return;

    const otherBusinessId = '600000000000000000000000';
    await request(app.getHttpServer() as string)
      .get(`/accountant/history?businessId=${otherBusinessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(404);
  });
});
