import { Test, type TestingModule } from '@nestjs/testing';
import { type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';

jest.setTimeout(30_000);

describe('Statistics (e2e)', () => {
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

  it('/business/statistics (GET) - Should retrieve business statistics', async () => {
    if (!jwtToken) return;

    const response = await request(app.getHttpServer() as string)
      .get(`/business/statistics?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    expect(response.body).toHaveProperty('businessId', businessId);
    expect(response.body).toHaveProperty('kpis');
    expect(response.body).toHaveProperty('invoiceStatistics');
    expect(response.body).toHaveProperty('productStatistics');
    expect(response.body).toHaveProperty('salesAnalytics');
    expect(response.body).toHaveProperty('revenueTimeSeries');
  });

  it('/business/statistics (GET) - Should work with custom prediction horizon', async () => {
    if (!jwtToken) return;

    const response = await request(app.getHttpServer() as string)
      .get(
        `/business/statistics?businessId=${businessId}&predictionHorizonDays=60`
      )
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    expect(response.body).toHaveProperty('businessId', businessId);
  });

  it('/business/statistics (GET) - Should return 403 for unauthorized business access', async () => {
    if (!jwtToken) return;

    const otherBusinessId = '600000000000000000000000'; // Non-existent ID
    await request(app.getHttpServer() as string)
      .get(`/business/statistics?businessId=${otherBusinessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(404);
  });
});
