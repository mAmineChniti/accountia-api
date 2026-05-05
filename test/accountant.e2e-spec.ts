import { Test, type TestingModule } from '@nestjs/testing';
import { type INestApplication } from '@nestjs/common';
import request, { type Response } from 'supertest';
import type {
  CreateJobResponse,
  AccountingResults,
  ServiceHealthResponse,
} from '../src/accountant/types/accountant-response';

// (jobs list guard removed — not used)

function isCreateJobControllerResponse(obj: unknown): obj is {
  message: string;
  timestamp: string;
  job: CreateJobResponse;
} {
  const r = obj as Record<string, unknown>;
  return (
    typeof r.message === 'string' &&
    typeof r.timestamp === 'string' &&
    'job' in r
  );
}

function isGetJobControllerResponse(obj: unknown): obj is {
  message: string;
  timestamp: string;
  results: AccountingResults;
} {
  const r = obj as Record<string, unknown>;
  return (
    typeof r.message === 'string' &&
    typeof r.timestamp === 'string' &&
    'results' in r
  );
}
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
    const response: Response = await request(app.getHttpServer() as string)
      .get(`/accountant/health`)
      .set('Authorization', `Bearer ${jwtToken}`);

    // Upstream AI Accountant may be unconfigured in CI/local dev. Accept 200 or 503.
    if (response.status === 200) {
      const body: unknown = response.body;
      expect((body as ServiceHealthResponse).service).toBe('ai-accountant');
      expect((body as ServiceHealthResponse).status).toBe('available');
    } else {
      expect(response.status).toBe(503);
      const body: unknown = response.body;
      if (typeof body === 'object' && body !== null) {
        const b = body as Record<string, unknown>;
        if (typeof b.service === 'string') {
          expect(b.service).toBe('ai-accountant');
        }
      }
    }
  });

  it('/accountant/jobs (GET) - Should return 404 for non-existent business', async () => {
    const otherBusinessId = '600000000000000000000000';
    await request(app.getHttpServer() as string)
      .get(`/accountant/jobs?businessId=${otherBusinessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(404);
  });

  it('/accountant/jobs (POST) - Create accounting job (201 or 503)', async () => {
    const payload = {
      businessId,
      periodStart: '2024-01-01T00:00:00.000Z',
      periodEnd: '2024-01-31T23:59:59.000Z',
    };

    const res: Response = await request(app.getHttpServer() as string)
      .post('/accountant/jobs')
      .set('Authorization', `Bearer ${jwtToken}`)
      .send(payload);

    if (res.status === 503) {
      const body: unknown = res.body;
      expect(body).toBeDefined();
      let msg = '';
      if (typeof body === 'string') msg = body;
      else if (typeof body === 'object' && body !== null && 'message' in body) {
        const b = body as Record<string, unknown>;
        if (typeof b.message === 'string') msg = b.message;
      }
      expect(
        /not configured|unavailable|ai accountant/i.exec(msg)
      ).toBeTruthy();
    } else {
      expect(res.status).toBe(201);
      const body: unknown = res.body;
      expect(isCreateJobControllerResponse(body)).toBeTruthy();
      if (isCreateJobControllerResponse(body)) {
        expect(typeof body.message).toBe('string');
        expect(typeof body.timestamp).toBe('string');
        expect(typeof body.job).toBe('object');
      }
    }
  });

  it('/accountant/jobs/:taskId (GET) - Get job results (200/404/503)', async () => {
    const taskId = 'nonexistent_task';
    const res: Response = await request(app.getHttpServer() as string)
      .get(`/accountant/jobs/${taskId}?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`);

    if (res.status === 503) {
      const body: unknown = res.body;
      expect(body).toBeDefined();
    } else if (res.status === 404) {
      expect(res.status).toBe(404);
    } else {
      expect(res.status).toBe(200);
      const body: unknown = res.body;
      expect(isGetJobControllerResponse(body)).toBeTruthy();
      if (isGetJobControllerResponse(body)) {
        expect(typeof body.message).toBe('string');
        expect(typeof body.timestamp).toBe('string');
        expect(typeof body.results).toBe('object');
      }
    }
  });

  it('/accountant/taxes/:year (GET) - Get tax results (200 or 503)', async () => {
    const year = 2024;
    const res: Response = await request(app.getHttpServer() as string)
      .get(`/accountant/taxes/${year}?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`);

    if (res.status === 503) {
      expect(res.body).toBeDefined();
    } else {
      expect(res.status).toBe(200);
      const body: unknown = res.body;
      // basic structural check for tax results response
      expect(typeof body).toBe('object');
      const b = body as Record<string, unknown>;
      expect(b.businessId).toBeDefined();
      expect(b.year).toBeDefined();
    }
  });

  it('/accountant/taxes/:year (POST) - Calculate taxes (201 or 503)', async () => {
    const year = 2024;
    const res: Response = await request(app.getHttpServer() as string)
      .post(`/accountant/taxes/${year}?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .send();

    if (res.status === 503) {
      expect(res.body).toBeDefined();
    } else {
      expect(res.status).toBe(201);
      expect(typeof res.body).toBe('object');
    }
  });
});
