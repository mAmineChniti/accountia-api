import { Test, type TestingModule } from '@nestjs/testing';
import { type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';

jest.setTimeout(30_000);

describe('ProductsController (e2e)', () => {
  let app: INestApplication;
  let jwtToken: string;
  const businessId = '69d969f17a9661afc2afbb2f';
  let createdProductId: string;

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

  it('/products (GET) - Should list products', async () => {
    if (!jwtToken) return;

    const response = await request(app.getHttpServer() as string)
      .get(`/products?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    expect(response.body).toHaveProperty('products');
  });

  it('/products (POST) - Should create a new product', async () => {
    if (!jwtToken) return;

    const response = await request(app.getHttpServer() as string)
      .post('/products')
      .set('Authorization', `Bearer ${jwtToken}`)
      .send({
        businessId,
        name: 'Jest E2E Product',
        description: 'Created by Jest e2e test',
        quantity: 10,
        unitPrice: 100,
        cost: 50,
      })
      .expect(201);

    expect(response.body).toHaveProperty('id');
    expect((response.body as { name: string }).name).toBe('Jest E2E Product');

    createdProductId = (response.body as { id: string }).id;
  });

  it('/products/:id (GET) - Should get the product by ID', async () => {
    if (!jwtToken || !createdProductId) return;

    const response = await request(app.getHttpServer() as string)
      .get(`/products/${createdProductId}?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    expect(response.body).toHaveProperty('id', createdProductId);
    expect((response.body as { name: string }).name).toBe('Jest E2E Product');
  });

  it('/products/:id (PATCH) - Should update the product', async () => {
    if (!jwtToken || !createdProductId) return;

    const response = await request(app.getHttpServer() as string)
      .patch(`/products/${createdProductId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .send({
        businessId,
        name: 'Jest E2E Product Updated',
        quantity: 15,
      })
      .expect(200);

    expect((response.body as { name: string }).name).toBe(
      'Jest E2E Product Updated'
    );
    expect((response.body as { quantity: number }).quantity).toBe(15);
  });

  it('/products/stock-insights (GET) - Should get stock insights', async () => {
    if (!jwtToken) return;

    const response = await request(app.getHttpServer() as string)
      .get(`/products/stock-insights?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    expect(response.body).toBeDefined();
  });

  // Test the Import Endpoint by attaching a virtual CSV buffer
  it('/products/import (POST) - Should import products from CSV', async () => {
    if (!jwtToken) return;

    const csvContent = Buffer.from(
      'name,description,unitPrice,quantity\nE2E Item,Test,20,5'
    );

    const response = await request(app.getHttpServer() as string)
      .post(`/products/import?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .attach('file', csvContent, {
        filename: 'test.csv',
        contentType: 'text/csv',
      })
      .expect(201);

    expect(response.body).toHaveProperty('imported');
  });

  it('/products/bulk-delete (POST) - Should bulk delete products', async () => {
    if (!jwtToken) return;

    // Send a dummy ID just to see if the route responds successfully
    const response = await request(app.getHttpServer() as string)
      .post('/products/bulk-delete')
      .set('Authorization', `Bearer ${jwtToken}`)
      .query({ businessId })
      .send({
        ids: ['60d5ecb8b392d40015b67a12'],
      })
      .expect(200);

    expect((response.body as { success: boolean }).success).toBe(true);
  });

  it('/products/:id (DELETE) - Should delete the test product', async () => {
    if (!jwtToken || !createdProductId) return;

    await request(app.getHttpServer() as string)
      .delete(`/products/${createdProductId}?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(204);
  });
});
