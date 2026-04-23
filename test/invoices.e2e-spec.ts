import { Test, type TestingModule } from '@nestjs/testing';
import { type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { type InvoiceResponseDto } from '../src/invoices/dto/invoice.dto';
import { AppModule } from './../src/app.module';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import { InvoiceRecipientType } from '@/invoices/enums/invoice-recipient.enum';

jest.setTimeout(60_000); // Increased timeout for potentially slow remote DB

describe('InvoicesController (e2e)', () => {
  let app: INestApplication;
  let jwtToken: string;
  const businessId = '69d969f17a9661afc2afbb2f';
  let createdInvoiceId: string;
  let seededProductId: string;

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

    // Seed a product for invoice line items so invoice creation is deterministic
    const productResp = await request(app.getHttpServer() as string)
      .post('/products')
      .set('Authorization', `Bearer ${jwtToken}`)
      .send({
        businessId,
        name: `E2E Seed Product ${Date.now()}`,
        description: 'Seed product for invoices e2e',
        quantity: 100,
        unitPrice: 1000,
        cost: 500,
      });

    if (productResp.status !== 201) {
      throw new Error(
        `Failed to seed product for invoices e2e: ${productResp.status} ${JSON.stringify(productResp.body)}`
      );
    }

    seededProductId = (productResp.body as { id: string }).id;
  });

  afterAll(async () => {
    await app.close();
  });

  it('/invoices (POST) - Should create a new draft invoice', async () => {
    if (!jwtToken) throw new Error('Missing jwtToken in test setup');

    const response = await request(app.getHttpServer() as string)
      .post('/invoices')
      .set('Authorization', `Bearer ${jwtToken}`)
      .send({
        businessId,
        recipient: {
          type: InvoiceRecipientType.EXTERNAL,
          email: 'customer@example.com',
          displayName: 'Test Customer',
        },
        lineItems: [
          {
            productId: seededProductId,
            productName: 'E2E Test Product',
            quantity: 1,
            unitPrice: 1500,
          },
        ],
        issuedDate: new Date(),
        dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        currency: 'TND',
      })
      .expect(201);

    expect(response.body).toHaveProperty('id');
    expect((response.body as { status: string }).status).toBe(
      InvoiceStatus.DRAFT
    );
    createdInvoiceId = (response.body as { id: string }).id;
  });

  it('/invoices/issued (GET) - Should list issued invoices', async () => {
    const response = await request(app.getHttpServer() as string)
      .get(`/invoices/issued?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    expect(response.body).toHaveProperty('invoices');
    expect(
      Array.isArray(
        (response.body as { invoices: InvoiceResponseDto[] }).invoices
      )
    ).toBe(true);
    // If we created a draft invoice earlier it should NOT appear in issued list
    if (createdInvoiceId) {
      const invoices = (response.body as { invoices: InvoiceResponseDto[] })
        .invoices;
      const found = invoices.some((inv) => inv.id === createdInvoiceId);
      expect(found).toBe(false);
    }
  });

  it('/invoices/issued/:id (GET) - Should get invoice details', async () => {
    if (!createdInvoiceId)
      throw new Error('Missing createdInvoiceId from previous test');

    const response = await request(app.getHttpServer() as string)
      .get(`/invoices/issued/${createdInvoiceId}?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    expect((response.body as { id: string }).id).toBe(createdInvoiceId);
    expect(
      (response.body as { issuerBusinessId: string }).issuerBusinessId
    ).toBe(businessId);
  });

  it('/invoices/issued/:id (PATCH) - Should update draft invoice', async () => {
    if (!createdInvoiceId)
      throw new Error('Missing createdInvoiceId from previous test');

    const response = await request(app.getHttpServer() as string)
      .patch(`/invoices/issued/${createdInvoiceId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .send({
        businessId,
        description: 'Updated draft during E2E',
      })
      .expect(200);

    expect((response.body as { description: string }).description).toBe(
      'Updated draft during E2E'
    );
  });

  it('/invoices/issued/:id/transition (POST) - Should transition state to ISSUED', async () => {
    const response = await request(app.getHttpServer() as string)
      .post(`/invoices/issued/${createdInvoiceId}/transition`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .send({
        businessId,
        status: InvoiceStatus.ISSUED,
      })
      .expect(201);

    expect((response.body as { status: string }).status).toBe(
      InvoiceStatus.ISSUED
    );
  });
});
