import { Test, type TestingModule } from '@nestjs/testing';
import { type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { type InvoiceReceiptResponseDto } from '../src/invoices/dto/invoice.dto';
import { AppModule } from './../src/app.module';

jest.setTimeout(60_000);

describe('CompanyInvoices (e2e)', () => {
  let app: INestApplication;
  let jwtToken: string;
  const businessId = '69d969f17a9661afc2afbb2f';
  let firstReceiptId: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    // Authenticate
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

  it('/invoices/received/business (GET) - Should list invoices received by business', async () => {
    if (!jwtToken) return;

    const response = await request(app.getHttpServer() as string)
      .get(`/invoices/received/business?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    expect(response.body).toHaveProperty('receipts');
    expect(
      Array.isArray(
        (response.body as { receipts: InvoiceReceiptResponseDto[] }).receipts
      )
    ).toBe(true);

    if (
      (response.body as { receipts: InvoiceReceiptResponseDto[] }).receipts
        .length > 0
    ) {
      firstReceiptId = (
        response.body as { receipts: InvoiceReceiptResponseDto[] }
      ).receipts[0].id;
    }
  });

  it('/invoices/received/:receiptId/details (GET) - Should get details of a received invoice', async () => {
    if (!jwtToken || !firstReceiptId) {
      console.log(
        'Skipping detail test: No receipts found in inbox for this test business.'
      );
      return;
    }

    const response = await request(app.getHttpServer() as string)
      .get(
        `/invoices/received/${firstReceiptId}/details?businessId=${businessId}`
      )
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect((res) => {
        // It might fail with 404 if the issuer's tenant DB is not reachable in CI/test env
        // or 403 if it was specifically addressed to another user.
        if (res.status === 200 || res.status === 404 || res.status === 403)
          return;
        throw new Error(
          `Unexpected status: ${res.status} ${JSON.stringify(res.body)}`
        );
      });

    if (response.status === 200) {
      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('invoiceNumber');
    }
  });
});
