import { Test, type TestingModule } from '@nestjs/testing';
import { type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { type BusinessInviteResponseDto } from '../src/business/dto/business-invite.dto';
import { AppModule } from './../src/app.module';

jest.setTimeout(60_000);

describe('Invites (e2e)', () => {
  let app: INestApplication;
  let jwtToken: string;
  const businessId = '69d969f17a9661afc2afbb2f';
  let createdInviteId: string;
  const testEmail = `test-invite-${Date.now()}@example.com`;

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

  it('/business/invites (POST) - Should create a new invitation', async () => {
    if (!jwtToken) return;

    const response = await request(app.getHttpServer() as string)
      .post('/business/invites')
      .set('Authorization', `Bearer ${jwtToken}`)
      .send({
        businessId: businessId,
        invitedEmail: testEmail,
        businessRole: 'MEMBER',
      })
      .expect(201);

    expect(response.body).toHaveProperty('invite');
    expect((response.body as { invite: { id: string } }).invite).toHaveProperty(
      'id'
    );
    createdInviteId = (response.body as { invite: { id: string } }).invite.id;
  });

  it('/business/invites/pending (GET) - Should list pending invitations', async () => {
    if (!jwtToken) return;

    const response = await request(app.getHttpServer() as string)
      .get(`/business/invites/pending?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    expect(response.body).toHaveProperty('invites');
    expect(
      Array.isArray(
        (response.body as { invites: BusinessInviteResponseDto['invite'][] })
          .invites
      )
    ).toBe(true);
    const found = (
      response.body as { invites: BusinessInviteResponseDto['invite'][] }
    ).invites.some((inv) => inv.invitedEmail === testEmail);
    expect(found).toBe(true);
  });

  it('/business/invites/:id (DELETE) - Should revoke an invitation', async () => {
    if (!jwtToken || !createdInviteId) return;

    await request(app.getHttpServer() as string)
      .delete(`/business/invites/${createdInviteId}?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    // Verify it's gone
    const listResponse = await request(app.getHttpServer() as string)
      .get(`/business/invites/pending?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    const found = (
      listResponse.body as { invites: BusinessInviteResponseDto['invite'][] }
    ).invites.some((inv) => inv.id === createdInviteId);
    expect(found).toBe(false);
  });
});
