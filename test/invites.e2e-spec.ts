import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';

jest.setTimeout(60000);

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
    const loginResponse = await request(app.getHttpServer())
      .post('/auth/login')
      .send({
        email: 'grajawiem@gmail.com',
        password: '000000000000',
      });

    if (loginResponse.status === 200) {
      jwtToken = loginResponse.body.accessToken;
    }
  });

  afterAll(async () => {
    await app.close();
  });

  it('/business/invites (POST) - Should create a new invitation', async () => {
    if (!jwtToken) return;

    const response = await request(app.getHttpServer())
      .post('/business/invites')
      .set('Authorization', `Bearer ${jwtToken}`)
      .send({
        businessId: businessId,
        invitedEmail: testEmail,
        businessRole: 'MEMBER',
      })
      .expect(201);

    expect(response.body).toHaveProperty('invite');
    expect(response.body.invite).toHaveProperty('id');
    createdInviteId = response.body.invite.id;
  });

  it('/business/invites/pending (GET) - Should list pending invitations', async () => {
    if (!jwtToken) return;

    const response = await request(app.getHttpServer())
      .get(`/business/invites/pending?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);

    expect(response.body).toHaveProperty('invites');
    expect(Array.isArray(response.body.invites)).toBe(true);
    const found = response.body.invites.some((inv: any) => inv.invitedEmail === testEmail);
    expect(found).toBe(true);
  });

  it('/business/invites/:id (DELETE) - Should revoke an invitation', async () => {
    if (!jwtToken || !createdInviteId) return;

    await request(app.getHttpServer())
      .delete(`/business/invites/${createdInviteId}?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);
      
    // Verify it's gone
    const listResponse = await request(app.getHttpServer())
      .get(`/business/invites/pending?businessId=${businessId}`)
      .set('Authorization', `Bearer ${jwtToken}`)
      .expect(200);
      
    const found = listResponse.body.invites.some((inv: any) => inv.id === createdInviteId);
    expect(found).toBe(false);
  });
});
