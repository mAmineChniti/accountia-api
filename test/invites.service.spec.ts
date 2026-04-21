import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken, getConnectionToken } from '@nestjs/mongoose';
import { BusinessService } from '../src/business/business.service';
import { BusinessInvite } from '../src/business/schemas/business-invite.schema';
import { Business } from '../src/business/schemas/business.schema';
import { BusinessUser } from '../src/business/schemas/business-user.schema';
import { User } from '../src/users/schemas/user.schema';
import { BusinessApplication } from '../src/business/schemas/business-application.schema';
import { EmailService } from '../src/email/email.service';
import { TenantConnectionService } from '../src/common/tenant/tenant-connection.service';
import { AuditEmitter } from '../src/audit/audit.emitter';
import { NotificationsService } from '../src/notifications/notifications.service';
import { ConfigService } from '@nestjs/config';
import { CacheService } from '../src/redis/cache.service';
import { TensorflowPredictionService } from '../src/business/services/tensorflow-prediction.service';
import { Role } from '@/auth/enums/role.enum';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { Types } from 'mongoose';
import { NotFoundException, BadRequestException } from '@nestjs/common';

describe('BusinessService (Invites)', () => {
  let service: BusinessService;
  let mockBusinessInviteModel: any;
  let mockBusinessModel: any;
  let mockBusinessUserModel: any;
  let mockUserModel: any;
  let mockEmailService: any;

  const businessId = new Types.ObjectId().toString();
  const inviterId = new Types.ObjectId().toString();
  const invitedEmail = 'newuser@example.com';

  const createMockQuery = (value: any) => ({
    select: jest.fn().mockReturnThis(),
    sort: jest.fn().mockReturnThis(),
    lean: jest.fn().mockResolvedValue(value),
    exec: jest.fn().mockResolvedValue(value),
    then: jest.fn().mockImplementation((resolve) => resolve(value)),
  });

  beforeEach(async () => {
    mockBusinessInviteModel = jest.fn().mockImplementation((dto) => ({
      ...dto,
      save: jest.fn().mockResolvedValue({ 
        ...dto, 
        _id: new Types.ObjectId(), 
        toInviteResponse: () => ({ id: '123', invitedEmail: dto.invitedEmail }) 
      }),
    }));

    Object.assign(mockBusinessInviteModel, {
      findOne: jest.fn(),
      find: jest.fn(),
      findById: jest.fn(),
      findByIdAndUpdate: jest.fn(),
      findByIdAndDelete: jest.fn(),
      create: jest.fn(),
    });

    mockBusinessModel = {
      findById: jest.fn(),
    };

    mockBusinessUserModel = {
      findOne: jest.fn(),
    };

    mockUserModel = {
      findOne: jest.fn(),
      findById: jest.fn(),
      find: jest.fn(),
    };

    mockEmailService = {
      sendBusinessInviteEmail: jest.fn().mockResolvedValue(true),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BusinessService,
        {
          provide: getModelToken(BusinessInvite.name),
          useValue: mockBusinessInviteModel,
        },
        {
          provide: getModelToken(Business.name),
          useValue: mockBusinessModel,
        },
        {
          provide: getModelToken(BusinessUser.name),
          useValue: mockBusinessUserModel,
        },
        {
          provide: getModelToken(User.name),
          useValue: mockUserModel,
        },
        {
          provide: getModelToken(BusinessApplication.name),
          useValue: {},
        },
        {
          provide: EmailService,
          useValue: mockEmailService,
        },
        {
          provide: TenantConnectionService,
          useValue: {},
        },
        {
          provide: AuditEmitter,
          useValue: { emitAction: jest.fn() },
        },
        {
          provide: NotificationsService,
          useValue: { createNotification: jest.fn() },
        },
        {
          provide: TensorflowPredictionService,
          useValue: {},
        },
        {
          provide: ConfigService,
          useValue: { get: jest.fn() },
        },
        {
          provide: CacheService,
          useValue: { delSafe: jest.fn(), delPatternSafe: jest.fn() },
        },
        {
          provide: getConnectionToken(),
          useValue: { startSession: jest.fn() },
        },
      ],
    }).compile();

    service = module.get<BusinessService>(BusinessService);
  });

  describe('inviteBusinessUser', () => {
    it('should create an invitation and send an email for a new user', async () => {
      mockBusinessModel.findById.mockResolvedValue({ _id: businessId, name: 'My Business' });
      mockBusinessInviteModel.findOne.mockReturnValue(createMockQuery(null));
      mockUserModel.findOne.mockReturnValue(createMockQuery(null));
      mockBusinessInviteModel.findByIdAndUpdate.mockReturnValue(createMockQuery({ emailSent: true }));
      
      const result = await service.inviteBusinessUser(businessId, { invitedEmail, businessRole: BusinessUserRole.MEMBER, businessId }, inviterId, Role.PLATFORM_ADMIN);

      expect(mockBusinessInviteModel).toHaveBeenCalled();
      expect(mockEmailService.sendBusinessInviteEmail).toHaveBeenCalled();
      expect(result).toBeDefined();
    });

    it('should throw BadRequestException if user already invited', async () => {
      mockBusinessModel.findById.mockResolvedValue({ _id: businessId, name: 'My Business' });
      mockBusinessInviteModel.findOne.mockReturnValue(createMockQuery({ _id: 'existing' }));

      await expect(service.inviteBusinessUser(businessId, { invitedEmail, businessRole: BusinessUserRole.MEMBER, businessId }, inviterId, Role.PLATFORM_ADMIN))
        .rejects.toThrow(BadRequestException);
    });
  });

  describe('getPendingInvites', () => {
    it('should return a list of pending invites', async () => {
      const mockInvites = [{ _id: '1', invitedEmail: 'a@b.com', inviterId: inviterId }];
      mockBusinessInviteModel.find.mockReturnValue(createMockQuery(mockInvites));
      mockUserModel.find.mockReturnValue(createMockQuery([{ _id: inviterId, firstName: 'John', lastName: 'Doe' }]));

      const result = await service.getPendingInvites(businessId, inviterId, Role.PLATFORM_ADMIN);

      expect(result.invites.length).toBe(1);
    });
  });

  describe('revokeInvite', () => {
    it('should delete a pending invite', async () => {
      const mockInvite = { 
        _id: 'invite1', 
        status: 'pending', 
        businessId: businessId,
        save: jest.fn().mockResolvedValue(true)
      };
      mockBusinessInviteModel.findById.mockReturnValue(createMockQuery(mockInvite));
      mockBusinessInviteModel.findByIdAndDelete.mockResolvedValue(mockInvite);

      const result = await service.revokeInvite(businessId, 'invite1', inviterId, Role.PLATFORM_ADMIN);

      expect(result.message).toContain('revoked');
    });

    it('should throw NotFoundException if invite not found', async () => {
      mockBusinessInviteModel.findById.mockReturnValue(createMockQuery(null));

      await expect(service.revokeInvite(businessId, 'non-existent', inviterId, Role.PLATFORM_ADMIN))
        .rejects.toThrow(NotFoundException);
    });
  });
});
