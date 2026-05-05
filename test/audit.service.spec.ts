import { Test, type TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { AuditService } from '../src/audit/audit.service';
import { AuditLog, AuditAction } from '../src/audit/schemas/audit-log.schema';
import { Types } from 'mongoose';
import { type CreateAuditLogDto } from '../src/audit/dto/audit-log.dto';

// Define a type for our mock model instances
interface MockAuditLogInstance {
  action: AuditAction;
  userEmail: string;
  userRole: string;
  userId?: string;
  createdAt?: Date;
  save: jest.Mock;
}

// Define the MockModel outside the describe block to satisfy unicorn/consistent-function-scoping
function MockModel(this: MockAuditLogInstance, dto: CreateAuditLogDto) {
  this.action = dto.action;
  this.userEmail = dto.userEmail;
  this.userRole = dto.userRole;
  this.userId = dto.userId ?? undefined;
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
MockModel.prototype.save = jest.fn().mockImplementation(function (
  this: MockAuditLogInstance
) {
  const savedDoc = {
    action: this.action,
    userEmail: this.userEmail,
    userRole: this.userRole,
    userId: this.userId,
    _id: new Types.ObjectId(),
    createdAt: new Date(),
  };
  return Promise.resolve({
    ...savedDoc,
    toISOString: function () {
      return savedDoc.createdAt.toISOString();
    },
  });
});

// Add static methods to MockModel

MockModel.find = jest.fn();

MockModel.countDocuments = jest.fn();

describe('AuditService', () => {
  let service: AuditService;
  let model: {
    find: jest.Mock;
    countDocuments: jest.Mock;
  };

  const mockAuditLog = {
    _id: new Types.ObjectId(),
    action: AuditAction.LOGIN,
    userEmail: 'test@example.com',
    userRole: 'CLIENT',
    userId: new Types.ObjectId(),
    ipAddress: '127.0.0.1',
    createdAt: new Date(),
    toISOString: function (this: { createdAt: Date }) {
      return this.createdAt.toISOString();
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuditService,
        {
          provide: getModelToken(AuditLog.name),
          useValue: MockModel,
        },
      ],
    }).compile();

    service = module.get<AuditService>(AuditService);
    model = module.get(getModelToken(AuditLog.name));
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('logAction', () => {
    it('should save a log entry', async () => {
      const dto: CreateAuditLogDto = {
        action: AuditAction.LOGIN,
        userEmail: 'test@example.com',
        userRole: 'CLIENT',
      };

      const result = await service.logAction(dto);
      expect(result).toBeDefined();
      expect(result?.action).toBe(AuditAction.LOGIN);
    });

    it('should return undefined if saving fails', async () => {
      jest
        .spyOn(MockModel.prototype, 'save')
        .mockRejectedValueOnce(new Error('Save failed'));

      const result = await service.logAction({
        action: AuditAction.LOGIN,
        userEmail: 'test@example.com',
        userRole: 'CLIENT',
      });
      expect(result).toBeUndefined();
    });
  });

  describe('getLogs', () => {
    it('should return paginated logs', async () => {
      const mockLogs = [mockAuditLog];
      const mockQuery = {
        sort: jest.fn().mockReturnThis(),
        skip: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue(mockLogs),
      };

      model.find.mockReturnValue(mockQuery);
      model.countDocuments.mockResolvedValue(1);

      const result = await service.getLogs(1, 10);

      expect(result.logs).toHaveLength(1);
      expect(result.total).toBe(1);
      expect(result.totalPages).toBe(1);
      expect(model.find).toHaveBeenCalledWith({});
    });

    it('should filter by action', async () => {
      const mockQuery = {
        sort: jest.fn().mockReturnThis(),
        skip: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([]),
      };

      model.find.mockReturnValue(mockQuery);
      model.countDocuments.mockResolvedValue(0);

      await service.getLogs(1, 10, AuditAction.LOGIN);

      expect(model.find).toHaveBeenCalledWith({ action: AuditAction.LOGIN });
      expect(model.countDocuments).toHaveBeenCalledWith({
        action: AuditAction.LOGIN,
      });
    });
  });
});
