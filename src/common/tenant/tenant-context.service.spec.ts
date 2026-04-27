import { Test } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { TenantContextService } from './tenant-context.service';
import { Business } from '@/business/schemas/business.schema';
import { BusinessUser } from '@/business/schemas/business-user.schema';
import { CacheService } from '@/redis/cache.service';
import { Role } from '@/auth/enums/role.enum';

describe('TenantContextService', () => {
  let service: TenantContextService;
  let businessModel: { findById: jest.Mock };
  let businessUserModel: { findOne: jest.Mock; find: jest.Mock };
  let cacheService: {
    get: jest.Mock;
    set: jest.Mock;
    del: jest.Mock;
    delPattern: jest.Mock;
  };

  beforeEach(async () => {
    businessModel = { findById: jest.fn() };
    businessUserModel = { findOne: jest.fn(), find: jest.fn() };
    cacheService = {
      get: jest.fn().mockResolvedValue(null),
      set: jest.fn().mockResolvedValue(),
      del: jest.fn().mockResolvedValue(),
      delPattern: jest.fn().mockResolvedValue(),
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        TenantContextService,
        { provide: getModelToken(Business.name), useValue: businessModel },
        {
          provide: getModelToken(BusinessUser.name),
          useValue: businessUserModel,
        },
        { provide: CacheService, useValue: cacheService },
      ],
    }).compile();

    service = moduleRef.get(TenantContextService);
  });

  describe('resolveUserBusinessId', () => {
    it('returns businessId when user has exactly one membership', async () => {
      businessUserModel.find.mockReturnValue({
        select: () => ({
          limit: () => Promise.resolve([{ businessId: 'biz-1' }]),
        }),
      });

      await expect(service.resolveUserBusinessId('u1')).resolves.toBe('biz-1');
    });

    it('returns null when user has zero memberships', async () => {
      businessUserModel.find.mockReturnValue({
        select: () => ({ limit: () => Promise.resolve([]) }),
      });

      await expect(service.resolveUserBusinessId('u1')).resolves.toBeNull();
    });

    it('returns null when user has multiple memberships (must disambiguate)', async () => {
      businessUserModel.find.mockReturnValue({
        select: () => ({
          limit: () =>
            Promise.resolve([{ businessId: 'a' }, { businessId: 'b' }]),
        }),
      });

      await expect(service.resolveUserBusinessId('u1')).resolves.toBeNull();
    });
  });

  describe('resolveTenantContext', () => {
    const user = {
      id: 'u1',
      role: Role.CLIENT,
      email: 'a@b.c',
      username: 'a',
      firstName: 'A',
      lastName: 'B',
    };

    it('throws NotFound when business does not exist', async () => {
      businessModel.findById.mockReturnValue({
        select: () => Promise.resolve(null),
      });
      await expect(service.resolveTenantContext(user, 'biz-x')).rejects.toThrow(
        NotFoundException
      );
    });

    it('throws Forbidden when business is not approved', async () => {
      businessModel.findById.mockReturnValue({
        select: () =>
          Promise.resolve({
            _id: { toString: () => 'biz-1' },
            status: 'pending',
            databaseName: 'db',
          }),
      });
      await expect(service.resolveTenantContext(user, 'biz-1')).rejects.toThrow(
        ForbiddenException
      );
    });

    it('throws Forbidden when user has no membership', async () => {
      businessModel.findById.mockReturnValue({
        select: () =>
          Promise.resolve({
            _id: { toString: () => 'biz-1' },
            status: 'approved',
            databaseName: 'db',
          }),
      });
      businessUserModel.findOne.mockReturnValue({
        select: () => Promise.resolve(null),
      });

      await expect(service.resolveTenantContext(user, 'biz-1')).rejects.toThrow(
        ForbiddenException
      );
    });

    it('returns tenant context for approved member', async () => {
      businessModel.findById.mockReturnValue({
        select: () =>
          Promise.resolve({
            _id: { toString: () => 'biz-1' },
            status: 'approved',
            databaseName: 'db',
          }),
      });
      businessUserModel.findOne.mockReturnValue({
        select: () => Promise.resolve({ role: 'MEMBER' }),
      });

      await expect(
        service.resolveTenantContext(user, 'biz-1')
      ).resolves.toEqual({
        businessId: 'biz-1',
        databaseName: 'db',
        membershipRole: 'MEMBER',
      });
      expect(cacheService.set).toHaveBeenCalled();
    });

    it('skips membership lookup for platform users', async () => {
      businessModel.findById.mockReturnValue({
        select: () =>
          Promise.resolve({
            _id: { toString: () => 'biz-1' },
            status: 'approved',
            databaseName: 'db',
          }),
      });

      const platformUser = { ...user, role: Role.PLATFORM_OWNER };
      const result = await service.resolveTenantContext(platformUser, 'biz-1');
      expect(result.membershipRole).toBe('platform-admin');
      expect(businessUserModel.findOne).not.toHaveBeenCalled();
    });

    it('returns cached context on hit', async () => {
      cacheService.get.mockResolvedValue({
        businessId: 'biz-1',
        databaseName: 'db',
        membershipRole: 'OWNER',
      });
      const result = await service.resolveTenantContext(user, 'biz-1');
      expect(result.membershipRole).toBe('OWNER');
      expect(businessModel.findById).not.toHaveBeenCalled();
    });
  });
});
