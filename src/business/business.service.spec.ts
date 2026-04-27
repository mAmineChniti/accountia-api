import { BusinessService } from './business.service';
import { BusinessUserRole } from './enums/business-user-role.enum';

type Mocked<T> = { [K in keyof T]: jest.Mock };

// Build a service instance with the dependencies we exercise mocked, and the
// rest stubbed out so the constructor does not blow up.
function buildService(
  overrides: Partial<{
    businessUserModel: Mocked<{ find: () => unknown; findOne: () => unknown }>;
    businessModel: Mocked<{ find: () => unknown; findById: () => unknown }>;
    userModel: Mocked<{ find: () => unknown }>;
    businessApplicationModel: Mocked<{ findOne: () => unknown }>;
  }> = {}
) {
  const businessUserModel = overrides.businessUserModel ?? {
    find: jest.fn(),
    findOne: jest.fn(),
  };
  const businessModel = overrides.businessModel ?? {
    find: jest.fn(),
    findById: jest.fn(),
  };
  const userModel = overrides.userModel ?? { find: jest.fn() };
  const businessApplicationModel = overrides.businessApplicationModel ?? {
    findOne: jest.fn().mockResolvedValue(null),
  };

  const service = new BusinessService(
    {} as never, // connection
    businessModel as never,
    businessApplicationModel as never,
    businessUserModel as never,
    {} as never, // businessInviteModel
    userModel as never,
    {} as never, // emailService
    {} as never, // tenantConnectionService
    {} as never, // auditEmitter
    {} as never, // notificationsService
    {} as never, // tensorflowPredictionService
    { get: jest.fn().mockReturnValue() } as never, // configService
    {} as never // cacheService
  );

  return {
    service,
    businessUserModel,
    businessModel,
    userModel,
    businessApplicationModel,
  };
}

describe('BusinessService', () => {
  describe('getMyBusinesses', () => {
    it('queries memberships including the CLIENT role', async () => {
      const find = jest.fn().mockReturnValue({
        select: () => ({ lean: () => Promise.resolve([]) }),
      });
      const { service, businessApplicationModel } = buildService({
        businessUserModel: { find, findOne: jest.fn() },
      });
      businessApplicationModel.findOne.mockResolvedValue(null);

      await service.getMyBusinesses('u1');

      expect(find).toHaveBeenCalledWith({
        userId: 'u1',
        role: {
          $in: [
            BusinessUserRole.OWNER,
            BusinessUserRole.ADMIN,
            BusinessUserRole.MEMBER,
            BusinessUserRole.CLIENT,
          ],
        },
      });
    });

    it('returns empty list when user has no memberships and no approved application', async () => {
      const businessUserModel = {
        find: jest.fn().mockReturnValue({
          select: () => ({ lean: () => Promise.resolve([]) }),
        }),
        findOne: jest.fn(),
      };
      const businessApplicationModel = {
        findOne: jest.fn().mockResolvedValue(null),
      };

      const { service } = buildService({
        businessUserModel,
        businessApplicationModel,
      });
      const result = await service.getMyBusinesses('u1');
      expect(result).toEqual({
        message: 'No businesses found',
        businesses: [],
      });
    });

    it('attaches role to each returned business', async () => {
      const businessUserModel = {
        find: jest.fn().mockReturnValue({
          select: () => ({
            lean: () =>
              Promise.resolve([
                { businessId: 'b1', role: BusinessUserRole.OWNER },
                { businessId: 'b2', role: BusinessUserRole.CLIENT },
              ]),
          }),
        }),
        findOne: jest.fn(),
      };
      const businessModel = {
        find: jest.fn().mockReturnValue({
          select: () => ({
            sort: () => ({
              lean: () =>
                Promise.resolve([
                  {
                    _id: { toString: () => 'b1' },
                    name: 'One',
                    phone: '111',
                    status: 'approved',
                    createdAt: new Date('2025-01-01'),
                  },
                  {
                    _id: { toString: () => 'b2' },
                    name: 'Two',
                    phone: '222',
                    status: 'approved',
                    createdAt: new Date('2025-02-01'),
                  },
                ]),
            }),
          }),
        }),
        findById: jest.fn(),
      };

      const { service } = buildService({ businessUserModel, businessModel });
      const result = await service.getMyBusinesses('u1');

      expect(result.businesses).toHaveLength(2);
      const b1 = result.businesses.find((b) => b.id === 'b1');
      const b2 = result.businesses.find((b) => b.id === 'b2');
      expect(b1?.role).toBe(BusinessUserRole.OWNER);
      expect(b2?.role).toBe(BusinessUserRole.CLIENT);
    });
  });
});
