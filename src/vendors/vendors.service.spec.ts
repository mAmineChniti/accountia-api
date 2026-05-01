import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { VendorsService } from './vendors.service';

function buildVendor(overrides: Record<string, unknown> = {}) {
  return {
    _id: 'v1',
    businessId: 'biz-1',
    name: 'Acme',
    contactName: 'Wile',
    email: 'contact@acme.com',
    phone: '+216 000',
    address: '',
    taxId: '',
    website: '',
    paymentTermsDays: 30,
    status: 'active',
    notes: '',
    totalOrders: 0,
    totalSpend: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
    save: jest.fn().mockResolvedValue(),
    ...overrides,
  };
}

function buildService(model: Record<string, jest.Mock>) {
  const service = new VendorsService({} as never);
  (service as unknown as { getVendorModel: () => unknown }).getVendorModel =
    () => model;
  return service;
}

describe('VendorsService', () => {
  describe('findById', () => {
    it('throws NotFound when vendor is missing', async () => {
      const service = buildService({
        findById: jest.fn().mockResolvedValue(null),
      });
      await expect(service.findById('v1', 'biz-1', 'db')).rejects.toThrow(
        NotFoundException
      );
    });

    it('throws Forbidden on cross-tenant access', async () => {
      const service = buildService({
        findById: jest
          .fn()
          .mockResolvedValue(buildVendor({ businessId: 'other' })),
      });
      await expect(service.findById('v1', 'biz-1', 'db')).rejects.toThrow(
        ForbiddenException
      );
    });

    it('returns the formatted vendor', async () => {
      const vendor = buildVendor();
      const service = buildService({
        findById: jest.fn().mockResolvedValue(vendor),
      });
      const res = await service.findById('v1', 'biz-1', 'db');
      expect(res).toMatchObject({
        id: 'v1',
        businessId: 'biz-1',
        name: 'Acme',
        paymentTermsDays: 30,
        totalOrders: 0,
        totalSpend: 0,
      });
    });
  });

  describe('update', () => {
    it('strips businessId from the update payload', async () => {
      const vendor = buildVendor();
      const findByIdAndUpdate = jest.fn().mockResolvedValue(vendor);
      const service = buildService({
        findById: jest.fn().mockResolvedValue(vendor),
        findByIdAndUpdate,
      });

      await service.update('v1', 'biz-1', 'db', {
        businessId: 'attempt-takeover',
        name: 'New',
      } as never);

      const [, payload] = findByIdAndUpdate.mock.calls[0];
      expect(payload).toEqual({ name: 'New' });
      expect(payload).not.toHaveProperty('businessId');
    });

    it('throws Forbidden when updating cross-tenant', async () => {
      const vendor = buildVendor({ businessId: 'other' });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(vendor),
        findByIdAndUpdate: jest.fn(),
      });
      await expect(
        service.update('v1', 'biz-1', 'db', {} as never)
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('delete', () => {
    it('throws Forbidden on cross-tenant delete', async () => {
      const vendor = buildVendor({ businessId: 'other' });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(vendor),
        findByIdAndDelete: jest.fn(),
      });
      await expect(service.delete('v1', 'biz-1', 'db')).rejects.toThrow(
        ForbiddenException
      );
    });

    it('removes the document for the owning business', async () => {
      const findByIdAndDelete = jest.fn().mockResolvedValue();
      const service = buildService({
        findById: jest.fn().mockResolvedValue(buildVendor()),
        findByIdAndDelete,
      });
      await service.delete('v1', 'biz-1', 'db');
      expect(findByIdAndDelete).toHaveBeenCalledWith('v1');
    });
  });

  describe('findByBusiness', () => {
    it('paginates without search', async () => {
      const lean = jest
        .fn()
        .mockResolvedValue([buildVendor(), buildVendor({ _id: 'v2' })]);
      const limit = jest.fn().mockReturnValue({ lean });
      const skip = jest.fn().mockReturnValue({ limit });
      const sort = jest.fn().mockReturnValue({ skip });
      const find = jest.fn().mockReturnValue({ sort, or: jest.fn() });
      const countDocuments = jest.fn().mockResolvedValue(2);

      const service = buildService({ find, countDocuments });

      const result = await service.findByBusiness('biz-1', 'db', 2, 5);
      expect(skip).toHaveBeenCalledWith(5);
      expect(limit).toHaveBeenCalledWith(5);
      expect(result).toMatchObject({
        total: 2,
        page: 2,
        limit: 5,
        totalPages: 1,
      });
      expect(result.vendors).toHaveLength(2);
    });

    it('extends conditions with $or when search term is provided', async () => {
      const lean = jest.fn().mockResolvedValue([]);
      const limit = jest.fn().mockReturnValue({ lean });
      const skip = jest.fn().mockReturnValue({ limit });
      const sort = jest.fn().mockReturnValue({ skip });
      const or = jest.fn().mockReturnValue({ sort, or: jest.fn() });
      const find = jest.fn().mockReturnValue({ sort, or });
      const countDocuments = jest.fn().mockResolvedValue(0);

      const service = buildService({ find, countDocuments });

      await service.findByBusiness('biz-1', 'db', 1, 10, 'acme');
      expect(or).toHaveBeenCalled();
      expect(countDocuments).toHaveBeenCalledWith(
        expect.objectContaining({ businessId: 'biz-1', $or: expect.any(Array) })
      );
    });
  });

  describe('incrementStats', () => {
    it('swallows errors when the model is not registered', async () => {
      const service = new VendorsService({
        useDb: () => ({
          model: () => {
            throw new Error('not registered');
          },
        }),
      } as never);
      await expect(
        service.incrementStats('v1', 'db', 100)
      ).resolves.toBeUndefined();
    });

    it('increments totalOrders and totalSpend', async () => {
      const findByIdAndUpdate = jest.fn().mockResolvedValue();
      const service = new VendorsService({
        useDb: () => ({
          model: () => ({ findByIdAndUpdate }),
        }),
      } as never);
      await service.incrementStats('v1', 'db', 250);
      expect(findByIdAndUpdate).toHaveBeenCalledWith('v1', {
        $inc: { totalOrders: 1, totalSpend: 250 },
      });
    });
  });
});
