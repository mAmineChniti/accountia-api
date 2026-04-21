import { Test, type TestingModule } from '@nestjs/testing';
import { getConnectionToken } from '@nestjs/mongoose';
import { ProductsService } from '../src/products/products.service';
import { CacheService } from '@/redis/cache.service';
import {
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { Types } from 'mongoose';
// Mock the AI mapper utility
jest.mock('@/common/utils/ai-mapper.util', () => ({
  mapColumnsUsingAi: jest
    .fn()
    .mockImplementation((records) => Promise.resolve(records)),
}));

describe('ProductsService', () => {
  let service: ProductsService;
  let cacheService: CacheService;
  let mockConnection: { useDb: jest.Mock };
  let mockProductModel: Record<string, jest.Mock>;
  let mockInvoiceModel: { aggregate: jest.Mock; exec: jest.Mock };
  let mockTenantDb: { model: jest.Mock };

  const businessId = new Types.ObjectId().toString();
  const databaseName = 'tenant_db';

  beforeEach(async () => {
    mockProductModel = {
      find: jest.fn().mockReturnThis(),
      findById: jest.fn(),
      findByIdAndUpdate: jest.fn(),
      findOneAndUpdate: jest.fn(),
      findOne: jest.fn().mockReturnThis(),
      findByIdAndDelete: jest.fn(),
      deleteOne: jest.fn(),
      countDocuments: jest.fn(),
      select: jest.fn().mockReturnThis(),
      sort: jest.fn().mockReturnThis(),
      skip: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      lean: jest.fn().mockReturnThis(),
      exec: jest.fn(),
      save: jest.fn(),
      or: jest.fn().mockReturnThis(),
      aggregate: jest.fn().mockReturnThis(),
    };

    // For "new productModel()" calls
    // eslint-disable-next-line unicorn/no-immediate-mutation
    mockProductModel.constructor = jest.fn().mockImplementation(() => ({
      save: jest.fn().mockResolvedValue({
        _id: new Types.ObjectId(),
        businessId,
        name: 'Test Product',
      }),
    }));
    // In NestJS/Mongoose, 'new Model()' is often mocked like this:
    const mockModelConstructor = jest.fn().mockImplementation((data) => ({
      ...data,
      _id: new Types.ObjectId(),
      save: jest.fn().mockResolvedValue({ ...data, _id: new Types.ObjectId() }),
    }));
    Object.assign(mockModelConstructor, mockProductModel);

    mockInvoiceModel = {
      aggregate: jest.fn().mockReturnThis(),
      exec: jest.fn(),
    };

    mockTenantDb = {
      model: jest.fn().mockImplementation((name: string) => {
        if (name === 'Product') return mockModelConstructor;
        if (name === 'Invoice') return mockInvoiceModel;
        return;
      }),
    };

    mockConnection = {
      useDb: jest.fn().mockReturnValue(mockTenantDb),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ProductsService,
        {
          provide: getConnectionToken(),
          useValue: mockConnection,
        },
        {
          provide: CacheService,
          useValue: {
            get: jest.fn(),
            set: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<ProductsService>(ProductsService);
    cacheService = module.get<CacheService>(CacheService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a new product', async () => {
      const dto = {
        name: 'New Product',
        description: 'Desc',
        unitPrice: 10,
        quantity: 5,
      };
      const result = await service.create(businessId, databaseName, dto as any);

      expect(mockConnection.useDb).toHaveBeenCalledWith(databaseName, {
        useCache: true,
      });
      expect(result).toBeDefined();
      expect(result.name).toBe('New Product');
    });
  });

  describe('findByBusiness', () => {
    it('should return paginated products', async () => {
      const mockProducts = [
        { _id: new Types.ObjectId(), businessId, name: 'P1' },
      ];
      mockProductModel.find.mockReturnThis();
      mockProductModel.or.mockReturnThis();
      mockProductModel.sort.mockReturnThis();
      mockProductModel.skip.mockReturnThis();
      mockProductModel.limit.mockReturnThis();
      mockProductModel.lean.mockResolvedValue(mockProducts);
      mockProductModel.countDocuments.mockResolvedValue(1);

      const result = await service.findByBusiness(
        businessId,
        databaseName,
        1,
        10,
        'search'
      );

      expect(mockProductModel.find).toHaveBeenCalled();
      expect(mockProductModel.or).toHaveBeenCalled();
      expect(result.products.length).toBe(1);
      expect(result.total).toBe(1);
    });
  });

  describe('findById', () => {
    it('should return a product if found and business access is verified', async () => {
      const productId = new Types.ObjectId().toString();
      const mockProduct = {
        _id: productId,
        businessId,
        name: 'Found Product',
        description: 'Desc',
        unitPrice: 10,
        quantity: 5,
        toString: () => productId,
      };

      mockProductModel.findById.mockResolvedValue(mockProduct);

      const result = await service.findById(
        productId,
        businessId,
        databaseName
      );

      expect(result.id).toBe(productId);
      expect(result.name).toBe('Found Product');
    });

    it('should throw NotFoundException if product not found', async () => {
      mockProductModel.findById.mockResolvedValue();

      await expect(
        service.findById('invalid-id', businessId, databaseName)
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw ForbiddenException if businessId does not match', async () => {
      const productId = new Types.ObjectId().toString();
      const mockProduct = {
        _id: productId,
        businessId: 'other-business',
        name: 'Private Product',
      };

      mockProductModel.findById.mockResolvedValue(mockProduct);

      await expect(
        service.findById(productId, businessId, databaseName)
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('update', () => {
    it('should update a product', async () => {
      const productId = new Types.ObjectId().toString();
      const mockProduct = { _id: productId, businessId, name: 'Old Name' };
      const dto = { name: 'New Name' };

      mockProductModel.findById.mockResolvedValue(mockProduct);
      mockProductModel.findByIdAndUpdate.mockResolvedValue({
        ...mockProduct,
        ...dto,
      });

      const result = await service.update(
        productId,
        businessId,
        databaseName,
        dto as any
      );

      expect(result.name).toBe('New Name');
      expect(mockProductModel.findByIdAndUpdate).toHaveBeenCalled();
    });
  });

  describe('delete', () => {
    it('should delete a product', async () => {
      const productId = new Types.ObjectId().toString();
      const mockProduct = { _id: productId, businessId };

      mockProductModel.findById.mockResolvedValue(mockProduct);

      await service.delete(productId, businessId, databaseName);

      expect(mockProductModel.findByIdAndDelete).toHaveBeenCalledWith(
        productId
      );
    });
  });

  describe('deleteMany', () => {
    it('should bulk delete products', async () => {
      const ids = [
        new Types.ObjectId().toString(),
        new Types.ObjectId().toString(),
      ];

      mockProductModel.deleteOne.mockResolvedValueOnce({ deletedCount: 1 });
      mockProductModel.deleteOne.mockResolvedValueOnce({ deletedCount: 0 });

      const result = await service.deleteMany(ids, businessId, databaseName);

      expect(result.deleted).toBe(1);
      expect(result.notFound.length).toBe(1);
    });
  });

  describe('findByIdsForBusiness', () => {
    it('should return products by IDs', async () => {
      const ids = [new Types.ObjectId().toString()];
      const mockProducts = [{ _id: ids[0], businessId, name: 'P1' }];

      mockProductModel.find.mockReturnThis();
      mockProductModel.lean.mockResolvedValue(mockProducts);

      const result = await service.findByIdsForBusiness(
        ids,
        businessId,
        databaseName
      );

      expect(result.length).toBe(1);
      expect(result[0].name).toBe('P1');
    });
  });

  describe('existsForBusiness', () => {
    it('should return true if product exists', async () => {
      const productId = new Types.ObjectId().toString();
      mockProductModel.findOne.mockReturnThis();
      mockProductModel.select.mockReturnThis();
      mockProductModel.lean.mockResolvedValue({ _id: productId });

      const result = await service.existsForBusiness(
        productId,
        businessId,
        databaseName
      );

      expect(result).toBe(true);
    });

    it('should return false if product does not exist', async () => {
      mockProductModel.findOne.mockReturnThis();
      mockProductModel.select.mockReturnThis();
      mockProductModel.lean.mockResolvedValue();

      const result = await service.existsForBusiness(
        'any',
        businessId,
        databaseName
      );

      expect(result).toBe(false);
    });
  });

  describe('updateQuantity', () => {
    it('should increment quantity', async () => {
      const productId = new Types.ObjectId().toString();
      const mockProduct = { _id: productId, businessId, quantity: 10 };
      mockProductModel.findById.mockResolvedValue(mockProduct);
      mockProductModel.findByIdAndUpdate.mockResolvedValue({
        ...mockProduct,
        quantity: 15,
      });

      const result = await service.updateQuantity(
        productId,
        businessId,
        databaseName,
        5
      );

      expect(mockProductModel.findByIdAndUpdate).toHaveBeenCalledWith(
        productId,
        { $inc: { quantity: 5 } },
        { returnDocument: 'after' }
      );
      expect(result.quantity).toBe(15);
    });

    it('should throw BadRequestException for insufficient stock on decrement', async () => {
      const productId = new Types.ObjectId().toString();
      const mockProduct = { _id: productId, businessId, quantity: 10 };
      mockProductModel.findById.mockResolvedValue(mockProduct);
      mockProductModel.findOneAndUpdate.mockResolvedValue(); // Simulate atomic fail

      await expect(
        service.updateQuantity(productId, businessId, databaseName, -15)
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('getStockInsights', () => {
    it('should return cached insights if available', async () => {
      const cachedData = { businessId, items: [] };
      (cacheService.get as jest.Mock).mockResolvedValue(cachedData);

      const result = await service.getStockInsights(businessId, databaseName);

      expect(cacheService.get).toHaveBeenCalled();
      expect(result).toEqual(cachedData);
    });

    it('should calculate insights and cache them if not cached', async () => {
      (cacheService.get as jest.Mock).mockResolvedValue();

      const productId = new Types.ObjectId().toString();
      const mockProducts = [
        { _id: productId, name: 'P1', quantity: 10, unitPrice: 100 },
      ];

      mockProductModel.find.mockReturnThis();
      mockProductModel.select.mockReturnThis();
      mockProductModel.lean.mockResolvedValue(mockProducts);

      mockInvoiceModel.aggregate.mockReturnThis();
      mockInvoiceModel.exec.mockResolvedValue([
        { productId: productId, soldQuantity: 70 }, // 70 sold in 30 days = 2.33 / day
      ]);

      const result = await service.getStockInsights(
        businessId,
        databaseName,
        30,
        30
      );

      expect(result.items.length).toBe(1);
      expect(result.items[0].dailySalesRate).toBe(2.33);
      expect(result.items[0].estimatedDaysUntilStockout).toBe(4.3); // 10 / 2.33 = 4.29
      expect(result.items[0].riskLevel).toBe('HIGH'); // stockout < 7 days
      expect(cacheService.set).toHaveBeenCalled();
    });
  });

  describe('importProducts', () => {
    it('should import valid products', async () => {
      const records = [
        {
          name: 'Imported P',
          description: 'Desc',
          unitPrice: '100',
          quantity: '10',
          cost: '50',
        },
      ];

      // mapColumnsUsingAi is already mocked to return the same records

      const result = await service.importProducts(
        businessId,
        databaseName,
        records
      );

      expect(result.imported).toBe(1);
      expect(result.failed).toBe(0);
    });

    it('should handle validation errors in rows', async () => {
      const records = [
        { name: '', description: 'Desc' }, // Invalid name
        { name: 'P2', description: 'Desc', unitPrice: 'invalid' }, // Invalid price
      ];

      const result = await service.importProducts(
        businessId,
        databaseName,
        records
      );

      expect(result.failed).toBe(2);
      expect(result.errors[0]).toContain('Missing required field: name');
    });
  });
});
