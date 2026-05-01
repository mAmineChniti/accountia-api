import { BadRequestException } from '@nestjs/common';
import { ExpensesController } from './expenses.controller';
import { type ExpensesService } from './expenses.service';
import { type ReceiptExtractionService } from './services/receipt-extraction.service';
import { ExpenseCategory } from './schemas/expense.schema';
import { Role } from '@/auth/enums/role.enum';

describe('ExpensesController', () => {
  let controller: ExpensesController;
  let expensesService: jest.Mocked<ExpensesService>;
  let receiptService: jest.Mocked<ReceiptExtractionService>;

  beforeEach(() => {
    expensesService = {
      create: jest.fn(),
      findByBusiness: jest.fn(),
      getSummary: jest.fn(),
      findById: jest.fn(),
      update: jest.fn(),
      submit: jest.fn(),
      review: jest.fn(),
      markReimbursed: jest.fn(),
      delete: jest.fn(),
    } as unknown as jest.Mocked<ExpensesService>;

    receiptService = {
      extractFromFile: jest.fn(),
    } as unknown as jest.Mocked<ReceiptExtractionService>;

    controller = new ExpensesController(expensesService, receiptService);
  });

  describe('extractReceipt', () => {
    it('throws BadRequest when no file is uploaded', async () => {
      await expect(
        controller.extractReceipt(undefined as unknown as Express.Multer.File)
      ).rejects.toThrow(BadRequestException);
    });

    it('delegates to ReceiptExtractionService when a file is provided', async () => {
      const fake = {
        title: 'X',
        amount: 1,
        currency: 'TND',
        expenseDate: '2025-01-01',
        vendor: 'V',
        category: ExpenseCategory.OTHER,
        description: '',
        confidence: 'high' as const,
      };
      receiptService.extractFromFile.mockResolvedValue(fake);

      const file = {
        mimetype: 'image/png',
        buffer: Buffer.from(''),
      } as Express.Multer.File;
      await expect(controller.extractReceipt(file)).resolves.toEqual(fake);
      expect(receiptService.extractFromFile).toHaveBeenCalledWith(file);
    });
  });

  describe('create', () => {
    it('builds the user display name and forwards to the service', async () => {
      const tenant = {
        businessId: 'b1',
        databaseName: 'db',
        membershipRole: 'OWNER',
      };
      const user = {
        id: 'u1',
        firstName: 'Ada',
        lastName: 'Lovelace',
        username: 'ada',
        role: Role.CLIENT,
        email: 'a@b.c',
      };
      const dto = { title: 't' } as Parameters<typeof controller.create>[0];
      (expensesService.create as jest.Mock).mockResolvedValue('ok');

      await controller.create(dto, tenant, user);
      expect(expensesService.create).toHaveBeenCalledWith(
        'b1',
        'db',
        dto,
        'u1',
        'Ada Lovelace'
      );
    });

    it('falls back to username when first/last names are blank', async () => {
      const tenant = {
        businessId: 'b1',
        databaseName: 'db',
        membershipRole: 'OWNER',
      };
      const user = {
        id: 'u1',
        firstName: '',
        lastName: '',
        username: 'ada',
        role: Role.CLIENT,
        email: 'a@b.c',
      };
      (expensesService.create as jest.Mock).mockResolvedValue('ok');

      await controller.create(
        {} as Parameters<typeof controller.create>[0],
        tenant,
        user
      );
      expect((expensesService.create as jest.Mock).mock.calls[0][4]).toBe(
        'ada'
      );
    });
  });
});
