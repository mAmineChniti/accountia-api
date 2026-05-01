import {
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { ExpensesService } from './expenses.service';
import { ExpenseStatus, ExpenseCategory } from './schemas/expense.schema';

type ExpenseDoc = {
  _id: string;
  businessId: string;
  submittedBy: string;
  submittedByName: string;
  title: string;
  amount: number;
  currency?: string;
  category: ExpenseCategory;
  expenseDate: Date;
  status: ExpenseStatus;
  reviewedBy?: string;
  reviewNotes?: string;
  reviewedAt?: Date;
  reimbursedAt?: Date;
  save: jest.Mock;
};

function buildExpense(overrides: Partial<ExpenseDoc> = {}): ExpenseDoc {
  return {
    _id: 'e1',
    businessId: 'biz-1',
    submittedBy: 'u1',
    submittedByName: 'Alice',
    title: 'Lunch',
    amount: 10,
    currency: 'TND',
    category: ExpenseCategory.MEALS,
    expenseDate: new Date('2025-06-12'),
    status: ExpenseStatus.DRAFT,
    save: jest.fn().mockResolvedValue(),
    ...overrides,
  };
}

function buildService(model: Record<string, jest.Mock>) {
  const service = new ExpensesService({} as never);
  // Stub the private model resolver so we don't touch Mongoose internals.
  (service as unknown as { getExpenseModel: () => unknown }).getExpenseModel =
    () => model;
  return service;
}

describe('ExpensesService', () => {
  describe('findById', () => {
    it('throws NotFound when the expense does not exist', async () => {
      const service = buildService({
        findById: jest.fn().mockResolvedValue(null),
      });
      await expect(service.findById('e1', 'biz-1', 'db')).rejects.toThrow(
        NotFoundException
      );
    });

    it('throws Forbidden when expense belongs to a different business', async () => {
      const service = buildService({
        findById: jest
          .fn()
          .mockResolvedValue(buildExpense({ businessId: 'biz-other' })),
      });
      await expect(service.findById('e1', 'biz-1', 'db')).rejects.toThrow(
        ForbiddenException
      );
    });
  });

  describe('update', () => {
    it('rejects edits on non-draft expenses', async () => {
      const expense = buildExpense({ status: ExpenseStatus.SUBMITTED });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(expense),
        findByIdAndUpdate: jest.fn(),
      });
      await expect(
        service.update('e1', 'biz-1', 'db', { title: 'X' } as never, 'u1')
      ).rejects.toThrow(BadRequestException);
    });

    it('rejects edits from a different submitter', async () => {
      const expense = buildExpense({ submittedBy: 'someone-else' });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(expense),
        findByIdAndUpdate: jest.fn(),
      });
      await expect(
        service.update('e1', 'biz-1', 'db', { title: 'X' } as never, 'u1')
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('submit', () => {
    it('transitions DRAFT → SUBMITTED', async () => {
      const expense = buildExpense({ status: ExpenseStatus.DRAFT });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(expense),
      });
      await service.submit('e1', 'biz-1', 'db', 'u1');
      expect(expense.status).toBe(ExpenseStatus.SUBMITTED);
      expect(expense.save).toHaveBeenCalled();
    });

    it('rejects submission for non-draft', async () => {
      const expense = buildExpense({ status: ExpenseStatus.APPROVED });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(expense),
      });
      await expect(service.submit('e1', 'biz-1', 'db', 'u1')).rejects.toThrow(
        BadRequestException
      );
    });
  });

  describe('review', () => {
    it('records reviewer + decision and timestamps it', async () => {
      const expense = buildExpense({ status: ExpenseStatus.SUBMITTED });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(expense),
      });

      await service.review(
        'e1',
        'biz-1',
        'db',
        { decision: ExpenseStatus.APPROVED, reviewNotes: 'ok' } as never,
        'reviewer-1'
      );

      expect(expense.status).toBe(ExpenseStatus.APPROVED);
      expect(expense.reviewedBy).toBe('reviewer-1');
      expect(expense.reviewNotes).toBe('ok');
      expect(expense.reviewedAt).toBeInstanceOf(Date);
    });

    it('rejects review for non-submitted expenses', async () => {
      const expense = buildExpense({ status: ExpenseStatus.DRAFT });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(expense),
      });
      await expect(
        service.review(
          'e1',
          'biz-1',
          'db',
          { decision: ExpenseStatus.APPROVED } as never,
          'reviewer-1'
        )
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('markReimbursed', () => {
    it('only transitions APPROVED → REIMBURSED', async () => {
      const expense = buildExpense({ status: ExpenseStatus.APPROVED });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(expense),
      });
      await service.markReimbursed('e1', 'biz-1', 'db');
      expect(expense.status).toBe(ExpenseStatus.REIMBURSED);
      expect(expense.reimbursedAt).toBeInstanceOf(Date);
    });

    it('rejects when expense is not approved', async () => {
      const expense = buildExpense({ status: ExpenseStatus.SUBMITTED });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(expense),
      });
      await expect(service.markReimbursed('e1', 'biz-1', 'db')).rejects.toThrow(
        BadRequestException
      );
    });
  });

  describe('delete', () => {
    it('only deletes drafts', async () => {
      const expense = buildExpense({ status: ExpenseStatus.SUBMITTED });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(expense),
        findByIdAndDelete: jest.fn(),
      });
      await expect(service.delete('e1', 'biz-1', 'db', 'u1')).rejects.toThrow(
        BadRequestException
      );
    });

    it('rejects deletion from a different submitter', async () => {
      const expense = buildExpense({
        status: ExpenseStatus.DRAFT,
        submittedBy: 'someone-else',
      });
      const service = buildService({
        findById: jest.fn().mockResolvedValue(expense),
        findByIdAndDelete: jest.fn(),
      });
      await expect(service.delete('e1', 'biz-1', 'db', 'u1')).rejects.toThrow(
        ForbiddenException
      );
    });

    it('removes the document for owner of a draft', async () => {
      const expense = buildExpense({ status: ExpenseStatus.DRAFT });
      const findByIdAndDelete = jest.fn().mockResolvedValue();
      const service = buildService({
        findById: jest.fn().mockResolvedValue(expense),
        findByIdAndDelete,
      });
      await service.delete('e1', 'biz-1', 'db', 'u1');
      expect(findByIdAndDelete).toHaveBeenCalledWith('e1');
    });
  });

  describe('findByBusiness', () => {
    it('builds the conditions object from optional filters', async () => {
      const find = jest.fn().mockReturnValue({
        sort: () => ({
          skip: () => ({ limit: () => ({ lean: () => Promise.resolve([]) }) }),
        }),
      });
      const countDocuments = jest.fn().mockResolvedValue(0);
      const service = buildService({ find, countDocuments });

      await service.findByBusiness(
        'biz-1',
        'db',
        1,
        10,
        'submitted',
        'meals',
        'u1'
      );

      expect(countDocuments).toHaveBeenCalledWith({
        businessId: 'biz-1',
        status: 'submitted',
        category: 'meals',
        submittedBy: 'u1',
      });
    });
  });
});
