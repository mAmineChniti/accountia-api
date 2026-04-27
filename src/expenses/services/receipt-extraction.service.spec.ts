import { BadRequestException } from '@nestjs/common';
import { ReceiptExtractionService } from './receipt-extraction.service';
import { ExpenseCategory } from '../schemas/expense.schema';

describe('ReceiptExtractionService', () => {
  let service: ReceiptExtractionService;

  beforeEach(() => {
    service = new ReceiptExtractionService();
  });

  // parseGroqResponse is private — exercise it via the prototype
  const parse = (raw: string) =>
    (
      service as unknown as { parseGroqResponse: (raw: string) => unknown }
    ).parseGroqResponse(raw);

  describe('parseGroqResponse', () => {
    it('returns sanitized fields for a well-formed response', () => {
      const out = parse(
        JSON.stringify({
          title: 'Lunch with client',
          amount: '42.5',
          currency: 'usd',
          expenseDate: '2025-06-12',
          vendor: 'Cafe X',
          category: ExpenseCategory.MEALS,
          description: 'Business lunch',
          confidence: 'high',
        })
      );

      expect(out).toMatchObject({
        title: 'Lunch with client',
        amount: 42.5,
        currency: 'USD',
        expenseDate: '2025-06-12',
        vendor: 'Cafe X',
        category: ExpenseCategory.MEALS,
        confidence: 'high',
      });
    });

    it('strips ```json fences before parsing', () => {
      const wrapped = '```json\n{"title":"A","amount":10}\n```';
      expect(parse(wrapped)).toMatchObject({ title: 'A', amount: 10 });
    });

    it('falls back to today when date is malformed', () => {
      const out = parse(
        JSON.stringify({ title: 'X', expenseDate: '12/31/2025' })
      ) as {
        expenseDate: string;
      };
      expect(out.expenseDate).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });

    it('coerces invalid amount to 0 and clamps negatives', () => {
      expect(parse(JSON.stringify({ amount: -5 }))).toMatchObject({
        amount: 0,
      });
      expect(parse(JSON.stringify({ amount: 'NaN' }))).toMatchObject({
        amount: 0,
      });
    });

    it('defaults invalid category to OTHER', () => {
      expect(parse(JSON.stringify({ category: 'pizza' }))).toMatchObject({
        category: ExpenseCategory.OTHER,
      });
    });

    it('defaults missing confidence to medium', () => {
      expect(parse(JSON.stringify({}))).toMatchObject({ confidence: 'medium' });
    });

    it('defaults currency to TND when missing', () => {
      expect(parse(JSON.stringify({}))).toMatchObject({ currency: 'TND' });
    });

    it('throws BadRequest on unparseable JSON', () => {
      expect(() => parse('not json at all')).toThrow(BadRequestException);
    });
  });

  describe('extractFromFile', () => {
    it('rejects unsupported mime types', async () => {
      await expect(
        service.extractFromFile({
          mimetype: 'text/csv',
          buffer: Buffer.from(''),
        } as unknown as Express.Multer.File)
      ).rejects.toThrow(BadRequestException);
    });
  });
});
