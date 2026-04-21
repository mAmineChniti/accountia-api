import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import OpenAI from 'openai';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const pdfParse = require('pdf-parse') as (buffer: Buffer) => Promise<{ text: string }>;
import { ExpenseCategory } from '../schemas/expense.schema';

export interface ExtractedReceiptData {
  title: string;
  amount: number;
  currency: string;
  expenseDate: string;
  vendor: string;
  category: ExpenseCategory;
  description: string;
  confidence: 'high' | 'medium' | 'low';
}

const VISION_MODEL = 'meta-llama/llama-4-scout-17b-16e-instruct';
const TEXT_MODEL = 'llama-3.3-70b-versatile';

const CATEGORIES = Object.values(ExpenseCategory).join(', ');

const EXTRACTION_PROMPT = `You are a receipt/invoice data extractor. Extract the following fields from the document and return ONLY a valid JSON object with no markdown, no explanation.

Fields to extract:
- title: short descriptive title of the expense (e.g. "Team Lunch at Restaurant X")
- amount: total amount as a number (no currency symbol)
- currency: currency code (default "TND" if unclear)
- expenseDate: date in YYYY-MM-DD format (use today if not found)
- vendor: merchant/vendor name
- category: one of [${CATEGORIES}] — pick the most appropriate
- description: brief description of what was purchased
- confidence: "high" if most fields found clearly, "medium" if some guessed, "low" if mostly guessed

Return ONLY the JSON object, nothing else.`;

@Injectable()
export class ReceiptExtractionService {
  private readonly logger = new Logger(ReceiptExtractionService.name);

  private getGroqClient(): OpenAI {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) throw new BadRequestException('GROQ_API_KEY not configured');
    return new OpenAI({ apiKey, baseURL: 'https://api.groq.com/openai/v1' });
  }

  async extractFromFile(file: Express.Multer.File): Promise<ExtractedReceiptData> {
    const mime = file.mimetype;

    if (mime === 'application/pdf') {
      return this.extractFromPdf(file.buffer);
    }

    if (mime.startsWith('image/')) {
      return this.extractFromImage(file.buffer, mime);
    }

    throw new BadRequestException(
      'Unsupported file type. Please upload a PDF, PNG, JPG, or WEBP.'
    );
  }

  private async extractFromImage(
    buffer: Buffer,
    mimeType: string
  ): Promise<ExtractedReceiptData> {
    const base64 = buffer.toString('base64');
    const client = this.getGroqClient();

    const response = await client.chat.completions.create({
      model: VISION_MODEL,
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'image_url',
              image_url: { url: `data:${mimeType};base64,${base64}` },
            },
            { type: 'text', text: EXTRACTION_PROMPT },
          ],
        },
      ],
      max_tokens: 512,
    });

    return this.parseGroqResponse(response.choices[0]?.message?.content ?? '');
  }

  private async extractFromPdf(buffer: Buffer): Promise<ExtractedReceiptData> {
    let text: string;
    try {
      const parsed = await pdfParse(buffer);
      text = parsed.text?.trim();
    } catch {
      throw new BadRequestException('Failed to read PDF. Make sure it is not password protected.');
    }

    if (!text || text.length < 10) {
      throw new BadRequestException('PDF appears to be empty or image-only. Please upload a text-based PDF or an image instead.');
    }

    const client = this.getGroqClient();
    const response = await client.chat.completions.create({
      model: TEXT_MODEL,
      messages: [
        {
          role: 'system',
          content: EXTRACTION_PROMPT,
        },
        {
          role: 'user',
          content: `Receipt/Invoice text:\n\n${text.slice(0, 4000)}`,
        },
      ],
      max_tokens: 512,
      response_format: { type: 'json_object' },
    });

    return this.parseGroqResponse(response.choices[0]?.message?.content ?? '');
  }

  private parseGroqResponse(raw: string): ExtractedReceiptData {
    try {
      const cleaned = raw.replace(/```json|```/g, '').trim();
      const parsed = JSON.parse(cleaned) as Partial<ExtractedReceiptData>;

      const today = new Date().toISOString().split('T')[0];
      const validCategories = new Set(Object.values(ExpenseCategory));

      return {
        title: String(parsed.title ?? 'Untitled Expense').slice(0, 100),
        amount: Math.max(0, Number(parsed.amount) || 0),
        currency: String(parsed.currency ?? 'TND').toUpperCase().slice(0, 3),
        expenseDate: /^\d{4}-\d{2}-\d{2}$/.test(String(parsed.expenseDate ?? ''))
          ? String(parsed.expenseDate)
          : today,
        vendor: String(parsed.vendor ?? '').slice(0, 100),
        category: validCategories.has(parsed.category as ExpenseCategory)
          ? (parsed.category as ExpenseCategory)
          : ExpenseCategory.OTHER,
        description: String(parsed.description ?? '').slice(0, 500),
        confidence: (['high', 'medium', 'low'].includes(String(parsed.confidence))
          ? parsed.confidence
          : 'medium') as ExtractedReceiptData['confidence'],
      };
    } catch (err) {
      this.logger.error('Failed to parse Groq response', raw);
      throw new BadRequestException('AI could not extract data from this document. Please fill the form manually.');
    }
  }
}
