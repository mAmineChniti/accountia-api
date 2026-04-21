/* eslint-disable unicorn/no-abusive-eslint-disable */
/* eslint-disable */
import { Injectable, Logger } from '@nestjs/common';
import OpenAI from 'openai';

const pdf = require('pdf-parse');
import { createWorker } from 'tesseract.js';
import * as fs from 'node:fs';

export interface ExtractedInvoiceData {
  invoiceNumber?: string;
  issuedDate?: string;
  dueDate?: string;
  currency?: string;
  vendorName?: string;
  lineItems: Array<{
    productName: string;
    quantity: number;
    unitPrice: number;
    description?: string;
  }>;
  taxAmount?: number;
  totalAmount?: number;
}

@Injectable()
export class InvoiceAiService {
  private readonly logger = new Logger(InvoiceAiService.name);
  private readonly groqClient: OpenAI | undefined;
  private readonly model = 'llama-3.3-70b-versatile';

  constructor() {
    const apiKey = process.env.GROQ_API_KEY;
    if (apiKey) {
      this.groqClient = new OpenAI({
        apiKey,
        baseURL: 'https://api.groq.com/openai/v1',
      });
    } else {
      this.logger.warn(
        'GROQ_API_KEY is not set. AI extraction will be unavailable.'
      );
    }
  }

  /**
   * Extract text and structure it from a PDF file
   */
  async processPdf(
    filePath: string,
    jobId: string
  ): Promise<{
    text: string;
    structuredData: ExtractedInvoiceData;
    method: 'text' | 'ocr';
    rawAiOutput: string;
  }> {
    this.logger.log(`[Job ${jobId}] Starting extraction for file: ${filePath}`);
    const dataBuffer = fs.readFileSync(filePath);

    // 1. Try digital text extraction first
    let text = '';
    try {
      text = await this.extractTextFromPdf(dataBuffer, jobId);
    } catch (error) {
      this.logger.warn(
        `[Job ${jobId}] Digital extraction failed: ${error.message}`
      );
    }

    let method: 'text' | 'ocr' = 'text';

    // 2. Fallback to OCR if text is too short or empty (likely scanned image)
    const isPdf = filePath.toLowerCase().endsWith('.pdf');
    if (!text || text.trim().length < 50) {
      if (isPdf) {
        this.logger.warn(
          `[Job ${jobId}] Digital extraction yield very little data (${text?.length || 0} chars) and file is PDF. OCR on PDF is not supported without conversion. Skipping OCR.`
        );
        // Note: For real production, we'd use a lib to convert PDF pages to images here.
      } else {
        this.logger.log(
          `[Job ${jobId}] Data too short (${text?.length || 0} chars). Falling back to OCR.`
        );
        text = await this.extractTextViaOcr(filePath, jobId);
        method = 'ocr';
      }
    }

    if (!text || text.trim().length === 0) {
      this.logger.error(`[Job ${jobId}] Failed to extract any text from file`);
      throw new Error('Failed to extract any text from PDF/Image');
    }

    this.logger.log(
      `[Job ${jobId}] Text extracted successfully (${text.length} chars). Sending to AI...`
    );

    // 3. Send to AI for structuring
    const { structuredData, rawAiOutput } = await this.structureDataWithAi(
      text,
      jobId
    );

    return {
      text,
      structuredData,
      method,
      rawAiOutput,
    };
  }

  private async extractTextFromPdf(
    buffer: Buffer,
    jobId: string
  ): Promise<string> {
    try {
      this.logger.debug(`[Job ${jobId}] Attempting digital PDF extraction...`);
      // Fix: Some environments wrap the exported function
      const pdfParser = typeof pdf === 'function' ? pdf : pdf.default;

      if (typeof pdfParser !== 'function') {
        this.logger.error(
          `[Job ${jobId}] pdf-parse is not a function. Type: ${typeof pdfParser}`
        );
        throw new Error('pdf-parse library not loaded correctly');
      }

      const data = await pdfParser(buffer);
      return data.text ?? '';
    } catch (error) {
      this.logger.error(
        `[Job ${jobId}] Error during pdf-parse extraction`,
        error
      );
      return '';
    }
  }

  private async extractTextViaOcr(
    filePath: string,
    jobId: string
  ): Promise<string> {
    try {
      this.logger.debug(
        `[Job ${jobId}] Attempting cleanup/OCR with Tesseract...`
      );
      // Tesseract.js creates a worker for OCR
      const worker = await createWorker('eng');
      const {
        data: { text },
      } = await worker.recognize(filePath);
      await worker.terminate();
      return text;
    } catch (error) {
      this.logger.error(
        `[Job ${jobId}] Error during Tesseract OCR extraction`,
        error
      );
      return '';
    }
  }

  private async structureDataWithAi(
    text: string,
    jobId: string
  ): Promise<{
    structuredData: ExtractedInvoiceData;
    rawAiOutput: string;
  }> {
    if (!this.groqClient) {
      this.logger.error(`[Job ${jobId}] Groq AI client is not configured`);
      throw new Error('Groq AI client is not configured');
    }

    this.logger.debug(
      `[Job ${jobId}] Sending extracted text to Groq AI (${text.length} chars)`
    );

    const systemPrompt = `
You are an expert financial data extraction assistant. 
Extract invoice information from the provided text into a strictly valid JSON format.

RULES:
1. Return ONLY the JSON object. No prose, no markdown code blocks.
2. If a field is missing, use null.
3. Do NOT perform any calculations. Use values exactly as found in text.
4. Line items must be an array of objects.
5. Dates should be in ISO format (YYYY-MM-DD) if possible.
6. The JSON must follow this exact structure:
{
  "invoiceNumber": string | null,
  "issuedDate": string | null,
  "dueDate": string | null,
  "currency": string | null,
  "vendorName": string | null,
  "lineItems": [
    {
      "productName": string,
      "quantity": number,
      "unitPrice": number,
      "description": string | null
    }
  ],
  "taxAmount": number | null,
  "totalAmount": number | null
}
`;

    const response = await this.groqClient.chat.completions.create({
      model: this.model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: `Extract from this invoice text:\n\n${text}` },
      ],
      temperature: 0,
      response_format: { type: 'json_object' },
    });

    const rawAiOutput = response.choices[0]?.message?.content ?? '{}';
    try {
      const structuredData = JSON.parse(rawAiOutput) as ExtractedInvoiceData;
      this.logger.log(`[Job ${jobId}] AI data structured successfully`);
      return { structuredData, rawAiOutput };
    } catch (error) {
      this.logger.error(
        `[Job ${jobId}] Failed to parse AI JSON response`,
        error
      );
      this.logger.debug(`[Job ${jobId}] Raw AI Output: ` + rawAiOutput);
      throw new Error('AI returned invalid JSON');
    }
  }
}
