import { Logger } from "@nestjs/common";
import OpenAI from "openai";
import { createWorker } from "tesseract.js";
import pdf2pic from "pdf2pic";
import sharp from "sharp";

const logger = new Logger("OcrDocumentExtraction");

interface ExtractionOptions {
  documentType: "product" | "invoice";
}

interface ProductExtractionResult {
  type: "product";
  name?: string;
  description?: string;
  unitPrice?: number;
  quantity?: number;
  cost?: number;
  currency?: string;
}

interface InvoiceLineItemExtraction {
  productName?: string;
  description?: string;
  quantity?: number;
  unitPrice?: number;
}

interface InvoiceExtractionResult {
  type: "invoice";
  invoiceNumber?: string;
  recipientName?: string;
  recipientEmail?: string;
  issuedDate?: string;
  dueDate?: string;
  totalAmount?: number;
  currency?: string;
  lineItems?: InvoiceLineItemExtraction[];
  description?: string;
  paymentTerms?: string;
}

type ExtractionResult = ProductExtractionResult | InvoiceExtractionResult;

// Initialize OpenAI client with Groq's base URL
function getGroqClient(): OpenAI | undefined {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return undefined;

  return new OpenAI({
    apiKey,
    baseURL: "https://api.groq.com/openai/v1",
  });
}

/**
 * Detect MIME type from file buffer or filename
 */
function detectMimeType(buffer: Buffer, filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase();

  if (ext === "png") return "image/png";
  if (ext === "jpg" || ext === "jpeg") return "image/jpeg";
  if (ext === "gif") return "image/gif";
  if (ext === "webp") return "image/webp";
  if (ext === "pdf") return "application/pdf";

  // Try to detect from magic bytes
  /* eslint-disable unicorn/number-literal-case */
  if (buffer.length > 4) {
    if (
      buffer[0] === 0x89 &&
      buffer[1] === 0x50 &&
      buffer[2] === 0x4e &&
      buffer[3] === 0x47
    ) {
      return "image/png";
    }
    if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
      return "image/jpeg";
    }
    if (
      buffer[0] === 0x25 &&
      buffer[1] === 0x50 &&
      buffer[2] === 0x44 &&
      buffer[3] === 0x46
    ) {
      return "application/pdf";
    }
  }
  /* eslint-enable unicorn/number-literal-case */

  return ext === "pdf" ? "application/pdf" : "image/jpeg";
}

/**
 * Convert PDF to image buffer (first page only)
 */
async function convertPdfToImage(pdfBuffer: Buffer): Promise<Buffer> {
  try {
    const options = {
      density: 150,
      format: "png" as const,
      width: 1200,
      height: 1600,
      quality: 90,
      saveFilename: "page",
      savePath: "/tmp",
    };

    const convert = pdf2pic.fromBuffer(pdfBuffer, options);
    const result = await convert(1); // Page 1

    // pdf2pic returns an array of results or a single result
    const firstResult: unknown = Array.isArray(result) ? result[0] : result;
    if (firstResult) {
      // Check if it's a base64 string or has a path
      if (typeof firstResult === "string") {
        return Buffer.from(firstResult, "base64");
      }
      if (typeof firstResult === "object" && firstResult !== null) {
        const fr = firstResult as { base64?: unknown };
        if (typeof fr.base64 === "string" && fr.base64.length > 0) {
          return Buffer.from(fr.base64, "base64");
        }
      }
    }
    throw new Error("PDF conversion failed: no output");
  } catch (error) {
    logger.error("PDF to image conversion failed", error as Error);
    throw new Error("Failed to convert PDF to image for OCR processing");
  }
}

/**
 * Preprocess image for better OCR results
 */
async function preprocessImage(imageBuffer: Buffer): Promise<Buffer> {
  try {
    return await sharp(imageBuffer)
      .grayscale() // Convert to grayscale
      .normalize() // Normalize contrast
      .sharpen({ sigma: 1 }) // Sharpen text
      .toBuffer();
  } catch {
    // If preprocessing fails, return original
    return imageBuffer;
  }
}

/**
 * Perform OCR on image buffer
 */
async function performOcr(imageBuffer: Buffer): Promise<string> {
  const worker = await createWorker("eng+ara+fra"); // English, Arabic, French
  try {
    const {
      data: { text },
    } = await worker.recognize(imageBuffer);
    return text;
  } finally {
    await worker.terminate();
  }
}

/**
 * Extract text from document (image or PDF) using OCR
 */
async function extractTextFromDocument(
  fileBuffer: Buffer,
  filename: string,
): Promise<string> {
  const mimeType = detectMimeType(fileBuffer, filename);
  let imageBuffer: Buffer;

  if (mimeType === "application/pdf") {
    logger.log("Converting PDF to image for OCR...");
    imageBuffer = await convertPdfToImage(fileBuffer);
  } else if (mimeType.startsWith("image/")) {
    imageBuffer = fileBuffer;
  } else {
    throw new Error(
      `Unsupported file format: ${mimeType}. Supported formats: PNG, JPEG, GIF, WebP, PDF`,
    );
  }

  // Preprocess for better OCR accuracy
  logger.log("Preprocessing image for OCR...");
  const processedBuffer = await preprocessImage(imageBuffer);

  // Perform OCR
  logger.log("Running OCR...");
  const extractedText = await performOcr(processedBuffer);

  if (!extractedText || extractedText.trim().length === 0) {
    throw new Error(
      "No text could be extracted from the document. Please ensure the image/PDF contains readable text.",
    );
  }

  logger.log(`OCR extracted ${extractedText.length} characters`);
  return extractedText;
}

/**
 * Extract structured data using text-based AI (much cheaper than vision models)
 */
async function extractWithAi(
  text: string,
  options: ExtractionOptions,
): Promise<ExtractionResult> {
  const client = getGroqClient();
  if (!client) {
    throw new Error("GROQ_API_KEY is not set. Cannot process document.");
  }

  const productPrompt = `You are an expert data extraction assistant. I have extracted text from a document using OCR.

OCR EXTRACTED TEXT:
"""
${text}
"""

Analyze this text and extract product information. Return ONLY a valid JSON object with these fields:
- name: Product name/title (string, required)
- description: Product description or details (string)
- unitPrice: Price per unit as number (no currency symbols)
- quantity: Stock quantity as number
- cost: Cost price as number
- currency: Currency code like TND, USD, EUR

Rules:
- If multiple products are mentioned, extract the main one
- Convert prices to numbers (remove currency symbols)
- Use null for missing fields except name which is required
- Respond with ONLY the JSON, no markdown or explanations

Example response:
{
  "type": "product",
  "name": "Wireless Mouse",
  "description": "Bluetooth wireless mouse with USB receiver",
  "unitPrice": 49.99,
  "quantity": 150,
  "cost": 25.00,
  "currency": "TND"
}`;

  const invoicePrompt = `You are an expert data extraction assistant. I have extracted text from a document using OCR.

OCR EXTRACTED TEXT:
"""
${text}
"""

Analyze this text and extract invoice information. Return ONLY a valid JSON object with these fields:
- invoiceNumber: The invoice number/ID (string)
- recipientName: Name of the recipient/bill to (string)
- recipientEmail: Email address of recipient (string)
- issuedDate: Issue date in ISO format YYYY-MM-DD if possible
- dueDate: Due date in ISO format YYYY-MM-DD if possible
- totalAmount: Total amount as number (no currency symbols)
- currency: Currency code like TND, USD, EUR
- description: Invoice description or notes (string)
- paymentTerms: Payment terms text (string)
- lineItems: Array of items, each with:
  - productName: Name of product/service (string)
  - description: Item description (string)
  - quantity: Number as integer
  - unitPrice: Price per unit as number

Rules:
- Extract all line items visible in the invoice
- Convert prices to numbers (remove currency symbols)
- Parse dates to YYYY-MM-DD format if possible
- Use null for missing fields
- Respond with ONLY the JSON, no markdown or explanations

Example response:
{
  "type": "invoice",
  "invoiceNumber": "INV-2024-001",
  "recipientName": "ABC Company",
  "recipientEmail": "contact@abc.com",
  "issuedDate": "2024-01-15",
  "dueDate": "2024-02-15",
  "totalAmount": 1250.00,
  "currency": "TND",
  "description": "Consulting services",
  "lineItems": [
    {
      "productName": "Web Development",
      "description": "Frontend development",
      "quantity": 10,
      "unitPrice": 125.00
    }
  ]
}`;

  const prompt =
    options.documentType === "product" ? productPrompt : invoicePrompt;
  const model = "llama-3.1-8b-instant"; // Fast, cheap text model

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30_000);

    const res = await client.chat.completions.create(
      {
        model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.1,
        max_tokens: 2048,
        response_format: { type: "json_object" },
      },
      { signal: controller.signal },
    );

    clearTimeout(timeoutId);

    const content = res.choices[0]?.message?.content;
    if (!content) {
      throw new Error("AI returned empty response");
    }

    // Parse the JSON response safely
    const parsedUnknown: unknown = JSON.parse(content);
    if (typeof parsedUnknown !== "object" || parsedUnknown === null) {
      throw new Error("AI returned invalid JSON object");
    }
    const parsed = parsedUnknown as ExtractionResult;
    logger.log(
      `Successfully extracted ${options.documentType} data using text-based AI`,
    );

    return parsed;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("AI extraction timed out after 30 seconds");
    }
    throw error;
  }
}

/**
 * Extract structured data from an image or PDF document using OCR + AI
 * This approach avoids vision model rate limits by using local OCR first
 */
export async function extractFromDocument(
  fileBuffer: Buffer,
  filename: string,
  options: ExtractionOptions,
): Promise<ExtractionResult | null> {
  try {
    // Step 1: Extract text using OCR (local processing)
    const extractedText = await extractTextFromDocument(fileBuffer, filename);

    // Step 2: Send extracted text to AI (cheap text model, not vision)
    const result = await extractWithAi(extractedText, options);

    return result;
  } catch (error) {
    logger.error("Document extraction failed", error as Error);
    throw error;
  }
}

export type {
  ExtractionResult,
  ProductExtractionResult,
  InvoiceExtractionResult,
};
