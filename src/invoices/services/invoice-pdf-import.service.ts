/* eslint-disable unicorn/no-abusive-eslint-disable */
/* eslint-disable */
import {
  Injectable,
  Logger,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  InvoiceImportJob,
  ImportJobStatus,
} from '../schemas/invoice-import-job.schema';
import { InvoiceAiService, ExtractedInvoiceData } from './invoice-ai.service';
import { InvoiceIssuanceService } from './invoice-issuance.service';
import { InvoiceStatus } from '../enums/invoice-status.enum';
import { CreateInvoiceDto } from '../dto/invoice.dto';
import { InvoiceRecipientType } from '../enums/invoice-recipient.enum';

@Injectable()
export class InvoicePdfImportService {
  private readonly logger = new Logger(InvoicePdfImportService.name);
  private readonly uploadsDir = path.join(process.cwd(), 'uploads', 'invoices');

  constructor(
    @InjectModel(InvoiceImportJob.name)
    private importJobModel: Model<InvoiceImportJob>,
    private readonly aiService: InvoiceAiService,
    private readonly issuanceService: InvoiceIssuanceService
  ) {
    if (!fs.existsSync(this.uploadsDir)) {
      fs.mkdirSync(this.uploadsDir, { recursive: true });
    }
  }

  /**
   * Start a new PDF import job
   */
  async startImportJob(
    file: { originalname: string; buffer: Buffer },
    businessId: string,
    databaseName: string,
    userId: string
  ): Promise<{ jobId: string }> {
    this.logger.log(
      `[User ${userId}] Starting PDF import for Business ${businessId}. File: ${file.originalname}`
    );

    // 1. Save file to disk
    const filename = `${Date.now()}-${file.originalname}`;
    const filePath = path.join(this.uploadsDir, filename);
    fs.writeFileSync(filePath, file.buffer);

    // 2. Create job record
    const job = await this.importJobModel.create({
      businessId,
      userId,
      status: ImportJobStatus.PENDING,
      pdfFilePath: filePath,
      originalFilename: file.originalname,
    });

    this.logger.log(
      `[Job ${job.id}] Created job for User ${userId}. Filename: ${filename}`
    );

    // 3. Trigger processing in background (fire-and-forget)
    this.processJob(job.id, databaseName).catch((error) => {
      this.logger.error(
        `[Job ${job.id}] Background processing initialization failed: ${error.message}`,
        error.stack
      );
    });

    return { jobId: job.id };
  }

  /**
   * Get job status
   */
  async getJobStatus(
    jobId: string,
    businessId: string
  ): Promise<InvoiceImportJob> {
    // eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-require-imports, unicorn/prefer-module
    const { isValidObjectId } = require('mongoose');
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call
    if (!isValidObjectId(jobId)) {
      this.logger.warn(`Rejected invalid Job ID format: ${jobId}`);
      throw new BadRequestException('Invalid Job ID format');
    }

    const job = await this.importJobModel
      .findOne({
        _id: jobId,
        businessId: businessId.toString(),
      })
      .exec();

    if (!job) {
      this.logger.error(
        `Job not found. JobId: ${jobId}, BusinessId: ${businessId}. Possible reasons: Job deleted, wrong BusinessId, or record not created yet.`
      );
      throw new NotFoundException(
        `Job ${jobId} not found for Business ${businessId}`
      );
    }
    return job;
  }

  /**
   * Background processing logic
   */
  private async processJob(jobId: string, databaseName: string): Promise<void> {
    try {
      const job = await this.importJobModel.findById(jobId).exec();
      if (!job) {
        this.logger.error(
          `[Job ${jobId}] Could not find job record in background task.`
        );
        return;
      }

      this.logger.log(`[Job ${jobId}] Transitioning to PROCESSING state.`);
      await this.importJobModel.updateOne(
        { _id: jobId },
        { status: ImportJobStatus.PROCESSING }
      );

      // 1. OCR and AI Extraction
      const extractionResult = await this.aiService.processPdf(
        job.pdfFilePath,
        jobId
      );
      const {
        text: rawText,
        rawAiOutput,
        method: extractionMethod,
        structuredData,
      } = extractionResult;

      // 2. Data Validation & Confidence Scoring
      const { confidenceScore, isReliable } =
        this.evaluateExtraction(structuredData);

      // 3. Map to Invoice Model
      const createInvoiceDto = this.mapToCreateDto(structuredData);

      const status = isReliable
        ? InvoiceStatus.DRAFT
        : InvoiceStatus.PENDING_REVIEW;

      this.logger.log(
        `[Job ${jobId}] Extraction complete (Reliable: ${isReliable}, Score: ${confidenceScore}). Creating invoice...`
      );

      // 4. Create Invoice using Issuance Service
      const invoice = await this.issuanceService.createDraftInvoice(
        job.businessId,
        databaseName,
        createInvoiceDto,
        job.userId
      );

      // Update the invoice with extra fields
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
      const issuanceService = this.issuanceService as any;
      // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment
      const tenantInvoiceModel =
        issuanceService.getTenantInvoiceModel(databaseName);

      // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
      await tenantInvoiceModel.updateOne(
        { _id: invoice.id },
        {
          status,
          source: 'pdf',
          confidenceScore,
          pdfFilePath: job.pdfFilePath,
          extractionData: {
            rawText,
            rawAiOutput,
            extractionMethod,
            structuredData,
          },
        }
      );

      // 5. Complete Job
      await this.importJobModel.updateOne(
        { _id: jobId },
        {
          status: ImportJobStatus.COMPLETED,
          invoiceId: invoice.id,
          metadata: {
            confidenceScore,
            extractionMethod,
          },
        }
      );

      this.logger.log(
        `[Job ${jobId}] Job finished successfully. Invoice: ${invoice.id}`
      );
    } catch (error: unknown) {
      const err = error as Error;
      this.logger.error(
        `[Job ${jobId}] Processing failed: ${err.message}`,
        err.stack
      );
      await this.importJobModel
        .updateOne(
          { _id: jobId },
          {
            status: ImportJobStatus.FAILED,
            error: err.message ?? 'Unknown processing error',
          }
        )
        .catch((error_: unknown) => {
          const innerErr = error_ as Error;
          this.logger.error(
            `[Job ${jobId}] Failed to update status to FAILED: ${innerErr.message}`
          );
        });
    }
  }

  private evaluateExtraction(data: ExtractedInvoiceData): {
    confidenceScore: number;
    isReliable: boolean;
  } {
    let score = 100;
    const diagnostics: string[] = [];

    // Check mandatory fields
    if (!data.invoiceNumber) {
      score -= 20;
      diagnostics.push('Missing invoice number');
    }
    if (!data.vendorName) {
      score -= 15;
      diagnostics.push('Missing vendor name');
    }
    if (!data.totalAmount) {
      score -= 25;
      diagnostics.push('Missing total amount');
    }
    if (!data.lineItems || data.lineItems.length === 0) {
      score -= 20;
      diagnostics.push('No line items found');
    }

    // Backend validation of totals
    if (data.totalAmount && data.lineItems && data.lineItems.length > 0) {
      const computedSubtotal = data.lineItems.reduce(
        (sum, item) => sum + item.quantity * item.unitPrice,
        0
      );
      const tax = data.taxAmount ?? 0;
      const expectedTotal = computedSubtotal + tax;

      // Allow 0.1 variance for rounding
      if (Math.abs(expectedTotal - data.totalAmount) > 0.1) {
        score -= 30;
        diagnostics.push(
          `Total mismatch. Extracted: ${data.totalAmount}, Computed: ${expectedTotal}`
        );
      }
    }

    const isReliable = score >= 80;
    return { confidenceScore: Math.max(0, score), isReliable };
  }

  private mapToCreateDto(data: ExtractedInvoiceData): CreateInvoiceDto {
    return {
      invoiceNumber: data.invoiceNumber ?? undefined,
      recipient: {
        type: InvoiceRecipientType.EXTERNAL,
        displayName: data.vendorName ?? 'Extracted Vendor',
        email: 'pending-evaluation@example.com', // Placeholder, user will need to fix
      },
      issuedDate: data.issuedDate ? new Date(data.issuedDate) : new Date(),
      dueDate: data.dueDate
        ? new Date(data.dueDate)
        : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      currency: data.currency ?? 'TND',
      lineItems: (data.lineItems ?? []).map((item) => ({
        productId: 'UNKNOWN', // Placeholder or search logic
        productName: item.productName ?? 'Unknown Product',
        quantity: item.quantity ?? 1,
        unitPrice: item.unitPrice ?? 0,
        description: item.description,
      })),
      description: `AI Extracted Invoice from PDF. Vendor: ${data.vendorName ?? 'Unknown'}`,
    }; // Cast as DTO might have some validation rules we bypass here
  }
}
