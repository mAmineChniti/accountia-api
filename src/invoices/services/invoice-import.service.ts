import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { parse as csvParse } from 'csv-parse/sync';
import * as XLSX from 'xlsx';
import { InvoiceIssuanceService } from './invoice-issuance.service';
import {
  ImportedInvoiceResultDto,
  BulkImportInvoicesResponseDto,
} from '@/invoices/dto/invoice-import.dto';
import {
  CreateInvoiceDto,
  CreateInvoiceRecipientDto,
} from '@/invoices/dto/invoice.dto';
import { InvoiceRecipientType } from '@/invoices/enums/invoice-recipient.enum';
import { fixStructureWithAi } from '@/common/utils/ai-structure-fixer.util';
import { parseFile as commonParseFile } from '@/common/utils/file-parser.util';
import { ProductsService } from '@/products/products.service';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection, Model } from 'mongoose';
import { ObjectId } from 'mongodb';
import { Product, ProductSchema } from '@/products/schemas/product.schema';

/**
 * Service for bulk importing invoices from CSV or Excel files
 *
 * Supported formats:
 * - CSV: Standard comma-separated values
 * - Excel: .xlsx files (single sheet)
 *
 * Features:
 * - Flexible data format (comma-separated fields or JSON arrays)
 * - Partial failure handling (continue on individual errors)
 * - Comprehensive validation and error reporting
 * - Support for multiple recipient types (platform business, individual, external)
 */
interface FileUpload {
  originalname: string;
  buffer: Buffer;
}

@Injectable()
export class InvoiceImportService {
  private readonly logger = new Logger(InvoiceImportService.name);

  constructor(
    private readonly issuanceService: InvoiceIssuanceService,
    private readonly productsService: ProductsService,
    @InjectConnection() private readonly connection: Connection
  ) {}

  /**
   * Parse file and import invoices in bulk
   * Supports both CSV and Excel (.xlsx) formats
   *
   * @param file - File buffer and metadata
   * @param businessId - Business importing the invoices
   * @param databaseName - Tenant database name
   * @param userId - User performing the import
   * @returns Import results with statistics
   */
  async importInvoicesFromFile(
    file: FileUpload,
    businessId: string,
    databaseName: string,
    userId: string
  ): Promise<BulkImportInvoicesResponseDto> {
    const startTime = Date.now();
    const generalErrors: string[] = [];
    const results: ImportedInvoiceResultDto[] = [];

    try {
      // Determine file type and parse
      const records = this.parseFile(file);

      if (records.length === 0) {
        throw new BadRequestException(
          'File is empty or contains no valid records'
        );
      }

      this.logger.debug(`Parsed ${records.length} records from file`);

      // Validate records
      const validationErrors = this.validateRecords(records);
      if (validationErrors.length > 0) {
        generalErrors.push(...validationErrors);
      }

      // Process each record
      for (const [i, record] of records.entries()) {
        try {
          const result = await this.processInvoiceRecord(
            record,
            businessId,
            databaseName,
            userId,
            i + 1 // Row number (1-indexed, accounting for header)
          );
          results.push(result);
        } catch (error) {
          const invoiceNumber =
            (record.invoiceNumber as string) || `Row ${i + 2}`;
          const errorRecord: ImportedInvoiceResultDto = {
            invoiceNumber,
            status: 'error',
            message: error instanceof Error ? error.message : 'Unknown error',
          };
          results.push(errorRecord);
          this.logger.warn(`Failed to import invoice row ${i + 2}:`, error);
        }
      }

      // Calculate statistics
      const successCount = results.filter((r) => r.status === 'success').length;
      const failedCount = results.filter((r) => r.status === 'error').length;
      const warningCount = results.filter((r) => r.status === 'warning').length;
      const processingTimeMs = Date.now() - startTime;

      const response: BulkImportInvoicesResponseDto = {
        totalRecords: records.length,
        successCount,
        failedCount,
        warningCount,
        results,
        generalErrors: generalErrors.length > 0 ? generalErrors : undefined,
        importStartedAt: new Date(startTime).toISOString(),
        importCompletedAt: new Date().toISOString(),
        processingTimeMs,
      };

      this.logger.log(
        `Import completed: ${successCount} succeeded, ${failedCount} failed, ` +
          `${warningCount} warnings in ${processingTimeMs}ms`
      );

      return response;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'File processing failed';
      this.logger.error(`Import failed: ${errorMessage}`, error);
      throw new BadRequestException(`File import failed: ${errorMessage}`);
    }
  }

  /**
   * Import invoices with AI Smart Structural Correction
   */
  async importInvoicesSmart(
    file: FileUpload,
    businessId: string,
    databaseName: string,
    userId: string
  ): Promise<BulkImportInvoicesResponseDto> {
    const startTime = Date.now();
    try {
      // 1. Raw parse
      const rawRecords = await commonParseFile(file.buffer, file.originalname);

      if (rawRecords.length === 0) {
        throw new BadRequestException('File is empty or invalid.');
      }

      // 2. Use AI to fix structure
      const schema = {
        targetKeys: [
          'invoiceNumber',
          'recipientType',
          'recipientPlatformId',
          'recipientEmail',
          'recipientDisplayName',
          'productIds',
          'productNames',
          'quantities',
          'unitPrices',
          'issuedDate',
          'dueDate',
          'description',
          'paymentTerms',
          'currency',
        ],
        description:
          'Bulk invoices for a business to import. Multiple products can be separated by pipes (|) in old file columns.',
      };

      this.logger.log(
        `Starting AI structural analysis for ${file.originalname}`
      );
      const normalizedRecords = await fixStructureWithAi(
        rawRecords,
        schema,
        this.logger
      );

      // 3. Process records manually to ensure they are parsed as intended by importInvoicesFromFile
      // But we can actually just call a modified version of importInvoicesFromFile or reuse its logic.
      // Since importInvoicesFromFile parses the file again, we should avoid that.

      // Let's create a specialized processor for normalized records.
      return this.processNormalizedInvoices(
        normalizedRecords,
        businessId,
        databaseName,
        userId,
        startTime
      );
    } catch (error) {
      if (error instanceof BadRequestException) throw error;
      this.logger.error('Smart Invoice Import failed:', error);
      throw new BadRequestException(
        `L'IA n'a pas pu traiter ce fichier de factures : ${error.message}`
      );
    }
  }

  private async processNormalizedInvoices(
    records: Record<string, any>[],
    businessId: string,
    databaseName: string,
    userId: string,
    startTime: number
  ): Promise<BulkImportInvoicesResponseDto> {
    const results: ImportedInvoiceResultDto[] = [];
    const generalErrors: string[] = [];

    for (const [i, record] of records.entries()) {
      try {
        const result = await this.processInvoiceRecord(
          record,
          businessId,
          databaseName,
          userId,
          i + 1
        );
        results.push(result);
      } catch (error) {
        results.push({
          invoiceNumber: (record.invoiceNumber as string) || `Row ${i + 1}`,
          status: 'error',
          message: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }

    const successCount = results.filter((r) => r.status === 'success').length;
    const failedCount = results.filter((r) => r.status === 'error').length;
    const warningCount = results.filter((r) => r.status === 'warning').length;

    return {
      totalRecords: records.length,
      successCount,
      failedCount,
      warningCount,
      results,
      importStartedAt: new Date(startTime).toISOString(),
      importCompletedAt: new Date().toISOString(),
      processingTimeMs: Date.now() - startTime,
    };
  }

  /**
   * Parse CSV or Excel file
   */
  private parseFile(file: FileUpload): Record<string, unknown>[] {
    const filename = file.originalname.toLowerCase();

    if (filename.endsWith('.csv')) {
      return this.parseCSV(file.buffer);
    } else if (filename.endsWith('.xlsx')) {
      return this.parseExcel(file.buffer);
    } else {
      throw new BadRequestException(
        'Unsupported file format. Please upload a CSV or XLSX file.'
      );
    }
  }

  /**
   * Parse CSV file
   */
  private parseCSV(buffer: Buffer): Record<string, unknown>[] {
    try {
      const csvData = buffer.toString('utf8');
      const records = csvParse(csvData, {
        columns: true, // Use first row as column headers
        skip_empty_lines: true,
        trim: true,
        cast: false, // Keep all values as strings initially
      });

      return records as Record<string, unknown>[];
    } catch (error) {
      throw new BadRequestException(
        `CSV parsing failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Parse Excel file (.xlsx)
   */
  private parseExcel(buffer: Buffer): Record<string, unknown>[] {
    try {
      const workbook = XLSX.read(buffer, { type: 'buffer', cellDates: true });

      if (workbook.SheetNames.length === 0) {
        throw new BadRequestException('Excel file contains no sheets');
      }

      // Use first sheet
      const sheetName = workbook.SheetNames[0];
      const worksheet = workbook.Sheets[sheetName];

      // Convert to JSON
      const records =
        XLSX.utils.sheet_to_json<Record<string, unknown>>(worksheet);

      this.logger.debug(
        `Parsed ${records.length} records from Excel sheet "${sheetName}"`
      );

      return records;
    } catch (error) {
      if (error instanceof BadRequestException) throw error;
      throw new BadRequestException(
        `Excel parsing failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Validate all records before processing
   */
  private validateRecords(records: Record<string, unknown>[]): string[] {
    const errors: string[] = [];

    if (records.length === 0) {
      errors.push('No records found in file');
      return errors;
    }

    // Check that all required columns exist
    const firstRecord = records[0];
    const requiredFields = ['recipientType', 'issuedDate', 'dueDate'];

    for (const field of requiredFields) {
      if (!(field in firstRecord)) {
        errors.push(
          `Colonne obligatoire manquante : "${field}". Les colonnes requises sont : ${requiredFields.join(', ')}. Vérifiez que vous utilisez le bon fichier pour l'importation de factures.`
        );
      }
    }

    return errors;
  }

  /**
   * Process a single invoice record from import
   */
  private async processInvoiceRecord(
    record: Record<string, unknown>,
    businessId: string,
    databaseName: string,
    userId: string,
    rowNumber: number
  ): Promise<ImportedInvoiceResultDto> {
    const invoiceNumber =
      String((record.invoiceNumber as string) ?? '').trim() || undefined;

    // Parse and validate recipient
    const recipientType = String((record.recipientType as string) ?? '').trim();
    if (
      !Object.values(InvoiceRecipientType).includes(
        recipientType as InvoiceRecipientType
      )
    ) {
      throw new Error(
        `Row ${rowNumber}: Invalid recipientType "${recipientType}". ` +
          `Must be one of: ${Object.values(InvoiceRecipientType).join(', ')}`
      );
    }

    // Parse recipient details
    const recipient: CreateInvoiceRecipientDto = {
      type: recipientType as InvoiceRecipientType,
      platformId: record.recipientPlatformId
        ? String((record.recipientPlatformId as string) ?? '').trim()
        : undefined,
      email: record.recipientEmail
        ? String((record.recipientEmail as string) ?? '').trim()
        : undefined,
      displayName: record.recipientDisplayName
        ? String((record.recipientDisplayName as string) ?? '').trim()
        : undefined,
    };

    // Validate recipient based on type
    if (
      (recipientType as unknown as InvoiceRecipientType) ===
        InvoiceRecipientType.PLATFORM_BUSINESS &&
      !recipient.platformId
    ) {
      throw new Error(
        `Row ${rowNumber}: recipientPlatformId is required for PLATFORM_BUSINESS`
      );
    }

    if (
      (recipientType as unknown as InvoiceRecipientType) ===
        InvoiceRecipientType.PLATFORM_INDIVIDUAL &&
      !recipient.email
    ) {
      throw new Error(
        `Row ${rowNumber}: recipientEmail is required for PLATFORM_INDIVIDUAL`
      );
    }

    if (
      (recipientType as unknown as InvoiceRecipientType) ===
      InvoiceRecipientType.EXTERNAL
    ) {
      if (!recipient.email) {
        throw new Error(
          `Row ${rowNumber}: recipientEmail is required for EXTERNAL recipients`
        );
      }
      if (!recipient.displayName) {
        throw new Error(
          `Row ${rowNumber}: recipientDisplayName is required for EXTERNAL recipients`
        );
      }
    }

    // Parse line items
    const lineItems = this.parseLineItems(record, rowNumber);
    if (lineItems.length === 0) {
      throw new Error(
        `Ligne ${rowNumber}: Aucun produit ou service valide trouvé (Vérifiez les colonnes productNames, quantities, unitPrices)`
      );
    }

    // Parse dates
    const issuedDate = this.parseDate(
      record.issuedDate,
      'issuedDate',
      rowNumber
    );
    const dueDate = this.parseDate(record.dueDate, 'dueDate', rowNumber);

    // ✅ RESOLVE PRODUCTS (Find or Create)
    // This allows importing invoices even if products use codes or haven't been created yet.
    await this.resolveLineItems(
      businessId,
      databaseName,
      lineItems,
      (record.currency as string) || 'TND'
    );

    if (dueDate < issuedDate) {
      throw new Error(
        `Row ${rowNumber}: dueDate must be after or equal to issuedDate`
      );
    }

    // Create invoice DTO
    const createInvoiceDto: CreateInvoiceDto = {
      ...(invoiceNumber && { invoiceNumber }),
      recipient,
      lineItems,
      issuedDate,
      dueDate,
      description: record.description
        ? String((record.description as string) ?? '').trim()
        : undefined,
      paymentTerms: record.paymentTerms
        ? String((record.paymentTerms as string) ?? '').trim()
        : undefined,
      currency: record.currency
        ? String((record.currency as string) ?? '').trim()
        : 'TND',
    };

    // ✅ SMART UPSERT/RE-IMPORT LOGIC
    // If an invoice with this number already exists and is a DRAFT, we "clean re-import" it:
    // 1. Restore reserved inventory from the old invoice.
    // 2. Delete the old invoice.
    // 3. Continue to standard creation (which will reserve inventory correctly).
    if (invoiceNumber) {
      const invoiceModel =
        this.issuanceService.getTenantInvoiceModel(databaseName);
      const existingInvoice = await invoiceModel
        .findOne({
          issuerBusinessId: businessId,
          invoiceNumber,
        })
        .exec();

      if (existingInvoice) {
        if (existingInvoice.status === 'DRAFT') {
          this.logger.debug(`Re-importing draft invoice: ${invoiceNumber}`);
          // Restore inventory first
          await this.issuanceService.restoreReservedInventoryForInvoice(
            existingInvoice,
            databaseName
          );
          // Delete old invoice
          await invoiceModel.deleteOne({ _id: existingInvoice._id });
        } else {
          // If not DRAFT, we skip with warning as before (don't overwrite PAID/ISSUED invoices)
          return {
            invoiceNumber,
            status: 'warning',
            message: `La facture ${invoiceNumber} existe déjà (${existingInvoice.status}) et ne peut pas être écrasée.`,
          };
        }
      }
    }

    // Create invoice
    const createdInvoice = await this.issuanceService.createDraftInvoice(
      businessId,
      databaseName,
      createInvoiceDto,
      userId
    );

    // Calculate total for response
    const totalAmount = lineItems.reduce(
      (sum, item) => sum + item.quantity * item.unitPrice,
      0
    );

    const result: ImportedInvoiceResultDto = {
      invoiceNumber,
      invoiceId: createdInvoice.id,
      status: 'success',
      message: 'Invoice created successfully',
      lineItemsCount: lineItems.length,
      totalAmount,
    };

    this.logger.debug(
      `Successfully imported invoice ${invoiceNumber} (ID: ${createdInvoice.id})`
    );

    return result;
  }

  /**
   * Parse line items from various formats
   * Supports:
   * 1. JSON string in lineItemsJson field
   * 2. Comma-separated values in productIds, productNames, quantities, unitPrices
   */
  private parseLineItems(
    record: Record<string, unknown>,
    rowNumber: number
  ): Array<{
    productId: string;
    productName: string;
    quantity: number;
    unitPrice: number;
    description?: string;
  }> {
    // Try JSON format first
    if (record.lineItemsJson) {
      try {
        const parsed: unknown = JSON.parse(
          String((record.lineItemsJson as string) ?? '')
        );
        if (Array.isArray(parsed)) {
          return (
            parsed as Array<{
              productId: string;
              productName: string;
              quantity: number;
              unitPrice: number;
              description?: string;
            }>
          ).map((item, idx) => {
            this.validateLineItem(item, rowNumber, idx);
            return item;
          });
        }
      } catch {
        throw new Error(
          `Row ${rowNumber}: Invalid lineItemsJson format. Must be valid JSON.`
        );
      }
    }

    // Try multi-delimited format (supports both pipe and comma)
    if (record.productIds && record.quantities && record.unitPrices) {
      // Helper function to split on either pipe or comma delimiter
      const smartSplit = (value: string): string[] => {
        // Split on either pipe or comma, trim whitespace
        return value
          .split(/[,|]/)
          .map((x) => x.trim())
          .filter((x) => x.length > 0);
      };

      const productIds = smartSplit(
        String((record.productIds as string) ?? '')
      );
      const productNames = record.productNames
        ? smartSplit(String((record.productNames as string) ?? ''))
        : productIds; // Default to IDs if names not provided
      const quantities = smartSplit(
        String((record.quantities as string) ?? '')
      ).map((x) => {
        const num = Number(x);
        if (Number.isNaN(num) || num < 0) {
          throw new Error(`Row ${rowNumber}: Invalid quantity "${x}"`);
        }
        return num;
      });
      const unitPrices = smartSplit(
        String((record.unitPrices as string) ?? '')
      ).map((x) => {
        const num = Number(x);
        if (Number.isNaN(num) || num < 0) {
          throw new Error(`Row ${rowNumber}: Invalid unitPrice "${x}"`);
        }
        return num;
      });

      // Validate array lengths match
      const maxLen = Math.max(
        productIds.length,
        quantities.length,
        unitPrices.length
      );
      if (
        productIds.length !== maxLen ||
        quantities.length !== maxLen ||
        unitPrices.length !== maxLen
      ) {
        throw new Error(
          `Row ${rowNumber}: productIds, quantities, and unitPrices must have the same number of items`
        );
      }

      return productIds.map((productId, idx) => ({
        productId,
        productName: productNames[idx] || productId,
        quantity: quantities[idx],
        unitPrice: unitPrices[idx],
      }));
    }

    throw new Error(
      `Row ${rowNumber}: Must provide either lineItemsJson or productIds+quantities+unitPrices`
    );
  }

  /**
   * Resolve product IDs by searching for existing ones by name or creating missing ones.
   */
  private async resolveLineItems(
    businessId: string,
    databaseName: string,
    lineItems: Array<any>,
    currency: string
  ): Promise<void> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    let productModel: Model<Product>;
    try {
      productModel = tenantDb.model<Product>(Product.name);
    } catch {
      productModel = tenantDb.model<Product>(Product.name, ProductSchema);
    }

    for (const item of lineItems) {
      const originalId = String(item.productId || '').trim();
      const productName = String(
        item.productName || item.productId || ''
      ).trim();

      // 1. If it's a valid ObjectId, check if it exists
      if (ObjectId.isValid(originalId)) {
        const existing = await productModel.findById(originalId).lean();
        if (existing) continue; // Already a valid resolved product
      }

      // 2. Not a valid ID or product not found, search by NAME
      let product = await productModel.findOne({
        businessId,
        name: { $regex: new RegExp(`^${productName}$`, 'i') },
      });

      // 3. If not found by name, AUTO-CREATE it
      if (!product) {
        this.logger.log(
          `[Import] Product "${productName}" not found. Creating on the fly...`
        );
        product = await productModel.create({
          businessId,
          name: productName,
          description: `Importé via facture (Réf: ${originalId})`,
          unitPrice: item.unitPrice || 0,
          cost: 0,
          quantity: item.quantity, // Give it initial quantity so reservation passes
          currency: currency || 'TND',
        });
      }

      // 4. Update the line item with the real MongoDB ObjectID
      item.productId = product._id.toString();
      item.productName = product.name; // Use the official name
    }
  }

  /**
   * Validate a single line item
   */
  private validateLineItem(
    item: unknown,
    rowNumber: number,
    itemIndex: number
  ): void {
    if (!item || typeof item !== 'object') {
      throw new Error(
        `Row ${rowNumber}: Line item ${itemIndex} is not an object`
      );
    }

    const lineItem = item as Record<string, unknown>;

    if (!lineItem.productId || typeof lineItem.productId !== 'string') {
      throw new Error(
        `Row ${rowNumber}: Line item ${itemIndex} must have a valid productId (string)`
      );
    }

    if (!lineItem.productName || typeof lineItem.productName !== 'string') {
      throw new Error(
        `Row ${rowNumber}: Line item ${itemIndex} must have a valid productName (string)`
      );
    }

    const quantity = Number(lineItem.quantity);
    if (Number.isNaN(quantity) || quantity < 0) {
      throw new Error(
        `Row ${rowNumber}: Line item ${itemIndex} has invalid quantity`
      );
    }

    const unitPrice = Number(lineItem.unitPrice);
    if (Number.isNaN(unitPrice) || unitPrice < 0) {
      throw new Error(
        `Row ${rowNumber}: Line item ${itemIndex} has invalid unitPrice`
      );
    }
  }

  /**
   * Parse date from various formats
   */
  private parseDate(
    dateValue: unknown,
    fieldName: string,
    rowNumber: number
  ): Date {
    if (!dateValue) {
      throw new Error(`Row ${rowNumber}: ${fieldName} is required`);
    }

    let date: Date;

    if (dateValue instanceof Date) {
      date = dateValue;
    } else if (typeof dateValue === 'number') {
      // With cellDates: true, numbers should not appear - they should be Date objects
      throw new TypeError(
        `Row ${rowNumber}: Invalid ${fieldName} format. Expected a date object or ISO string`
      );
    } else if (typeof dateValue === 'string') {
      // Try to parse string
      date = new Date(dateValue);
      if (Number.isNaN(date.getTime())) {
        throw new TypeError(
          `Row ${rowNumber}: Invalid ${fieldName} format "${dateValue}". ` +
            `Use ISO format (YYYY-MM-DD) or timestamp`
        );
      }
    } else {
      throw new TypeError(`Row ${rowNumber}: Invalid ${fieldName} type`);
    }

    if (Number.isNaN(date.getTime())) {
      throw new TypeError(`Row ${rowNumber}: Invalid ${fieldName}`);
    }

    return date;
  }

  /**
   * Get import template example
   */
  getImportTemplate(): {
    csvExample: string;
    csvColumns: string[];
    recipientTypes: InvoiceRecipientType[];
    notes: string;
  } {
    const csvColumns = [
      'invoiceNumber',
      'recipientType',
      'recipientPlatformId',
      'recipientEmail',
      'recipientDisplayName',
      'productIds',
      'productNames',
      'quantities',
      'unitPrices',
      'issuedDate',
      'dueDate',
      'description',
      'paymentTerms',
      'currency',
    ];

    const csvExample = `invoiceNumber,recipientType,recipientEmail,recipientDisplayName,productIds,productNames,quantities,unitPrices,issuedDate,dueDate,description,paymentTerms,currency
INV-2024-001,EXTERNAL,john@example.com,John Doe,PROD-001,Website Service,1,5000.00,2024-01-15,2024-02-15,Website development services,NET30,TND
,EXTERNAL,vendor@example.com,Vendor Inc,PROD-002|PROD-003,Consulting|Support,2|1,2000.00|1500.00,2024-01-20,2024-02-20,Auto-generated invoice number,NET45,TND`;

    const recipientTypes = Object.values(InvoiceRecipientType);

    const notes =
      'Format: Use comma-separated values. Dates must be in YYYY-MM-DD format. ' +
      'invoiceNumber is optional - if not provided, it will be auto-generated in format INV-{YYYYMMDD}-{randomString}. ' +
      'For PLATFORM_BUSINESS, provide recipientPlatformId. ' +
      'For EXTERNAL, provide recipientEmail and recipientDisplayName. ' +
      'Multiple line items can be separated by pipe (|) character.';

    return {
      csvExample,
      csvColumns,
      recipientTypes,
      notes,
    };
  }

  /**
   * AI Extraction: Read CSV/Excel and let Gemini return a generic prefilled form object
   */
  async extractDraftInvoiceWithAi(file: FileUpload): Promise<any> {
    try {
      const records = this.parseFile(file);
      if (records.length === 0) {
        throw new BadRequestException('File is empty or invalid.');
      }

      // Convert parsed records to JSON string to feed into Gemini
      const fileText = JSON.stringify(records, null, 2);

      const prompt = `You are an AI accountant. I will provide you with raw JSON extracted from a CSV/Excel file uploaded by the user representing ONE invoice or draft invoice.
Your task is to parse this data and return a JSON object. Give me ONLY valid JSON, do NOT include markdown syntax like \`\`\`json.

The JSON should precisely follow this structure:
{
  "recipient": {
    "type": "EXTERNAL",
    "email": "client_email_if_found@example.com",
    "displayName": "Client Name or Company"
  },
  "lineItems": [
    {
      "productId": "",
      "productName": "Item name",
      "quantity": 1,
      "unitPrice": 100,
      "description": "Item description if found"
    }
  ],
  "issuedDate": "YYYY-MM-DD",
  "dueDate": "YYYY-MM-DD",
  "currency": "TND",
  "description": "Optional notes if any found"
}

Data from file:
${fileText}
`;

      const aiResponse = await this.callAi(prompt);

      try {
        const cleaned = aiResponse
          .replaceAll(/```json/gi, '')
          .replaceAll('```', '')
          .trim();
        return JSON.parse(cleaned);
      } catch {
        this.logger.error('Failed to parse AI JSON response', aiResponse);
        throw new BadRequestException(
          "L'IA n'a pas pu formater correctement cette facture."
        );
      }
    } catch (error) {
      if (error instanceof BadRequestException) throw error;
      this.logger.error('Failed to extract invoice via AI', error);
      throw new BadRequestException('Erreur lors du traitement du fichier.');
    }
  }

  private async callAi(prompt: string): Promise<string> {
    let geminiKey = process.env.GEMINI_API_KEY;
    if (geminiKey) geminiKey = geminiKey.replaceAll('"', '');

    if (!geminiKey || geminiKey.length < 20) {
      throw new BadRequestException('Configuration API Gemini manquante.');
    }

    // Try models in order (verified from ListModels API)
    // gemini-2.0-flash-lite has much higher free tier rate limits
    const models = [
      'gemini-2.0-flash-lite',
      'gemini-2.0-flash-001',
      'gemini-2.0-flash',
      'gemini-flash-lite-latest',
    ];

    for (const model of models) {
      try {
        this.logger.log(`[Invoice AI] Trying model: ${model}`);
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: prompt }] }],
            }),
          }
        );

        if (response.ok) {
          const data = await response.json();
          const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) {
            this.logger.log(`[Invoice AI] Success with model: ${model}`);
            return text;
          }
        } else {
          const errText = await response.text();
          this.logger.warn(
            `[Invoice AI] Model ${model} failed ${response.status}: ${errText.slice(0, 200)}`
          );
          // Continue to next model
        }
      } catch (error) {
        this.logger.error(`[Invoice AI] Network error for ${model}:`, error);
      }
    }

    throw new BadRequestException(
      'Gemini indisponible. Veuillez réessayer dans quelques secondes.'
    );
  }
}
