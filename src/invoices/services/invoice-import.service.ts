import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { parse as csvParse } from 'csv-parse/sync';
import * as XLSX from 'xlsx';
import { Connection } from 'mongoose';
import { ObjectId } from 'mongodb';
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
            itemNumber: i + 2,
            invoiceNumber,
            success: false,
            errors: [error instanceof Error ? error.message : 'Unknown error'],
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
        bom: true,
        cast: false, // Keep all values as strings initially
      });

      return (records as Record<string, unknown>[]).map((record) =>
        this.normalizeRecordKeys(record)
      );
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

      return records.map((record) => this.normalizeRecordKeys(record));
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
          `Missing required column: "${field}". Required columns: ${requiredFields.join(', ')}`
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
    const lineItems = await this.parseLineItems(
      record,
      businessId,
      databaseName,
      rowNumber
    );
    if (lineItems.length === 0) {
      throw new Error(`Row ${rowNumber}: No valid line items found`);
    }

    // Parse dates
    const issuedDate = this.parseDate(
      record.issuedDate,
      'issuedDate',
      rowNumber
    );
    const dueDate = this.parseDate(record.dueDate, 'dueDate', rowNumber);

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
      itemNumber: rowNumber,
      invoiceNumber,
      invoiceId: createdInvoice.id,
      success: true,
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
    businessId: string,
    databaseName: string,
    rowNumber: number
  ): Promise<
    Array<{
      productId: string;
      productName: string;
      quantity: number;
      unitPrice: number;
      description?: string;
    }>
  > {
    const parsedItems = this.parseLineItemsRaw(record, rowNumber);
    return this.resolveLineItemProductReferences(
      parsedItems,
      businessId,
      databaseName,
      rowNumber
    );
  }

  private parseLineItemsRaw(
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

  private async resolveLineItemProductReferences(
    items: Array<{
      productId: string;
      productName: string;
      quantity: number;
      unitPrice: number;
      description?: string;
    }>,
    businessId: string,
    databaseName: string,
    rowNumber: number
  ): Promise<
    Array<{
      productId: string;
      productName: string;
      quantity: number;
      unitPrice: number;
      description?: string;
    }>
  > {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    const productsCollection = tenantDb.collection('products');
    const businessObjectId = ObjectId.isValid(businessId)
      ? new ObjectId(businessId)
      : undefined;

    const cache = new Map<string, string>();

    const resolvedItems = await Promise.all(
      items.map(async (item, idx) => {
        const rawProductId = item.productId.trim();
        const businessFilter = businessObjectId
          ? { $or: [{ businessId: businessObjectId }, { businessId }] }
          : { businessId };

        if (ObjectId.isValid(rawProductId)) {
          const idMatch = await productsCollection.findOne(
            {
              ...businessFilter,
              _id: new ObjectId(rawProductId),
            },
            { projection: { _id: 1 } }
          );

          if (idMatch?._id) {
            return item;
          }
          // If the provided ObjectId exists in another tenant or no longer exists,
          // try resolving by product name within this business.
        }

        const normalizedName = item.productName.trim().toLowerCase();
        if (!normalizedName) {
          throw new Error(
            `Row ${rowNumber}: Line item ${idx + 1} has non-ObjectId productId and missing productName`
          );
        }

        const cachedId = cache.get(normalizedName);
        if (cachedId) {
          return { ...item, productId: cachedId };
        }

        const matchedProduct = await productsCollection.findOne(
          {
            ...businessFilter,
            name: {
              $regex: `^${this.escapeRegex(item.productName.trim())}$`,
              $options: 'i',
            },
          },
          { projection: { _id: 1 } }
        );

        if (!matchedProduct?._id) {
          throw new Error(
            `Row ${rowNumber}: Product reference "${item.productId}" not found. Use a valid product ObjectId or an existing product name in productNames.`
          );
        }

        const resolvedProductId = String(matchedProduct._id);
        cache.set(normalizedName, resolvedProductId);
        this.logger.debug(
          `Resolved import product reference "${item.productId}" to ${resolvedProductId} using name "${item.productName}"`
        );

        return {
          ...item,
          productId: resolvedProductId,
        };
      })
    );

    return resolvedItems;
  }

  private escapeRegex(value: string): string {
    return value.replaceAll(/[$()*+.?[\\\]^{|}]/g, String.raw`\$&`);
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
      // Support Excel serial date numbers for wider file compatibility.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
      const parsed = (XLSX as any).SSF.parse_date_code(dateValue) as {
        y: number;
        m: number;
        d: number;
        H: number;
        M: number;
        S: number;
      };
      if (!parsed) {
        throw new TypeError(
          `Row ${rowNumber}: Invalid ${fieldName} numeric format "${dateValue}"`
        );
      }
      date = new Date(
        parsed.y,
        Math.max(0, parsed.m - 1),
        parsed.d,
        parsed.H,
        parsed.M,
        parsed.S
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

  private normalizeRecordKeys(
    record: Record<string, unknown>
  ): Record<string, unknown> {
    const aliasMap: Record<string, string> = {
      invoicenumber: 'invoiceNumber',
      recipienttype: 'recipientType',
      issueddate: 'issuedDate',
      duedate: 'dueDate',
      recipientplatformid: 'recipientPlatformId',
      recipientplatfoormid: 'recipientPlatformId',
      recipientplatformld: 'recipientPlatformId',
      recipientemail: 'recipientEmail',
      recipienemail: 'recipientEmail',
      recipientdisplayname: 'recipientDisplayName',
      productids: 'productIds',
      productnames: 'productNames',
      quantities: 'quantities',
      unitprices: 'unitPrices',
      lineitemsjson: 'lineItemsJson',
      description: 'description',
      paymentterms: 'paymentTerms',
      currency: 'currency',
    };

    const normalizedRecord: Record<string, unknown> = {};

    for (const [rawKey, value] of Object.entries(record)) {
      const normalizedLookup = rawKey
        .replace(/^\uFEFF/, '')
        .replaceAll(/[^\dA-Za-z]/g, '')
        .toLowerCase();

      const canonicalKey = aliasMap[normalizedLookup] ?? rawKey.trim();
      normalizedRecord[canonicalKey] = value;
    }

    return normalizedRecord;
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
      'Multiple line items can be separated by pipe (|) character. ' +
      'productIds accepts either Mongo ObjectId values or legacy references; when legacy values are used, productNames must match existing tenant product names.';

    return {
      csvExample,
      csvColumns,
      recipientTypes,
      notes,
    };
  }
}
