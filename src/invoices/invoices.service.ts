/**
 * DEPRECATED SERVICE
 *
 * This service has been replaced by a new three-service architecture:
 * - InvoiceIssuanceService: Create, update, and manage invoices issued by your business
 * - InvoiceReceiptService: View and manage invoices received by your business
 * - RecipientResolutionService: Background identity resolution for recipients
 *
 * All methods in this service throw deprecation errors and are no longer used.
 * Please update your imports to use the new services from @/invoices/services.
 */

import type {
  CreateInvoiceDto,
  UpdateInvoiceDto,
  InvoiceResponseDto,
  InvoiceListResponseDto,
} from '@/invoices/dto/invoice.dto';

/**
 * @deprecated Use InvoiceIssuanceService, InvoiceReceiptService, or RecipientResolutionService instead
 */
export class InvoicesService {
  private throwDeprecated(method: string): never {
    throw new Error(
      `InvoicesService.${method}() is deprecated. Use the new three-service architecture instead: ` +
        `InvoiceIssuanceService, InvoiceReceiptService, or RecipientResolutionService from @/invoices/services`
    );
  }

  // Deprecated personal invoice methods
  createPersonalInvoice(
    _businessId: string,
    _dto: CreateInvoiceDto
  ): Promise<InvoiceResponseDto> {
    return this.throwDeprecated('createPersonalInvoice');
  }

  getPersonalInvoicesByBusiness(
    _businessId: string,
    _page?: number,
    _limit?: number
  ): Promise<InvoiceListResponseDto> {
    return this.throwDeprecated('getPersonalInvoicesByBusiness');
  }

  getPersonalInvoicesForUser(
    _clientUserId: string,
    _page?: number,
    _limit?: number
  ): Promise<InvoiceListResponseDto> {
    return this.throwDeprecated('getPersonalInvoicesForUser');
  }

  getPersonalInvoiceById(_invoiceId: string): Promise<InvoiceResponseDto> {
    return this.throwDeprecated('getPersonalInvoiceById');
  }

  updatePersonalInvoice(
    _invoiceId: string,
    _businessId: string,
    _dto: UpdateInvoiceDto
  ): Promise<InvoiceResponseDto> {
    return this.throwDeprecated('updatePersonalInvoice');
  }

  deletePersonalInvoice(
    _invoiceId: string,
    _businessId: string
  ): Promise<void> {
    return this.throwDeprecated('deletePersonalInvoice');
  }

  // Deprecated company invoice methods
  createCompanyInvoice(
    _businessId: string,
    _dto: CreateInvoiceDto
  ): Promise<InvoiceResponseDto> {
    return this.throwDeprecated('createCompanyInvoice');
  }

  getCompanyInvoicesByBusiness(
    _businessId: string,
    _page?: number,
    _limit?: number
  ): Promise<InvoiceListResponseDto> {
    return this.throwDeprecated('getCompanyInvoicesByBusiness');
  }

  getCompanyInvoicesForBusiness(
    _businessId: string,
    _page?: number,
    _limit?: number
  ): Promise<InvoiceListResponseDto> {
    return this.throwDeprecated('getCompanyInvoicesForBusiness');
  }

  getCompanyInvoicesReceivedByBusiness(
    _businessId: string,
    _page?: number,
    _limit?: number
  ): Promise<InvoiceListResponseDto> {
    return this.throwDeprecated('getCompanyInvoicesReceivedByBusiness');
  }

  getPersonalInvoicesReceivedByUser(
    _userId: string,
    _page?: number,
    _limit?: number
  ): Promise<InvoiceListResponseDto> {
    return this.throwDeprecated('getPersonalInvoicesReceivedByUser');
  }

  getCompanyInvoiceById(_invoiceId: string): Promise<InvoiceResponseDto> {
    return this.throwDeprecated('getCompanyInvoiceById');
  }

  updateCompanyInvoice(
    _invoiceId: string,
    _businessId: string,
    _dto: UpdateInvoiceDto
  ): Promise<InvoiceResponseDto> {
    return this.throwDeprecated('updateCompanyInvoice');
  }

  deleteCompanyInvoice(_invoiceId: string, _businessId: string): Promise<void> {
    return this.throwDeprecated('deleteCompanyInvoice');
  }

  // Deprecated import methods
  importPersonalInvoices(
    _businessId: string,
    _records: unknown[]
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    return this.throwDeprecated('importPersonalInvoices');
  }

  importCompanyInvoices(
    _businessId: string,
    _records: unknown[]
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    return this.throwDeprecated('importCompanyInvoices');
  }
}
