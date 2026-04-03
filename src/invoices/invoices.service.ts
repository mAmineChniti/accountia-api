import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { PersonalInvoice } from '@/invoices/schemas/personal-invoice.schema';
import { CompanyInvoice } from '@/invoices/schemas/company-invoice.schema';
import { Product } from '@/products/schemas/product.schema';
import {
  CreatePersonalInvoiceDto,
  CreateCompanyInvoiceDto,
  UpdateInvoiceDto,
  PersonalInvoiceResponseDto,
  CompanyInvoiceResponseDto,
  InvoiceListResponseDto,
} from '@/invoices/dto/invoice.dto';

@Injectable()
export class InvoicesService {
  constructor(
    @InjectModel(PersonalInvoice.name)
    private readonly personalInvoiceModel: Model<PersonalInvoice>,
    @InjectModel(CompanyInvoice.name)
    private readonly companyInvoiceModel: Model<CompanyInvoice>,
    @InjectModel(Product.name)
    private readonly productModel: Model<Product>
  ) {}

  /**
   * Create a personal invoice (issued to a client user)
   * Deducts quantity from product inventory
   */
  async createPersonalInvoice(
    businessId: string,
    dto: CreatePersonalInvoiceDto
  ): Promise<PersonalInvoiceResponseDto> {
    // Fetch product
    const product = await this.productModel.findById(dto.productId);
    if (!product) {
      throw new NotFoundException('Product not found');
    }

    // Check product belongs to business
    if (product.businessId.toString() !== businessId) {
      throw new ForbiddenException('Product does not belong to this business');
    }

    // Check sufficient quantity
    if (product.quantity < dto.quantity) {
      throw new BadRequestException('Insufficient product quantity');
    }

    // Calculate amount
    const amount = dto.quantity * product.unitPrice;

    // Create invoice
    const invoice = new this.personalInvoiceModel({
      businessId,
      clientUserId: dto.clientUserId,
      productId: dto.productId,
      quantity: dto.quantity,
      amount,
      issuedAt: new Date(),
      paid: false,
    });

    const savedInvoice = await invoice.save();

    // Deduct quantity from product
    await this.productModel.findByIdAndUpdate(
      dto.productId,
      { $inc: { quantity: -dto.quantity } },
      { new: true }
    );

    return this.formatPersonalInvoiceResponse(savedInvoice);
  }

  /**
   * Create a company invoice (issued to another business)
   * Deducts quantity from product inventory
   */
  async createCompanyInvoice(
    businessId: string,
    dto: CreateCompanyInvoiceDto
  ): Promise<CompanyInvoiceResponseDto> {
    // Fetch product
    const product = await this.productModel.findById(dto.productId);
    if (!product) {
      throw new NotFoundException('Product not found');
    }

    // Check product belongs to business
    if (product.businessId.toString() !== businessId) {
      throw new ForbiddenException('Product does not belong to this business');
    }

    // Check sufficient quantity
    if (product.quantity < dto.quantity) {
      throw new BadRequestException('Insufficient product quantity');
    }

    // Calculate amount
    const amount = dto.quantity * product.unitPrice;

    // Create invoice
    const invoice = new this.companyInvoiceModel({
      businessId,
      clientBusinessId: dto.clientBusinessId,
      clientCompanyName: dto.clientCompanyName,
      clientContactEmail: dto.clientContactEmail,
      productId: dto.productId,
      quantity: dto.quantity,
      amount,
      issuedAt: new Date(),
      paid: false,
    });

    const savedInvoice = await invoice.save();

    // Deduct quantity from product
    await this.productModel.findByIdAndUpdate(
      dto.productId,
      { $inc: { quantity: -dto.quantity } },
      { new: true }
    );

    return this.formatCompanyInvoiceResponse(savedInvoice);
  }

  /**
   * Get all personal invoices for a business
   */
  async getPersonalInvoicesByBusiness(
    businessId: string,
    page = 1,
    limit = 10
  ): Promise<InvoiceListResponseDto> {
    const skip = (page - 1) * limit;
    const [invoices, total] = await Promise.all([
      this.personalInvoiceModel
        .find({ businessId })
        .sort({ issuedAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      this.personalInvoiceModel.countDocuments({ businessId }),
    ]);

    return {
      invoices: invoices.map((inv) => {
        const typed = inv as unknown as PersonalInvoice;
        return this.formatPersonalInvoiceResponse(typed);
      }),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get all company invoices for a business
   */
  async getCompanyInvoicesByBusiness(
    businessId: string,
    page = 1,
    limit = 10
  ): Promise<InvoiceListResponseDto> {
    const skip = (page - 1) * limit;
    const [invoices, total] = await Promise.all([
      this.companyInvoiceModel
        .find({ businessId })
        .sort({ issuedAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      this.companyInvoiceModel.countDocuments({ businessId }),
    ]);

    return {
      invoices: invoices.map((inv) => {
        const typed = inv as unknown as CompanyInvoice;
        return this.formatCompanyInvoiceResponse(typed);
      }),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get invoices received by a user (personal invoices)
   */
  async getPersonalInvoicesForUser(
    clientUserId: string,
    page = 1,
    limit = 10
  ): Promise<InvoiceListResponseDto> {
    const skip = (page - 1) * limit;
    const [invoices, total] = await Promise.all([
      this.personalInvoiceModel
        .find({ clientUserId })
        .sort({ issuedAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      this.personalInvoiceModel.countDocuments({ clientUserId }),
    ]);

    return {
      invoices: invoices.map((inv) => {
        const typed = inv as unknown as PersonalInvoice;
        return this.formatPersonalInvoiceResponse(typed);
      }),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get invoices received by a business
   */
  async getCompanyInvoicesForBusiness(
    clientBusinessId: string,
    page = 1,
    limit = 10
  ): Promise<InvoiceListResponseDto> {
    const skip = (page - 1) * limit;
    const [invoices, total] = await Promise.all([
      this.companyInvoiceModel
        .find({ clientBusinessId })
        .sort({ issuedAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      this.companyInvoiceModel.countDocuments({ clientBusinessId }),
    ]);

    return {
      invoices: invoices.map((inv) =>
        this.formatCompanyInvoiceResponse(inv as CompanyInvoice)
      ),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get a personal invoice by ID
   */
  async getPersonalInvoiceById(
    invoiceId: string
  ): Promise<PersonalInvoiceResponseDto> {
    const invoice = await this.personalInvoiceModel.findById(invoiceId);
    if (!invoice) {
      throw new NotFoundException('Personal invoice not found');
    }
    return this.formatPersonalInvoiceResponse(invoice);
  }

  /**
   * Get a company invoice by ID
   */
  async getCompanyInvoiceById(
    invoiceId: string
  ): Promise<CompanyInvoiceResponseDto> {
    const invoice = await this.companyInvoiceModel.findById(invoiceId);
    if (!invoice) {
      throw new NotFoundException('Company invoice not found');
    }
    return this.formatCompanyInvoiceResponse(invoice);
  }

  /**
   * Update personal invoice (mark as paid)
   */
  async updatePersonalInvoice(
    invoiceId: string,
    businessId: string,
    dto: UpdateInvoiceDto
  ): Promise<PersonalInvoiceResponseDto> {
    const invoice = await this.personalInvoiceModel.findById(invoiceId);
    if (!invoice) {
      throw new NotFoundException('Personal invoice not found');
    }

    if (invoice.businessId.toString() !== businessId) {
      throw new ForbiddenException('Invoice does not belong to this business');
    }

    if (dto.paid !== undefined) {
      invoice.paid = dto.paid;
      invoice.paidAt = dto.paid ? new Date() : undefined;
    }

    const updated = await invoice.save();
    return this.formatPersonalInvoiceResponse(updated);
  }

  /**
   * Update company invoice (mark as paid)
   */
  async updateCompanyInvoice(
    invoiceId: string,
    businessId: string,
    dto: UpdateInvoiceDto
  ): Promise<CompanyInvoiceResponseDto> {
    const invoice = await this.companyInvoiceModel.findById(invoiceId);
    if (!invoice) {
      throw new NotFoundException('Company invoice not found');
    }

    if (invoice.businessId.toString() !== businessId) {
      throw new ForbiddenException('Invoice does not belong to this business');
    }

    if (dto.paid !== undefined) {
      invoice.paid = dto.paid;
      invoice.paidAt = dto.paid ? new Date() : undefined;
    }

    const updated = await invoice.save();
    return this.formatCompanyInvoiceResponse(updated);
  }

  /**
   * Delete personal invoice
   */
  async deletePersonalInvoice(
    invoiceId: string,
    businessId: string
  ): Promise<void> {
    const invoice = await this.personalInvoiceModel.findById(invoiceId);
    if (!invoice) {
      throw new NotFoundException('Personal invoice not found');
    }

    if (invoice.businessId.toString() !== businessId) {
      throw new ForbiddenException('Invoice does not belong to this business');
    }

    // Restore product quantity
    await this.productModel.findByIdAndUpdate(
      invoice.productId,
      { $inc: { quantity: invoice.quantity } },
      { new: true }
    );

    await this.personalInvoiceModel.findByIdAndDelete(invoiceId);
  }

  /**
   * Delete company invoice
   */
  async deleteCompanyInvoice(
    invoiceId: string,
    businessId: string
  ): Promise<void> {
    const invoice = await this.companyInvoiceModel.findById(invoiceId);
    if (!invoice) {
      throw new NotFoundException('Company invoice not found');
    }

    if (invoice.businessId.toString() !== businessId) {
      throw new ForbiddenException('Invoice does not belong to this business');
    }

    // Restore product quantity
    await this.productModel.findByIdAndUpdate(
      invoice.productId,
      { $inc: { quantity: invoice.quantity } },
      { new: true }
    );

    await this.companyInvoiceModel.findByIdAndDelete(invoiceId);
  }

  private formatPersonalInvoiceResponse(
    invoice: PersonalInvoice
  ): PersonalInvoiceResponseDto {
    return {
      id: invoice._id.toString(),
      businessId: invoice.businessId.toString(),
      productId: invoice.productId.toString(),
      clientUserId: invoice.clientUserId.toString(),
      quantity: invoice.quantity,
      amount: invoice.amount,
      issuedAt: invoice.issuedAt,
      paid: invoice.paid,
      paidAt: invoice.paidAt ?? undefined,
      createdAt: invoice.createdAt,
      updatedAt: invoice.updatedAt,
    };
  }

  private formatCompanyInvoiceResponse(
    invoice: CompanyInvoice
  ): CompanyInvoiceResponseDto {
    return {
      id: invoice._id.toString(),
      businessId: invoice.businessId.toString(),
      productId: invoice.productId.toString(),
      clientBusinessId: invoice.clientBusinessId.toString(),
      clientCompanyName: invoice.clientCompanyName,
      clientContactEmail: invoice.clientContactEmail,
      quantity: invoice.quantity,
      amount: invoice.amount,
      issuedAt: invoice.issuedAt,
      paid: invoice.paid,
      paidAt: invoice.paidAt ?? undefined,
      createdAt: invoice.createdAt,
      updatedAt: invoice.updatedAt,
    };
  }

  /**
   * Import personal invoices from parsed CSV/Excel data
   */
  async importPersonalInvoices(
    businessId: string,
    records: Record<string, unknown>[]
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    const errors: string[] = [];
    let imported = 0;

    for (const [i, record] of records.entries()) {
      const rowNum = i + 2;

      try {
        const clientUserId = record.clientUserId as string;
        const productId = record.productId as string;
        const quantity = record.quantity as number;

        if (!clientUserId?.trim()) {
          throw new Error('Missing required field: clientUserId');
        }
        if (!productId?.trim()) {
          throw new Error('Missing required field: productId');
        }

        const parsedQuantity = Number(quantity);
        if (Number.isNaN(parsedQuantity) || parsedQuantity < 1) {
          throw new Error('quantity must be a valid positive number');
        }

        // Fetch product and validate
        const product = await this.productModel.findById(productId);
        if (!product) {
          throw new Error('Product not found');
        }

        if (product.businessId.toString() !== businessId) {
          throw new Error('Product does not belong to this business');
        }

        if (product.quantity < parsedQuantity) {
          throw new Error('Insufficient product quantity');
        }

        // Calculate amount and create invoice
        const amount = parsedQuantity * product.unitPrice;
        const invoice = new this.personalInvoiceModel({
          businessId,
          clientUserId: clientUserId.trim(),
          productId,
          quantity: parsedQuantity,
          amount,
          issuedAt: new Date(),
          paid: false,
        });

        await invoice.save();

        // Deduct quantity from product
        await this.productModel.findByIdAndUpdate(
          productId,
          { $inc: { quantity: -parsedQuantity } },
          { new: true }
        );

        imported++;
      } catch (error) {
        errors.push(`Row ${rowNum}: ${(error as Error).message}`);
      }
    }

    return { imported, failed: errors.length, errors };
  }

  /**
   * Import company invoices from parsed CSV/Excel data
   */
  async importCompanyInvoices(
    businessId: string,
    records: Record<string, unknown>[]
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    const errors: string[] = [];
    let imported = 0;

    for (const [i, record] of records.entries()) {
      const rowNum = i + 2;

      try {
        const clientBusinessId = record.clientBusinessId as string;
        const clientCompanyName = record.clientCompanyName as string;
        const clientContactEmail = record.clientContactEmail as string;
        const productId = record.productId as string;
        const quantity = record.quantity as number;

        if (!clientBusinessId?.trim()) {
          throw new Error('Missing required field: clientBusinessId');
        }
        if (!clientCompanyName?.trim()) {
          throw new Error('Missing required field: clientCompanyName');
        }
        if (!clientContactEmail?.trim()) {
          throw new Error('Missing required field: clientContactEmail');
        }
        if (!productId?.trim()) {
          throw new Error('Missing required field: productId');
        }

        const parsedQuantity = Number(quantity);
        if (Number.isNaN(parsedQuantity) || parsedQuantity < 1) {
          throw new Error('quantity must be a valid positive number');
        }

        // Fetch product and validate
        const product = await this.productModel.findById(productId);
        if (!product) {
          throw new Error('Product not found');
        }

        if (product.businessId.toString() !== businessId) {
          throw new Error('Product does not belong to this business');
        }

        if (product.quantity < parsedQuantity) {
          throw new Error('Insufficient product quantity');
        }

        // Calculate amount and create invoice
        const amount = parsedQuantity * product.unitPrice;
        const invoice = new this.companyInvoiceModel({
          businessId,
          clientBusinessId: clientBusinessId.trim(),
          clientCompanyName: clientCompanyName.trim(),
          clientContactEmail: clientContactEmail.trim(),
          productId,
          quantity: parsedQuantity,
          amount,
          issuedAt: new Date(),
          paid: false,
        });

        await invoice.save();

        // Deduct quantity from product
        await this.productModel.findByIdAndUpdate(
          productId,
          { $inc: { quantity: -parsedQuantity } },
          { new: true }
        );

        imported++;
      } catch (error) {
        errors.push(`Row ${rowNum}: ${(error as Error).message}`);
      }
    }

    return { imported, failed: errors.length, errors };
  }
}
