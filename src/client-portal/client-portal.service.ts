import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectConnection, InjectModel } from '@nestjs/mongoose';
import { Connection, Model } from 'mongoose';
import * as crypto from 'node:crypto';
import { PortalToken } from './schemas/portal-token.schema';
import { InvoiceReceipt } from '@/invoices/schemas/invoice-receipt.schema';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';

export interface PortalInvoiceSummary {
  id: string;
  invoiceNumber: string;
  issuerBusinessName: string;
  totalAmount: number;
  currency: string;
  issuedDate: string;
  dueDate: string;
  status: string;
  amountPaid: number;
}

export interface PortalInvoiceDetail extends PortalInvoiceSummary {
  lineItems: Array<{
    productName: string;
    quantity: number;
    unitPrice: number;
    amount: number;
  }>;
  description?: string;
  paymentTerms?: string;
}

@Injectable()
export class ClientPortalService {
  constructor(
    @InjectConnection() private connection: Connection,
    @InjectModel(PortalToken.name) private portalTokenModel: Model<PortalToken>,
    @InjectModel(InvoiceReceipt.name)
    private receiptModel: Model<InvoiceReceipt>
  ) {}

  private getInvoiceModel(databaseName: string): Model<Invoice> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    try {
      return tenantDb.model<Invoice>(Invoice.name);
    } catch {
      return tenantDb.model<Invoice>(Invoice.name, InvoiceSchema);
    }
  }

  async generatePortalToken(
    businessId: string,
    clientEmail: string,
    clientName?: string,
    expiryDays = 30
  ): Promise<{ token: string; expiresAt: Date }> {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiryDays);
    const normalizedEmail = clientEmail.toLowerCase().trim();

    await this.portalTokenModel.findOneAndUpdate(
      { businessId, clientEmail: normalizedEmail },
      { token, expiresAt, clientName },
      { upsert: true, new: true }
    );

    return { token, expiresAt };
  }

  async validateToken(token: string): Promise<PortalToken> {
    const portalToken = await this.portalTokenModel.findOne({
      token,
      expiresAt: { $gt: new Date() },
    });

    if (!portalToken) {
      throw new UnauthorizedException('Invalid or expired portal token');
    }

    await this.portalTokenModel.findByIdAndUpdate(portalToken._id, {
      lastAccessedAt: new Date(),
    });

    return portalToken;
  }

  async getClientInvoices(token: string): Promise<PortalInvoiceSummary[]> {
    const portalToken = await this.validateToken(token);
    const normalizedEmail = portalToken.clientEmail.toLowerCase().trim();

    const receipts = await this.receiptModel
      .find({
        issuerBusinessId: portalToken.businessId,
        recipientEmail: { $regex: new RegExp(`^${normalizedEmail}$`, 'i') },
      })
      .sort({ issuedDate: -1 })
      .lean();

    return (receipts as InvoiceReceipt[]).map((r) => ({
      id: String(r._id),
      invoiceNumber: r.invoiceNumber,
      issuerBusinessName: r.issuerBusinessName,
      totalAmount: r.totalAmount,
      currency: r.currency,
      issuedDate:
        r.issuedDate instanceof Date
          ? r.issuedDate.toISOString()
          : String(r.issuedDate),
      dueDate:
        r.dueDate instanceof Date ? r.dueDate.toISOString() : String(r.dueDate),
      status: r.invoiceStatus,
      amountPaid: 0,
    }));
  }

  async getClientInvoiceDetail(
    token: string,
    invoiceId: string
  ): Promise<PortalInvoiceDetail> {
    const portalToken = await this.validateToken(token);
    const normalizedEmail = portalToken.clientEmail.toLowerCase().trim();

    const receipt = await this.receiptModel.findOne({
      _id: invoiceId,
      issuerBusinessId: portalToken.businessId,
      recipientEmail: { $regex: new RegExp(`^${normalizedEmail}$`, 'i') },
    });

    if (!receipt) throw new NotFoundException('Invoice not found');

    const invoiceModel = this.getInvoiceModel(receipt.issuerTenantDatabaseName);
    const invoice = await invoiceModel.findById(String(receipt.invoiceId));

    if (!invoice) throw new NotFoundException('Invoice not found');

    return {
      id: String(receipt._id),
      invoiceNumber: invoice.invoiceNumber,
      issuerBusinessName: receipt.issuerBusinessName,
      totalAmount: invoice.totalAmount,
      currency: invoice.currency,
      issuedDate: invoice.issuedDate.toISOString(),
      dueDate: invoice.dueDate.toISOString(),
      status: invoice.status,
      amountPaid: invoice.amountPaid ?? 0,
      lineItems: (invoice.lineItems ?? []).map((item) => ({
        productName: item.productName,
        quantity: item.quantity,
        unitPrice: item.unitPrice,
        amount: item.amount,
      })),
      description: invoice.description,
      paymentTerms: invoice.paymentTerms,
    };
  }

  async getPortalInfo(token: string): Promise<{
    clientEmail: string;
    clientName?: string;
    businessId: string;
    expiresAt: Date;
  }> {
    const portalToken = await this.validateToken(token);
    return {
      clientEmail: portalToken.clientEmail,
      clientName: portalToken.clientName,
      businessId: String(portalToken.businessId),
      expiresAt: portalToken.expiresAt,
    };
  }
}
