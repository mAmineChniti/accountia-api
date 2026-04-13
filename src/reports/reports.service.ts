import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection, Model } from 'mongoose';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import {
  VatReportQueryDto,
  VatReportPeriod,
  VatReportResponseDto,
  VatInvoiceDto,
  VatRateSummaryDto,
} from './dto/vat-report.dto';

const VAT_RATE = 0.19; // Tunisia standard VAT rate 19%

@Injectable()
export class ReportsService {
  constructor(@InjectConnection() private connection: Connection) {}

  private getInvoiceModel(databaseName: string): Model<Invoice> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    try {
      return tenantDb.model<Invoice>(Invoice.name);
    } catch {
      return tenantDb.model<Invoice>(Invoice.name, InvoiceSchema);
    }
  }

  async getVatReport(
    businessId: string,
    databaseName: string,
    query: VatReportQueryDto
  ): Promise<VatReportResponseDto> {
    const { startDate, endDate } = this.resolveDateRange(query);
    const invoiceModel = this.getInvoiceModel(databaseName);

    const invoices = await invoiceModel
      .find({
        issuerBusinessId: businessId,
        status: { $in: [InvoiceStatus.PAID, InvoiceStatus.PARTIAL, InvoiceStatus.ISSUED, InvoiceStatus.OVERDUE] },
        issuedDate: { $gte: startDate, $lte: endDate },
      })
      .sort({ issuedDate: -1 })
      .lean();

    const vatInvoices: VatInvoiceDto[] = [];
    const rateMap = new Map<number, { netAmount: number; vatAmount: number; count: number }>();

    let totalOutputVat = 0;
    let totalTaxableRevenue = 0;

    for (const inv of invoices) {
      let invNet = 0;
      let invVat = 0;
      let invGross = 0;

      const lineItems = (inv.lineItems ?? []).map((item) => {
        const net = item.amount / (1 + VAT_RATE);
        const vat = item.amount - net;
        invNet += net;
        invVat += vat;
        invGross += item.amount;

        const existing = rateMap.get(VAT_RATE * 100) ?? { netAmount: 0, vatAmount: 0, count: 0 };
        rateMap.set(VAT_RATE * 100, {
          netAmount: existing.netAmount + net,
          vatAmount: existing.vatAmount + vat,
          count: existing.count + 1,
        });

        return {
          productName: item.productName,
          netAmount: Math.round(net * 100) / 100,
          vatRate: VAT_RATE * 100,
          vatAmount: Math.round(vat * 100) / 100,
          grossAmount: Math.round(item.amount * 100) / 100,
        };
      });

      totalOutputVat += invVat;
      totalTaxableRevenue += invNet;

      const recipientName =
        (inv.recipient as { displayName?: string; email?: string })?.displayName ??
        (inv.recipient as { displayName?: string; email?: string })?.email ??
        'Unknown';

      vatInvoices.push({
        invoiceId: String(inv._id),
        invoiceNumber: inv.invoiceNumber,
        issuedDate: inv.issuedDate.toISOString(),
        recipientName,
        totalNet: Math.round(invNet * 100) / 100,
        totalVat: Math.round(invVat * 100) / 100,
        totalGross: Math.round(invGross * 100) / 100,
        status: inv.status,
        lineItems,
      });
    }

    const byRate: VatRateSummaryDto[] = Array.from(rateMap.entries()).map(([rate, data]) => ({
      rate,
      netAmount: Math.round(data.netAmount * 100) / 100,
      vatAmount: Math.round(data.vatAmount * 100) / 100,
      count: data.count,
    }));

    return {
      businessId,
      period: query.period,
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString(),
      totalOutputVat: Math.round(totalOutputVat * 100) / 100,
      totalInputVat: 0,
      netVatPayable: Math.round(totalOutputVat * 100) / 100,
      totalTaxableRevenue: Math.round(totalTaxableRevenue * 100) / 100,
      byRate,
      invoices: vatInvoices,
    };
  }

  private resolveDateRange(query: VatReportQueryDto): { startDate: Date; endDate: Date } {
    const now = new Date();

    if (query.period === VatReportPeriod.CUSTOM) {
      if (!query.startDate || !query.endDate) {
        throw new BadRequestException('startDate and endDate are required for custom period');
      }
      return { startDate: new Date(query.startDate), endDate: new Date(query.endDate) };
    }

    const year = query.year ? parseInt(query.year, 10) : now.getFullYear();

    if (query.period === VatReportPeriod.YEARLY) {
      return {
        startDate: new Date(year, 0, 1),
        endDate: new Date(year, 11, 31, 23, 59, 59),
      };
    }

    if (query.period === VatReportPeriod.QUARTERLY) {
      const quarter = query.quarter ? parseInt(query.quarter, 10) : Math.ceil((now.getMonth() + 1) / 3);
      const startMonth = (quarter - 1) * 3;
      return {
        startDate: new Date(year, startMonth, 1),
        endDate: new Date(year, startMonth + 3, 0, 23, 59, 59),
      };
    }

    // MONTHLY
    const month = query.month ? parseInt(query.month, 10) - 1 : now.getMonth();
    return {
      startDate: new Date(year, month, 1),
      endDate: new Date(year, month + 1, 0, 23, 59, 59),
    };
  }
}
