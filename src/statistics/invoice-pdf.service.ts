import { Injectable } from '@nestjs/common';
import PDFDocument from 'pdfkit';

@Injectable()
export class InvoicePdfService {
  async generatePdf(data: Record<string, unknown>): Promise<Buffer> {
    const formatCurrency = (value: unknown): string => {
      let numberValue = 0;
      if (typeof value === 'number') {
        numberValue = value;
      } else if (typeof value === 'string') {
        numberValue = Number.parseFloat(value);
      }

      if (!Number.isFinite(numberValue)) {
        numberValue = 0;
      }

      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD',
      }).format(numberValue);
    };

    const text = (key: string, fallback = ''): string => {
      const value = data[key];
      if (typeof value === 'string') return value;
      if (typeof value === 'number' || typeof value === 'boolean')
        return String(value);
      return fallback;
    };

    const companyName = text('companyName', 'ACCOUNTIA');
    const companyAddress = text(
      'companyAddress',
      '123 Business Way, Tech City'
    );
    const companyEmail = text('companyEmail', 'billing@accountia.com');

    const clientName = text('clientName', 'Valued Client');
    const clientAddress = text('clientAddress', 'Client Address');
    const clientEmail = text('clientEmail', 'client@example.com');

    const invoiceNumber = text('invoiceNumber', 'INV-000000');
    const invoiceDate = text('invoiceDate', new Date().toLocaleDateString());
    const dueDate = text('dueDate', new Date().toLocaleDateString());

    const items = Array.isArray(data.items)
      ? (data.items as Array<Record<string, unknown>>)
      : [];

    const subtotalValue = data.subtotal;
    const taxRateValue = data.taxRate;
    const taxAmountValue = data.taxAmount;
    const totalAmountValue = data.totalAmount;

    const doc = new PDFDocument({ size: 'A4', margin: 40 });
    const chunks: Buffer[] = [];

    doc.on('data', (chunk: Buffer) => chunks.push(chunk));

    const finished = new Promise<Buffer>((resolve, reject) => {
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);
    });

    // Header
    doc.fillColor('#2563eb').fontSize(22).text(companyName, { align: 'left' });
    doc.moveDown(0.2);
    doc.fillColor('#666').fontSize(10).text(companyAddress);
    doc.text(companyEmail);

    doc.moveDown(1);

    // Invoice details
    doc.fillColor('#000').fontSize(12).text('Bill To:', { underline: true });
    doc.fontSize(10).text(clientName);
    doc.text(clientAddress);
    doc.text(clientEmail);

    doc.moveUp(3);
    const rightStart = 360;
    doc
      .fontSize(12)
      .text('Invoice Info:', rightStart, 120, { underline: true });
    doc.fontSize(10).text(`Invoice #: ${invoiceNumber}`, rightStart, 140);
    doc.text(`Date: ${invoiceDate}`, rightStart);
    doc.text(`Due: ${dueDate}`, rightStart);

    doc.moveDown(2);

    // Table header
    const tableTop = 200;
    const itemX = 40;
    const qtyX = 320;
    const priceX = 380;
    const totalX = 460;

    doc.fontSize(10).fillColor('#666').text('Description', itemX, tableTop);
    doc.text('Qty', qtyX, tableTop, { width: 40, align: 'right' });
    doc.text('Price', priceX, tableTop, { width: 60, align: 'right' });
    doc.text('Total', totalX, tableTop, { width: 80, align: 'right' });

    doc
      .moveTo(itemX, tableTop + 15)
      .lineTo(550, tableTop + 15)
      .stroke('#eee');

    let y = tableTop + 25;

    doc.fillColor('#000');
    for (const item of items) {
      let description = 'Item';
      if (typeof item.description === 'string') {
        description = item.description;
      } else if (
        typeof item.description === 'number' ||
        typeof item.description === 'boolean'
      ) {
        description = String(item.description);
      }

      const quantity = Number(item.quantity ?? 0);
      const price = Number(item.price ?? 0);
      const total = Number(item.total ?? quantity * price);

      doc.fontSize(10).text(description, itemX, y);
      doc.text(String(quantity), qtyX, y, { width: 40, align: 'right' });
      doc.text(formatCurrency(price), priceX, y, { width: 60, align: 'right' });
      doc.text(formatCurrency(total), totalX, y, { width: 80, align: 'right' });
      y += 20;

      if (y > 730) {
        doc.addPage();
        y = 50;
      }
    }

    // Totals
    const subtotal = formatCurrency(subtotalValue);
    const taxRate =
      typeof taxRateValue === 'number'
        ? taxRateValue
        : Number(taxRateValue ?? 0);
    const taxAmount = formatCurrency(taxAmountValue);
    const grandTotal = formatCurrency(totalAmountValue);

    doc
      .moveTo(itemX, y + 5)
      .lineTo(550, y + 5)
      .stroke('#eee');
    y += 15;
    doc
      .fontSize(10)
      .text('Subtotal', totalX - 80, y, { width: 80, align: 'left' });
    doc.text(subtotal, totalX, y, { width: 80, align: 'right' });
    y += 16;
    doc.text(`Tax (${taxRate}%)`, totalX - 80, y, { width: 80, align: 'left' });
    doc.text(taxAmount, totalX, y, { width: 80, align: 'right' });
    y += 16;
    doc
      .font('Helvetica-Bold')
      .fontSize(12)
      .text('Total', totalX - 80, y, { width: 80, align: 'left' });
    doc.text(grandTotal, totalX, y, { width: 80, align: 'right' });

    doc.moveDown(2);
    doc
      .font('Helvetica')
      .fontSize(10)
      .fillColor('#999')
      .text('Thank you for your business!', itemX, y + 40);
    doc.text('This is a computer generated invoice.');

    doc.end();

    return finished;
  }
}
