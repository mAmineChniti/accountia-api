import { Controller, Get, Post, Body, Param, Patch, Delete, UseGuards, Res } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { RecurringInvoicesService } from './recurring-invoices.service';
import { CreateRecurringInvoiceDto, UpdateRecurringInvoiceStatusDto } from './dto/recurring-invoice.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import type { UserPayload } from '@/auth/types/auth.types';
import { InvoicePdfService } from './invoice-pdf.service';
import type { Response } from 'express';

@ApiTags('Recurring Invoices')
@Controller('recurring-invoices')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class RecurringInvoicesController {
  constructor(
    private readonly recurringService: RecurringInvoicesService,
    private readonly pdfService: InvoicePdfService
  ) { }

  @Post()
  @ApiOperation({ summary: 'Create a new recurring invoice schedule' })
  @ApiResponse({ status: 201, description: 'The recurring invoice has been successfully created.' })
  create(@Body() createDto: CreateRecurringInvoiceDto, @CurrentUser() user: UserPayload) {
    // In a real app, you might link it to the user's active business here
    return this.recurringService.create(createDto);
  }

  @Get()
  @ApiOperation({ summary: 'List all recurring invoices' })
  findAll() {
    return this.recurringService.findAll();
  }

  @Get('stats')
  @ApiOperation({ summary: 'Get overall statistics for recurring invoices (MRR, Active, Paused)' })
  getStats() {
    return this.recurringService.getStats();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a single recurring invoice by ID' })
  findOne(@Param('id') id: string) {
    return this.recurringService.findOne(id);
  }

  @Patch(':id/status')
  @ApiOperation({ summary: 'Update the status of a recurring invoice (active/paused/cancelled)' })
  updateStatus(@Param('id') id: string, @Body() statusDto: UpdateRecurringInvoiceStatusDto) {
    return this.recurringService.updateStatus(id, statusDto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a recurring invoice schedule entirely' })
  remove(@Param('id') id: string) {
    return this.recurringService.remove(id);
  }

  @Get(':id/download')
  @ApiOperation({ summary: 'Download invoice PDF' })
  async download(@Param('id') id: string, @Res() res: Response) {
    const invoice = await this.recurringService.findOne(id);
    if (!invoice) return res.status(404).json({ message: 'Invoice not found' });

    // Map invoice to template data
    const data = {
      companyName: 'Accountia Ltd',
      companyAddress: '123 Business Way, Tech City',
      companyEmail: 'billing@accountia.com',
      clientName: invoice.clientName || 'Valued Client',
      clientAddress: 'Client address placeholder',
      clientEmail: invoice.clientEmail || 'client@example.com',
      invoiceNumber: `INV-${id.slice(-6).toUpperCase()}`,
      invoiceDate: new Date().toLocaleDateString(),
      dueDate: new Date(invoice.nextRunDate).toLocaleDateString(),
      items: invoice.items.map((item) => ({
        description: item.description,
        quantity: item.quantity,
        price: item.price,
        total: item.quantity * item.price,
      })),
      subtotal: invoice.totalAmount,
      taxRate: 0,
      taxAmount: 0,
      totalAmount: invoice.totalAmount,
    };

    const pdfBuffer = await this.pdfService.generatePdf(data);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=invoice-${id}.pdf`);
    res.send(pdfBuffer);
  }
}
