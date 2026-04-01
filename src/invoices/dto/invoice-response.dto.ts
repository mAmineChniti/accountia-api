import { type InvoiceStatusDto } from './create-invoice.dto';

export class InvoiceItemResponseDto {
  id: string;
  description: string;
  quantity: number;
  unitPrice: number;
  total: number;
}

export class InvoiceResponseDto {
  id: string;
  invoiceNumber: string;
  businessOwnerId: string;
  clientName: string;
  clientEmail: string;
  clientPhone?: string;
  lineItems: InvoiceItemResponseDto[];
  subtotal: number;
  taxRate: number;
  taxAmount: number;
  total: number;
  issueDate: Date;
  dueDate: Date;
  status: InvoiceStatusDto;
  notes?: string;
  currency: string;
  sentAt?: Date;
  paidAt?: Date;
  remindersMuted?: boolean;
  reminderHistory?: { sentAt: Date; intervalDays: number }[];
  createdAt: Date;
  updatedAt: Date;
}

export class InvoiceListResponseDto {
  invoices: InvoiceResponseDto[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}
