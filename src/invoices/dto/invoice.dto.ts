import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsNumber,
  IsOptional,
  IsEnum,
  IsDateString,
  Min,
  MinLength,
  MaxLength,
} from 'class-validator';
import { InvoiceStatus } from '../schemas/invoice.schema';

export class CreateInvoiceDto {
  @ApiProperty({
    example: '507f1f77bcf86cd799439011',
    description: 'Client user ID',
  })
  @IsString()
  clientId: string;

  @ApiProperty({ example: 'Web Development Services' })
  @IsString()
  @MinLength(3)
  @MaxLength(200)
  description: string;

  @ApiProperty({ example: 1500 })
  @IsNumber()
  @Min(0.01)
  amount: number;

  @ApiPropertyOptional({ example: 'USD' })
  @IsOptional()
  @IsString()
  currency?: string;

  @ApiProperty({ example: '2025-04-01' })
  @IsDateString()
  dueDate: string;

  @ApiPropertyOptional({ example: 'Payment for March 2025' })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  notes?: string;
}

export class UpdateInvoiceStatusDto {
  @ApiProperty({ enum: InvoiceStatus, enumName: 'InvoiceStatus' })
  @IsEnum(InvoiceStatus)
  status: InvoiceStatus;
}

export class InvoiceResponseDto {
  @ApiProperty() id: string;
  @ApiProperty() invoiceNumber: string;
  @ApiProperty() description: string;
  @ApiProperty() amount: number;
  @ApiProperty() currency: string;
  @ApiProperty({ enum: InvoiceStatus, enumName: 'InvoiceStatus' })
  status: InvoiceStatus;
  @ApiProperty() dueDate: string;
  @ApiPropertyOptional() paidAt?: string;
  @ApiPropertyOptional() notes?: string;
  @ApiProperty() clientId: string;
  @ApiProperty() businessOwnerId: string;
  @ApiProperty() createdAt: string;
}

export class InvoicesListResponseDto {
  @ApiProperty() message: string;
  @ApiProperty({ type: InvoiceResponseDto, isArray: true })
  invoices: InvoiceResponseDto[];
  @ApiProperty() total: number;
}
