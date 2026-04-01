import {
  IsString,
  IsEmail,
  IsNumber,
  IsArray,
  IsDate,
  IsOptional,
  ValidateNested,
  Min,
  ArrayMinSize,
  IsEnum,
  IsIn,
} from 'class-validator';
import { Type } from 'class-transformer';

export enum InvoiceStatusDto {
  DRAFT = 'DRAFT',
  SENT = 'SENT',
  PAID = 'PAID',
  PENDING = 'PENDING',
  OVERDUE = 'OVERDUE',
}

export class CreateInvoiceItemDto {
  @IsString()
  description: string;

  @IsNumber()
  @Min(1)
  quantity: number;

  @IsNumber()
  @Min(0)
  unitPrice: number;
}

export class CreateInvoiceDto {
  @IsString()
  clientName: string;

  @IsEmail()
  clientEmail: string;

  @IsOptional()
  @IsString()
  clientPhone?: string;

  @IsArray()
  @ValidateNested({ each: true })
  @ArrayMinSize(1)
  @Type(() => CreateInvoiceItemDto)
  lineItems: CreateInvoiceItemDto[];

  @IsDate()
  @Type(() => Date)
  issueDate: Date;

  @IsDate()
  @Type(() => Date)
  dueDate: Date;

  @IsNumber()
  @IsIn([0, 7, 13, 19], {
    message: 'VAT rate must be one of: 0%, 7%, 13%, 19%',
  })
  taxRate = 19;

  @IsOptional()
  @IsString()
  notes?: string;

  @IsOptional()
  @IsString()
  currency?: string = 'TND';

  @IsOptional()
  @IsEnum(InvoiceStatusDto)
  status?: InvoiceStatusDto = InvoiceStatusDto.DRAFT;
}
