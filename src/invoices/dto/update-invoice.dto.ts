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
import { InvoiceStatusDto, CreateInvoiceItemDto } from './create-invoice.dto';

export class UpdateInvoiceDto {
  @IsOptional()
  @IsString()
  clientName?: string;

  @IsOptional()
  @IsEmail()
  clientEmail?: string;

  @IsOptional()
  @IsString()
  clientPhone?: string;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @ArrayMinSize(1)
  @Type(() => CreateInvoiceItemDto)
  lineItems?: CreateInvoiceItemDto[];

  @IsOptional()
  @IsDate()
  @Type(() => Date)
  issueDate?: Date;

  @IsOptional()
  @IsDate()
  @Type(() => Date)
  dueDate?: Date;

  @IsOptional()
  @IsNumber()
  @IsIn([0, 7, 13, 19], { message: 'VAT rate must be one of: 0%, 7%, 13%, 19%' })
  taxRate?: number;

  @IsOptional()
  @IsString()
  notes?: string;

  @IsOptional()
  @IsString()
  currency?: string;

  @IsOptional()
  @IsEnum(InvoiceStatusDto)
  status?: InvoiceStatusDto;
}
