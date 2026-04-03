import {
  IsString,
  IsEmail,
  IsNumber,
  IsBoolean,
  IsOptional,
  Min,
} from 'class-validator';

export class CreatePersonalInvoiceDto {
  @IsString()
  clientUserId!: string;

  @IsString()
  productId!: string;

  @IsNumber()
  @Min(1)
  quantity!: number;
}

export class CreateCompanyInvoiceDto {
  @IsString()
  clientBusinessId!: string;

  @IsString()
  clientCompanyName!: string;

  @IsEmail()
  clientContactEmail!: string;

  @IsString()
  productId!: string;

  @IsNumber()
  @Min(1)
  quantity!: number;
}

export class UpdateInvoiceDto {
  @IsOptional()
  @IsBoolean()
  paid?: boolean;
}

export class InvoiceResponseDto {
  id!: string;
  businessId!: string;
  productId!: string;
  quantity!: number;
  amount!: number;
  issuedAt!: Date;
  paid!: boolean;
  paidAt?: Date | null;
  createdAt!: Date;
  updatedAt!: Date;
}

export class PersonalInvoiceResponseDto extends InvoiceResponseDto {
  clientUserId!: string;
}

export class CompanyInvoiceResponseDto extends InvoiceResponseDto {
  clientBusinessId!: string;
  clientCompanyName!: string;
  clientContactEmail!: string;
}

export class InvoiceListResponseDto {
  invoices!: (PersonalInvoiceResponseDto | CompanyInvoiceResponseDto)[];
  total!: number;
  page!: number;
  limit!: number;
  totalPages!: number;
}
