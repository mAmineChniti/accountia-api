import {
  IsString,
  IsOptional,
  IsEnum,
  IsNumber,
  IsEmail,
  Min,
  Max,
  IsArray,
  IsDate,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { VendorStatus } from '../schemas/vendor.schema';

export class CreateVendorDto {
  @ApiProperty()
  @IsString()
  businessId!: string;

  @ApiProperty()
  @IsString()
  name!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  contactName?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  phone?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  address?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  taxId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  website?: string;

  @ApiPropertyOptional({ default: 30 })
  @IsOptional()
  @IsNumber()
  @Min(0)
  paymentTermsDays?: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  notes?: string;

  @ApiPropertyOptional({ minimum: 1, maximum: 5 })
  @IsOptional()
  @IsNumber()
  @Min(1)
  @Max(5)
  rating?: number;
}

export class UpdateVendorDto {
  @ApiProperty()
  @IsString()
  businessId!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  contactName?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  phone?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  address?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  taxId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  website?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNumber()
  @Min(0)
  paymentTermsDays?: number;

  @ApiPropertyOptional({ enum: VendorStatus, enumName: 'VendorStatus' })
  @IsOptional()
  @IsEnum(VendorStatus)
  status?: VendorStatus;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  notes?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNumber()
  @Min(1)
  @Max(5)
  rating?: number;
}

export class VendorResponseDto {
  @ApiProperty()
  @IsString()
  id!: string;

  @ApiProperty()
  @IsString()
  businessId!: string;

  @ApiProperty()
  @IsString()
  name!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  contactName?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  email?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  phone?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  address?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  taxId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  website?: string;

  @ApiProperty()
  @IsNumber()
  paymentTermsDays!: number;

  @ApiProperty({ enum: VendorStatus, enumName: 'VendorStatus' })
  @IsEnum(VendorStatus)
  status!: VendorStatus;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  notes?: string;

  @ApiProperty()
  @IsNumber()
  totalOrders!: number;

  @ApiProperty()
  @IsNumber()
  totalSpend!: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNumber()
  rating?: number;

  @IsDate()
  @Type(() => Date)
  createdAt!: Date;

  @IsDate()
  @Type(() => Date)
  updatedAt!: Date;
}

export class VendorListResponseDto {
  @ApiProperty({ type: [VendorResponseDto], isArray: true })
  @IsArray()
  @Type(() => VendorResponseDto)
  vendors!: VendorResponseDto[];

  @ApiProperty()
  @IsNumber()
  total!: number;

  @ApiProperty()
  @IsNumber()
  page!: number;

  @ApiProperty()
  @IsNumber()
  limit!: number;

  @ApiProperty()
  @IsNumber()
  totalPages!: number;
}
