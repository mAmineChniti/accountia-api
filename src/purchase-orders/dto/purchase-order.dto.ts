import {
  IsString, IsOptional, IsEnum, IsNumber, IsDateString, IsArray, ValidateNested, Min, IsBoolean,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { PurchaseOrderStatus } from '../schemas/purchase-order.schema';

export class POLineItemDto {
  @ApiPropertyOptional()
  @IsOptional()
  productId?: string;

  @ApiProperty()
  @IsString()
  productName!: string;

  @ApiProperty()
  @IsNumber()
  @Min(1)
  orderedQuantity!: number;

  @ApiProperty()
  @IsNumber()
  @Min(0)
  unitPrice!: number;

  @ApiProperty()
  @IsNumber()
  @Min(0)
  amount!: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;
}

export class CreatePurchaseOrderDto {
  @ApiProperty()
  @IsString()
  businessId!: string;

  @ApiProperty()
  @IsString()
  vendorId!: string;

  @ApiProperty()
  @IsString()
  vendorName!: string;

  @ApiProperty({ description: 'ISO 8601 order date' })
  @IsDateString()
  orderDate!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsDateString()
  expectedDeliveryDate?: string;

  @ApiProperty({ type: [POLineItemDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => POLineItemDto)
  lineItems!: POLineItemDto[];

  @ApiProperty()
  @IsNumber()
  @Min(0)
  totalAmount!: number;

  @ApiPropertyOptional({ default: 'TND' })
  @IsOptional()
  @IsString()
  currency?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  notes?: string;
}

export class UpdatePurchaseOrderDto {
  @ApiProperty()
  @IsString()
  businessId!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsDateString()
  expectedDeliveryDate?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  notes?: string;

  @ApiPropertyOptional({ type: [POLineItemDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => POLineItemDto)
  lineItems?: POLineItemDto[];

  @ApiPropertyOptional()
  @IsOptional()
  @IsNumber()
  @Min(0)
  totalAmount?: number;
}

export class ReceiveGoodsDto {
  @ApiProperty()
  @IsString()
  businessId!: string;

  @ApiProperty({ description: 'Map of lineItem ID to received quantity' })
  receivedQuantities!: Record<string, number>;
}

export class ApprovePODto {
  @ApiProperty()
  @IsString()
  businessId!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  rejectionReason?: string;
}

export class PurchaseOrderResponseDto {
  id!: string;
  businessId!: string;
  poNumber!: string;
  vendorId!: string;
  vendorName!: string;
  status!: PurchaseOrderStatus;
  lineItems!: POLineItemDto[];
  totalAmount!: number;
  currency!: string;
  orderDate!: string;
  expectedDeliveryDate?: string;
  receivedAt?: string;
  notes?: string;
  createdBy?: string;
  approvedBy?: string;
  approvedAt?: string;
  rejectionReason?: string;
  lastStatusChangeAt?: string;
  createdAt!: Date;
  updatedAt!: Date;
}

export class PurchaseOrderListResponseDto {
  purchaseOrders!: PurchaseOrderResponseDto[];
  total!: number;
  page!: number;
  limit!: number;
  totalPages!: number;
}
