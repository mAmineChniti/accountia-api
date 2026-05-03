import {
  IsString,
  IsOptional,
  IsEmail,
  IsNumber,
  Min,
  IsDate,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class GeneratePortalTokenDto {
  @ApiProperty({ description: 'Business ID for tenant resolution' })
  @IsString()
  businessId!: string;

  @ApiProperty({ description: 'Client email address' })
  @IsEmail()
  clientEmail!: string;

  @ApiPropertyOptional({ description: 'Client name' })
  @IsOptional()
  @IsString()
  clientName?: string;

  @ApiPropertyOptional({ description: 'Token expiry in days', minimum: 1 })
  @IsOptional()
  @IsNumber()
  @Min(1)
  expiryDays?: number;
}

export class GeneratePortalTokenResponseDto {
  @ApiProperty({ description: 'Portal access token' })
  @IsString()
  token!: string;

  @ApiProperty({ description: 'Token expiration date' })
  @IsDate()
  @Type(() => Date)
  expiresAt!: Date;

  @ApiProperty({ description: 'Portal URL' })
  @IsString()
  portalUrl!: string;
}
