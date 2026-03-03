import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsOptional,
  IsUrl,
  MinLength,
  MaxLength,
} from 'class-validator';

export class CreateBusinessApplicationDto {
  @ApiProperty({ example: 'Acme Corp' })
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  businessName: string;

  @ApiProperty({ example: 'Retail' })
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  businessType: string;

  @ApiProperty({ example: 'We sell accounting software.' })
  @IsString()
  @MinLength(10)
  @MaxLength(1000)
  description: string;

  @ApiPropertyOptional({ example: 'https://acme.com' })
  @IsOptional()
  @IsUrl()
  website?: string;
}

export class BusinessApplicationResponseDto {
  @ApiProperty()
  message: string;
}
