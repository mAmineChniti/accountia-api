import {
  IsString,
  IsOptional,
  IsUrl,
  MinLength,
  MaxLength,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class BusinessApplicationDto {
  @ApiProperty({ description: 'Business name', example: 'My Company' })
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  businessName: string;

  @ApiProperty({ description: 'Business type', example: 'startup' })
  @IsString()
  @MinLength(1)
  businessType: string;

  @ApiProperty({
    description: 'Business description',
    example: 'A fintech startup focused on SME accounting',
  })
  @IsString()
  @MinLength(10)
  @MaxLength(500)
  description: string;

  @ApiPropertyOptional({
    description: 'Business website URL',
    example: 'https://mycompany.com',
  })
  @IsOptional()
  @IsUrl()
  website?: string;
}
