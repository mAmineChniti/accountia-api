import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional, MinLength, MaxLength } from 'class-validator';

export class CreateBusinessDto {
  @ApiProperty({ example: 'Tech Solutions Inc.' })
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  name: string;

  @ApiProperty({
    example: 'A technology company specializing in software development',
  })
  @IsString()
  @MinLength(10)
  @MaxLength(500)
  description: string;

  @ApiPropertyOptional({ example: 'https://techsolutions.com' })
  @IsOptional()
  @IsString()
  website?: string;

  @ApiProperty({ example: '+1-555-0123' })
  @IsString()
  phone: string;

  @ApiProperty({ example: 'contact@techsolutions.com' })
  @IsString()
  email: string;

  @ApiPropertyOptional({ example: 'tech_solutions_db' })
  @IsOptional()
  @IsString()
  databaseName?: string;
}
