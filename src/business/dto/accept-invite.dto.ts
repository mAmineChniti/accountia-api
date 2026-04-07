import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Equals,
  IsBoolean,
  IsDateString,
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
} from 'class-validator';

export class AcceptInviteDto {
  @ApiProperty({ description: 'Invitation token' })
  @IsString()
  @IsNotEmpty()
  token: string;

  @ApiProperty({ description: 'First name' })
  @IsString()
  @IsNotEmpty()
  firstName: string;

  @ApiProperty({ description: 'Last name' })
  @IsString()
  @IsNotEmpty()
  lastName: string;

  @ApiProperty({ description: 'Password' })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password: string;

  @ApiProperty({
    description: 'Must be true to accept the terms and complete invitation',
    example: true,
  })
  @IsBoolean()
  @Equals(true, { message: 'You must accept terms and conditions' })
  acceptTerms: boolean;

  @ApiPropertyOptional({
    description: 'Birthdate in ISO format (optional)',
    example: '1995-03-14',
  })
  @IsOptional()
  @IsDateString()
  birthdate?: string;
}
