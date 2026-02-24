import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MinLength,
  MaxLength,
  IsOptional,
  IsBoolean,
  IsDateString,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class RegisterDto {
  @ApiProperty({ example: 'john_doe', minLength: 5, maxLength: 20 })
  @IsNotEmpty()
  @IsString()
  @MinLength(5)
  @MaxLength(20)
  username: string;

  @ApiProperty({ example: 'john@example.com' })
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'P@ssw0rd!', minLength: 6 })
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'John', minLength: 2, maxLength: 50 })
  @IsNotEmpty()
  @IsString()
  @MinLength(2)
  @MaxLength(50)
  firstName: string;

  @ApiProperty({ example: 'Doe', minLength: 2, maxLength: 50 })
  @IsNotEmpty()
  @IsString()
  @MinLength(2)
  @MaxLength(50)
  lastName: string;

  @ApiProperty({ example: '1990-01-01T00:00:00Z' })
  @IsNotEmpty()
  @IsDateString()
  birthdate: string;

  @ApiPropertyOptional({ example: '+1234567890' })
  @IsOptional()
  @IsString()
  phoneNumber?: string;

  @ApiProperty({ example: true })
  @IsNotEmpty()
  @IsBoolean()
  acceptTerms: boolean;

  @ApiPropertyOptional({ example: 'data:image/png;base64,iVBORw0...' })
  @IsOptional()
  @IsString()
  @MaxLength(9_333_334, {
    message: 'Profile picture base64 data must be less than 7MB',
  })
  profilePicture?: string;
}
