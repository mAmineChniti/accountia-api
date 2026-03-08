import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, MaxLength } from 'class-validator';

export class BanUserDto {
  @ApiPropertyOptional({ example: 'Violation of terms of service' })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  reason?: string;
}

export class BanResponseDto {
  @ApiProperty({ example: 'User banned successfully' })
  message: string;

  @ApiProperty({ example: '507f1f77bcf86cd799439011' })
  userId: string;

  @ApiProperty({ example: true })
  isBanned: boolean;

  @ApiPropertyOptional({ example: 'Violation of terms of service' })
  reason?: string;
}
