import { IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangePasswordDto {
  @ApiProperty({
    example: 'OldP@ssw0rd!',
    minLength: 6,
    description: 'Current password',
  })
  @IsString()
  @MinLength(6)
  currentPassword: string;

  @ApiProperty({
    example: 'NewP@ssw0rd!',
    minLength: 6,
    description: 'New password',
  })
  @IsString()
  @MinLength(6)
  newPassword: string;
}
