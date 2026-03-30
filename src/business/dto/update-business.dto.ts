import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsBoolean } from 'class-validator';
import { PartialType } from '@nestjs/swagger';
import { CreateBusinessDto } from '@/business/dto/create-business.dto';

export class UpdateBusinessDto extends PartialType(CreateBusinessDto) {
  @ApiPropertyOptional({ example: false })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  automationSettings?: {
    remindersEnabled?: boolean;
    reminderIntervals?: number[];
  };
}
