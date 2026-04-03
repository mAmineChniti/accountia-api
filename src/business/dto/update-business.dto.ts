import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional } from 'class-validator';
import { PartialType } from '@nestjs/swagger';
import { CreateBusinessDto } from '@/business/dto/create-business.dto';

export class UpdateBusinessDto extends PartialType(CreateBusinessDto) {
  @ApiPropertyOptional()
  @IsOptional()
  automationSettings?: {
    remindersEnabled?: boolean;
    reminderIntervals?: number[];
  };
}
