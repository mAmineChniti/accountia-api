import { IsNumber, IsDateString, IsOptional } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateExpenseDto {
  @IsNumber()
  amount!: number;

  @Type(() => Date)
  @IsDateString()
  date!: Date;

  @IsOptional()
  user?: string;
}
