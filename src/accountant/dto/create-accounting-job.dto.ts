import { IsDateString } from 'class-validator';

export class CreateAccountingJobDto {
  @IsDateString()
  period_start: string;

  @IsDateString()
  period_end: string;
}

export interface InternalCreateAccountingJobPayload {
  business_id: string;
  period_start: string;
  period_end: string;
}
