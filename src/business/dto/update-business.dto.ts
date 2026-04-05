import { ApiPropertyOptional, PartialType } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';
import { CreateBusinessDto } from '@/business/dto/create-business.dto';

export class UpdateBusinessDto extends PartialType(CreateBusinessDto) {
  @ApiPropertyOptional({
    description: 'Tenant businessId used to resolve current business context.',
    type: String,
  })
  @IsOptional()
  @IsString()
  businessId?: string;
}
