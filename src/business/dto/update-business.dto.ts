import { ApiProperty, PartialType } from '@nestjs/swagger';
import { IsString } from 'class-validator';
import { CreateBusinessDto } from '@/business/dto/create-business.dto';

export class UpdateBusinessDto extends PartialType(CreateBusinessDto) {
  @ApiProperty({
    description: 'Tenant businessId used to resolve current business context.',
    type: String,
  })
  @IsString()
  businessId!: string;
}
