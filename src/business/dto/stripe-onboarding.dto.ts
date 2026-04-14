import {
  IsString,
  IsUrl,
  IsOptional,
  IsBoolean,
  IsDefined,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class StripeOnboardingLinkDto {
  @ApiProperty({
    description:
      'Stripe onboarding URL for the business to complete account setup',
    example: 'https://connect.stripe.com/onboarding/acct_1234567890123456',
  })
  @IsUrl()
  @IsDefined()
  onboardingUrl!: string;

  @ApiPropertyOptional({
    description: 'Message to display to the user',
    example:
      'Click the link to complete your Stripe Connect account setup. You will be able to receive payments once verified.',
  })
  @IsString()
  @IsOptional()
  message?: string;
}

export class StripeConnectStatusDto {
  @ApiProperty({
    description: 'Whether the business has a Stripe Connect account configured',
    example: true,
  })
  @IsBoolean()
  @IsDefined()
  isConnected!: boolean;

  @ApiPropertyOptional({
    description: 'Optional Stripe Connect account ID',
    example: 'acct_1234567890123456',
  })
  @IsString()
  @IsOptional()
  stripeConnectId?: string;

  @ApiProperty({
    description: 'Status message',
    example: 'Stripe Connect account configured and ready to receive payments',
  })
  @IsString()
  @IsDefined()
  message!: string;
}
