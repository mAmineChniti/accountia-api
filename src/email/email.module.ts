import { Module } from '@nestjs/common';
import { EmailService } from '@/email/email.service';

@Module({
  imports: [],
  providers: [EmailService],
  exports: [EmailService],
})
export class EmailModule {}
