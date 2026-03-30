import { Module } from '@nestjs/common';
import { EmailService } from '@/email/email.service';
import { EmailController } from '@/email/email.controller';

@Module({
  imports: [],
  controllers: [EmailController],
  providers: [EmailService],
  exports: [EmailService],
})
export class EmailModule {}
