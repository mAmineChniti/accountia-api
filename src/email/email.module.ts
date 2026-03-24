import { Module } from '@nestjs/common';
import { EmailService } from '@/email/email.service';
import { EmailController } from '@/email/email.controller';
import { AuthModule } from '@/auth/auth.module';

@Module({
  imports: [AuthModule],
  controllers: [EmailController],
  providers: [EmailService],
  exports: [EmailService],
})
export class EmailModule {}
