import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ChatController } from './chat.controller';
import { ChatService } from './chat.service';
import { Business, BusinessSchema } from '@/business/schemas/business.schema';
import {
  BusinessUser,
  BusinessUserSchema,
} from '@/business/schemas/business-user.schema';
import {
  PersonalInvoice,
  PersonalInvoiceSchema,
} from '@/invoices/schemas/personal-invoice.schema';
import {
  CompanyInvoice,
  CompanyInvoiceSchema,
} from '@/invoices/schemas/company-invoice.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Business.name, schema: BusinessSchema },
      { name: BusinessUser.name, schema: BusinessUserSchema },
      { name: PersonalInvoice.name, schema: PersonalInvoiceSchema },
      { name: CompanyInvoice.name, schema: CompanyInvoiceSchema },
    ]),
  ],
  controllers: [ChatController],
  providers: [ChatService],
})
export class ChatModule {}
