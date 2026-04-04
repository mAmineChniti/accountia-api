import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ChatController } from './chat.controller';
import { ChatService } from './chat.service';
import { Business, BusinessSchema } from '@/business/schemas/business.schema';
import {
  BusinessUser,
  BusinessUserSchema,
} from '@/business/schemas/business-user.schema';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Business.name, schema: BusinessSchema },
      { name: BusinessUser.name, schema: BusinessUserSchema },
      { name: Invoice.name, schema: InvoiceSchema },
    ]),
  ],
  controllers: [ChatController],
  providers: [ChatService],
})
export class ChatModule {}
