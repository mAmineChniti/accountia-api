import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ChatController } from './chat.controller';
import { ChatService } from './chat.service';
import { ChatGateway } from './chat.gateway';
import { Business, BusinessSchema } from '@/business/schemas/business.schema';
import {
  BusinessUser,
  BusinessUserSchema,
} from '@/business/schemas/business-user.schema';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';
import {
  InvoiceReceipt,
  InvoiceReceiptSchema,
} from '@/invoices/schemas/invoice-receipt.schema';
import { Product, ProductSchema } from '@/products/schemas/product.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Business.name, schema: BusinessSchema },
      { name: BusinessUser.name, schema: BusinessUserSchema },
      { name: Invoice.name, schema: InvoiceSchema },
      { name: InvoiceReceipt.name, schema: InvoiceReceiptSchema },
      { name: Product.name, schema: ProductSchema },
    ]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [ChatController],
  providers: [ChatService, ChatGateway],
})
export class ChatModule {}
