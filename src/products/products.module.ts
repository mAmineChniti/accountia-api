import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Product, ProductSchema } from './schemas/product.schema';
import { Business, BusinessSchema } from '@/business/schemas/business.schema';
import {
  BusinessUser,
  BusinessUserSchema,
} from '@/business/schemas/business-user.schema';
import { ProductsService } from './products.service';
import { ProductsController } from './products.controller';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';
import { TenantContextService } from '@/common/tenant/tenant-context.service';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Product.name, schema: ProductSchema },
      { name: Business.name, schema: BusinessSchema },
      { name: BusinessUser.name, schema: BusinessUserSchema },
    ]),
  ],
  providers: [
    ProductsService,
    TenantConnectionService,
    TenantContextService,
    TenantContextGuard,
  ],
  controllers: [ProductsController],
  exports: [ProductsService],
})
export class ProductsModule {}
