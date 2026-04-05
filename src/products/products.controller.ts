import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Patch,
  Delete,
  Query,
  HttpCode,
  HttpStatus,
  UseGuards,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { type Multer } from 'multer';
import {
  ApiTags,
  ApiOperation,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiNotFoundResponse,
  ApiBadRequestResponse,
  ApiForbiddenResponse,
  ApiParam,
  ApiQuery,
  ApiBearerAuth,
  ApiConsumes,
  ApiBody,
} from '@nestjs/swagger';
import { ProductsService } from './products.service';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import {
  ProductResponseDto,
  ProductListResponseDto,
} from './dto/product-response.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import {
  BusinessRolesGuard,
  BusinessRoles,
} from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { parseFile } from '@/common/utils/file-parser.util';
import type { TenantContext } from '@/common/tenant/tenant.types';

@ApiTags('Products')
@Controller('products')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
@BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a new product',
    description:
      'Create a new product for the current business. Set the active business using businessId in the request body.',
  })
  @ApiBody({
    description:
      'Product payload with businessId to resolve current tenant context.',
    type: CreateProductDto,
  })
  @ApiCreatedResponse({
    description: 'Product created successfully',
    type: ProductResponseDto,
  })
  @ApiBadRequestResponse({ description: 'Invalid input data' })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions or unauthorized business',
  })
  async create(
    @Body() createProductDto: CreateProductDto,
    @CurrentTenant() tenant: TenantContext
  ): Promise<ProductResponseDto> {
    return this.productsService.create(tenant.businessId, createProductDto);
  }

  @Get()
  @ApiOperation({
    summary: 'Get all products for the business',
    description:
      'Retrieve paginated list of products for the current business. Include businessId in the request body to set the current business context.',
  })
  @ApiOkResponse({
    description: 'Products retrieved successfully',
    type: ProductListResponseDto,
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions or unauthorized business',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number (default: 1)',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Items per page (default: 10)',
  })
  @ApiQuery({
    name: 'search',
    required: false,
    type: String,
    description: 'Search by name or description',
  })
  async findAll(
    @CurrentTenant() tenant: TenantContext,
    @Query('page') page = 1,
    @Query('limit') limit = 10,
    @Query('search') search?: string
  ): Promise<ProductListResponseDto> {
    return this.productsService.findByBusiness(
      tenant.businessId,
      page,
      limit,
      search
    );
  }

  @Get(':id')
  @ApiOperation({
    summary: 'Get a product by ID',
    description:
      'Get a specific product by ID (must belong to current business). Include businessId in the request body to set the current business context.',
  })
  @ApiOkResponse({
    description: 'Product retrieved successfully',
    type: ProductResponseDto,
  })
  @ApiNotFoundResponse({ description: 'Product not found' })
  @ApiForbiddenResponse({
    description: 'Product does not belong to your business',
  })
  @ApiParam({
    name: 'id',
    description: 'Product ID',
    type: String,
  })
  async findById(
    @Param('id') id: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<ProductResponseDto> {
    return this.productsService.findById(id, tenant.businessId);
  }

  @Patch(':id')
  @ApiOperation({
    summary: 'Update a product',
    description:
      'Update a product (must belong to current business). Include businessId in the request body to set the current business context.',
  })
  @ApiBody({
    description:
      'Product update payload with businessId to resolve current tenant context.',
    type: UpdateProductDto,
  })
  @ApiOkResponse({
    description: 'Product updated successfully',
    type: ProductResponseDto,
  })
  @ApiNotFoundResponse({ description: 'Product not found' })
  @ApiBadRequestResponse({ description: 'Invalid input data' })
  @ApiForbiddenResponse({
    description: 'Product does not belong to your business',
  })
  @ApiParam({
    name: 'id',
    description: 'Product ID',
    type: String,
  })
  async update(
    @Param('id') id: string,
    @Body() updateProductDto: UpdateProductDto,
    @CurrentTenant() tenant: TenantContext
  ): Promise<ProductResponseDto> {
    return this.productsService.update(id, tenant.businessId, updateProductDto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a product',
    description:
      'Delete a product (must belong to current business). Include businessId in the request body to set the current business context.',
  })
  @ApiNotFoundResponse({ description: 'Product not found' })
  @ApiForbiddenResponse({
    description: 'Product does not belong to your business',
  })
  @ApiParam({
    name: 'id',
    description: 'Product ID',
    type: String,
  })
  async delete(
    @Param('id') id: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<void> {
    return this.productsService.delete(id, tenant.businessId);
  }

  @Post('import')
  @HttpCode(HttpStatus.CREATED)
  @UseInterceptors(FileInterceptor('file'))
  @ApiConsumes('multipart/form-data')
  @ApiOperation({
    summary: 'Import products from CSV or Excel',
    description:
      'Bulk import products from a CSV or Excel file. Required columns: name, description, unitPrice, quantity. Include businessId in the request body to set the current business context.',
  })
  @ApiCreatedResponse({
    description: 'Products imported successfully',
    schema: {
      type: 'object',
      properties: {
        imported: { type: 'number' },
        failed: { type: 'number' },
        errors: { type: 'array', items: { type: 'string' } },
      },
    },
  })
  @ApiBadRequestResponse({ description: 'Invalid file format or data' })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions',
  })
  async importProducts(
    @UploadedFile() file: Multer.File,
    @CurrentTenant() tenant: TenantContext
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    const records = await parseFile(
      (file as unknown as { buffer: Buffer; originalname: string }).buffer,
      (file as unknown as { buffer: Buffer; originalname: string }).originalname
    );
    return this.productsService.importProducts(tenant.businessId, records);
  }
}
