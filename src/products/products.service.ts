import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection, Model } from 'mongoose';
import { Product, ProductSchema } from './schemas/product.schema';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import {
  ProductResponseDto,
  ProductListResponseDto,
} from './dto/product-response.dto';

@Injectable()
export class ProductsService {
  constructor(@InjectConnection() private connection: Connection) {}

  /**
   * Get the product model for a specific tenant database
   * Registers the schema on the connection if not already registered
   *
   * MULTI-TENANCY: Each tenant has its own isolated product collection
   * The schema is registered once per tenant connection and cached
   */
  private getProductModel(databaseName: string): Model<Product> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });

    try {
      // Try to get existing model
      return tenantDb.model<Product>(Product.name);
    } catch {
      // Schema not registered on this connection, register it now
      return tenantDb.model<Product>(Product.name, ProductSchema);
    }
  }

  /**
   * Create a new product for a business (in tenant database)
   */
  async create(
    businessId: string,
    databaseName: string,
    createProductDto: CreateProductDto
  ): Promise<ProductResponseDto> {
    const productModel = this.getProductModel(databaseName);
    const { businessId: ignoredBusinessId, ...productData } = createProductDto;
    void ignoredBusinessId;
    const product = new productModel({
      businessId,
      ...productData,
    });
    await product.save();
    return this.formatProductResponse(product);
  }

  /**
   * Get all products for a business with pagination (from tenant database)
   */
  async findByBusiness(
    businessId: string,
    databaseName: string,
    page = 1,
    limit = 10,
    search?: string
  ): Promise<ProductListResponseDto> {
    const productModel = this.getProductModel(databaseName);
    const conditions: { businessId?: string } = { businessId };

    let query = productModel.find({ ...conditions });
    let countFilter: Record<string, unknown> = { ...conditions };

    if (search) {
      query = query.or([
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
      ]);
      countFilter = {
        ...conditions,
        $or: [
          { name: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } },
        ],
      };
    }

    const total = await productModel.countDocuments(countFilter);
    const products = (await query
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean()) as Product[];

    return {
      products: products.map((p) => this.formatProductResponse(p)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get a single product by ID (from tenant database)
   */
  async findById(
    id: string,
    businessId: string,
    databaseName: string
  ): Promise<ProductResponseDto> {
    const productModel = this.getProductModel(databaseName);
    const product = await productModel.findById(id);

    if (!product) {
      throw new NotFoundException(`Product with ID ${id} not found`);
    }

    this.verifyBusinessAccess(product.businessId, businessId);

    return this.formatProductResponse(product);
  }

  /**
   * Update a product (in tenant database)
   */
  async update(
    id: string,
    businessId: string,
    databaseName: string,
    updateProductDto: UpdateProductDto
  ): Promise<ProductResponseDto> {
    const productModel = this.getProductModel(databaseName);
    const product = await productModel.findById(id);

    if (!product) {
      throw new NotFoundException(`Product with ID ${id} not found`);
    }

    this.verifyBusinessAccess(product.businessId, businessId);

    const { businessId: ignoredBusinessId, ...updateData } = updateProductDto;
    void ignoredBusinessId;
    const updated = await productModel.findByIdAndUpdate(id, updateData, {
      returnDocument: 'after',
      runValidators: true,
    });

    if (!updated) {
      throw new NotFoundException(`Product with ID ${id} not found`);
    }

    return this.formatProductResponse(updated);
  }

  /**
   * Delete a product (from tenant database)
   */
  async delete(
    id: string,
    businessId: string,
    databaseName: string
  ): Promise<void> {
    const productModel = this.getProductModel(databaseName);
    const product = await productModel.findById(id);

    if (!product) {
      throw new NotFoundException(`Product with ID ${id} not found`);
    }

    this.verifyBusinessAccess(product.businessId, businessId);

    await productModel.findByIdAndDelete(id);
  }

  /**
   * Get products by IDs for a business (bulk fetch from tenant database)
   */
  async findByIdsForBusiness(
    ids: string[],
    businessId: string,
    databaseName: string
  ): Promise<ProductResponseDto[]> {
    const productModel = this.getProductModel(databaseName);
    const products = (await productModel
      .find({
        _id: { $in: ids },
        businessId,
      })
      .lean()) as Product[];

    return products.map((p) => this.formatProductResponse(p));
  }

  /**
   * Update product quantity (in tenant database)
   */
  async updateQuantity(
    id: string,
    businessId: string,
    databaseName: string,
    quantityDelta: number
  ): Promise<ProductResponseDto> {
    const productModel = this.getProductModel(databaseName);
    const product = await productModel.findById(id);

    if (!product) {
      throw new NotFoundException(`Product with ID ${id} not found`);
    }

    this.verifyBusinessAccess(product.businessId, businessId);

    const updated =
      quantityDelta < 0
        ? await productModel.findOneAndUpdate(
            {
              _id: id,
              quantity: { $gte: Math.abs(quantityDelta) },
            },
            { $inc: { quantity: quantityDelta } },
            { returnDocument: 'after' }
          )
        : await productModel.findByIdAndUpdate(
            id,
            { $inc: { quantity: quantityDelta } },
            { returnDocument: 'after' }
          );

    if (!updated) {
      throw new BadRequestException(
        'Insufficient stock to apply quantity update'
      );
    }

    return this.formatProductResponse(updated);
  }

  /**
   * Check if product exists for a business (in tenant database)
   */
  async existsForBusiness(
    id: string,
    businessId: string,
    databaseName: string
  ): Promise<boolean> {
    const productModel = this.getProductModel(databaseName);
    const product = await productModel
      .findOne({ _id: id, businessId })
      .select('_id')
      .lean();
    return !!product;
  }

  /**
   * Import products from parsed CSV/Excel data (into tenant database)
   */
  async importProducts(
    businessId: string,
    databaseName: string,
    records: Record<string, unknown>[]
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    const productModel = this.getProductModel(databaseName);
    const errors: string[] = [];
    let imported = 0;

    for (const [i, record] of records.entries()) {
      const rowNum = i + 2; // +2 because header is row 1 and arrays are 0-indexed

      try {
        const name = this.parseStringField(record.name);
        const description = this.parseStringField(record.description);
        const unitPriceRaw = record.unitPrice;
        const quantityRaw = record.quantity;

        if (!name) {
          throw new Error('Missing required field: name');
        }
        if (!description) {
          throw new Error('Missing required field: description');
        }

        const parsedUnitPrice = this.parseNumberField(unitPriceRaw);
        if (Number.isNaN(parsedUnitPrice) || parsedUnitPrice < 0) {
          throw new Error('unitPrice must be a valid positive number');
        }

        const parsedQuantity = this.parseNumberField(quantityRaw);
        if (Number.isNaN(parsedQuantity) || parsedQuantity < 0) {
          throw new Error('quantity must be a valid positive number');
        }

        const costRaw = record.cost;
        const parsedCost = this.parseNumberField(costRaw);
        if (Number.isNaN(parsedCost) || parsedCost < 0) {
          // Default cost to 0 if not provided or invalid
        }

        // Create product
        const product = new productModel({
          businessId,
          name: name.trim(),
          description: description.trim(),
          unitPrice: parsedUnitPrice,
          cost: Number.isNaN(parsedCost) ? 0 : parsedCost,
          quantity: parsedQuantity || 0,
        });

        await product.save();
        imported++;
      } catch (error) {
        errors.push(`Row ${rowNum}: ${(error as Error).message}`);
      }
    }

    return {
      imported,
      failed: errors.length,
      errors,
    };
  }

  private verifyBusinessAccess(
    productBusinessId: string,
    currentBusinessId: string
  ): void {
    // Convert both to strings for comparison to handle ObjectId vs string mismatch
    const productId = String(productBusinessId);
    const currentId = String(currentBusinessId);

    if (productId !== currentId) {
      throw new ForbiddenException(
        'You do not have permission to access this product'
      );
    }
  }

  private parseStringField(value: unknown): string {
    return typeof value === 'string' ? value.trim() : '';
  }

  private parseNumberField(value: unknown): number {
    if (typeof value === 'number') {
      return value;
    }
    if (typeof value === 'string' && value.trim() !== '') {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : Number.NaN;
    }
    return Number.NaN;
  }

  /**
   * Format product response
   */
  private formatProductResponse(product: Product): ProductResponseDto {
    return {
      id: product._id.toString(),
      businessId: product.businessId,
      name: product.name,
      description: product.description,
      unitPrice: product.unitPrice,
      cost: product.cost ?? 0,
      quantity: product.quantity,
      currency: product.currency ?? 'TND',
      createdAt: product.createdAt,
      updatedAt: product.updatedAt,
    };
  }
}
