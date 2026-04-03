import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Product } from './schemas/product.schema';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import {
  ProductResponseDto,
  ProductListResponseDto,
} from './dto/product-response.dto';

@Injectable()
export class ProductsService {
  constructor(
    @InjectModel(Product.name) private productModel: Model<Product>
  ) {}

  /**
   * Create a new product for a business
   */
  async create(
    businessId: string,
    createProductDto: CreateProductDto
  ): Promise<ProductResponseDto> {
    const product = new this.productModel({
      businessId,
      ...createProductDto,
    });
    await product.save();
    return this.formatProductResponse(product);
  }

  /**
   * Get all products for a business with pagination
   */
  async findByBusiness(
    businessId: string,
    page = 1,
    limit = 10,
    search?: string
  ): Promise<ProductListResponseDto> {
    let query = this.productModel.find({ businessId });

    if (search) {
      query = query.or([
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
      ]);
    }

    const total = await this.productModel.countDocuments({ businessId });
    const products = await query
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    return {
      products: products.map((p) => this.formatProductResponse(p)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get a single product by ID (with business access verification)
   */
  async findById(id: string, businessId: string): Promise<ProductResponseDto> {
    const product = await this.productModel.findById(id);

    if (!product) {
      throw new NotFoundException(`Product with ID ${id} not found`);
    }

    this.verifyBusinessAccess(product.businessId.toString(), businessId);

    return this.formatProductResponse(product);
  }

  /**
   * Update a product (with business access verification)
   */
  async update(
    id: string,
    businessId: string,
    updateProductDto: UpdateProductDto
  ): Promise<ProductResponseDto> {
    const product = await this.productModel.findById(id);

    if (!product) {
      throw new NotFoundException(`Product with ID ${id} not found`);
    }

    this.verifyBusinessAccess(product.businessId.toString(), businessId);

    const updated = await this.productModel.findByIdAndUpdate(
      id,
      updateProductDto,
      { new: true, runValidators: true }
    );

    return this.formatProductResponse(updated!);
  }

  /**
   * Delete a product (with business access verification)
   */
  async delete(id: string, businessId: string): Promise<void> {
    const product = await this.productModel.findById(id);

    if (!product) {
      throw new NotFoundException(`Product with ID ${id} not found`);
    }

    this.verifyBusinessAccess(product.businessId.toString(), businessId);

    await this.productModel.findByIdAndDelete(id);
  }

  /**
   * Get products by IDs for a business (bulk fetch with business scope)
   */
  async findByIdsForBusiness(
    ids: string[],
    businessId: string
  ): Promise<ProductResponseDto[]> {
    const products = await this.productModel
      .find({
        _id: { $in: ids },
        businessId,
      })
      .lean();

    return products.map((p) => this.formatProductResponse(p));
  }

  /**
   * Update product quantity (with business access verification)
   */
  async updateQuantity(
    id: string,
    businessId: string,
    quantityDelta: number
  ): Promise<ProductResponseDto> {
    const product = await this.productModel.findById(id);

    if (!product) {
      throw new NotFoundException(`Product with ID ${id} not found`);
    }

    this.verifyBusinessAccess(product.businessId.toString(), businessId);

    const updated = await this.productModel.findByIdAndUpdate(
      id,
      { $inc: { quantity: quantityDelta } },
      { new: true }
    );

    return this.formatProductResponse(updated!);
  }

  /**
   * Check if product exists for a business
   */
  async existsForBusiness(id: string, businessId: string): Promise<boolean> {
    const product = await this.productModel
      .findOne({ _id: id, businessId })
      .select('_id')
      .lean();
    return !!product;
  }

  /**
   * Import products from parsed CSV/Excel data
   */
  async importProducts(
    businessId: string,
    records: Record<string, unknown>[]
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    const errors: string[] = [];
    let imported = 0;

    for (const [i, record] of records.entries()) {
      const rowNum = i + 2; // +2 because header is row 1 and arrays are 0-indexed

      try {
        // Validate required fields
        const name = record.name as string;
        const description = record.description as string;
        const unitPrice = record.unitPrice as number;
        const quantity = record.quantity as number;

        if (!name?.trim()) {
          throw new Error('Missing required field: name');
        }
        if (!description?.trim()) {
          throw new Error('Missing required field: description');
        }

        const parsedUnitPrice = Number(unitPrice);
        if (Number.isNaN(parsedUnitPrice) || parsedUnitPrice < 0) {
          throw new Error('unitPrice must be a valid positive number');
        }

        const parsedQuantity = Number(quantity);
        if (Number.isNaN(parsedQuantity) || parsedQuantity < 0) {
          throw new Error('quantity must be a valid positive number');
        }

        // Create product
        const product = new this.productModel({
          businessId,
          name: name.trim(),
          description: description.trim(),
          unitPrice: parsedUnitPrice,
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
    if (productBusinessId !== currentBusinessId) {
      throw new ForbiddenException(
        'You do not have permission to access this product'
      );
    }
  }

  /**
   * Format product response
   */
  private formatProductResponse(product: Product): ProductResponseDto {
    return {
      id: product._id.toString(),
      name: product.name,
      description: product.description,
      unitPrice: product.unitPrice,
      quantity: product.quantity,
      createdAt: product.createdAt,
      updatedAt: product.updatedAt,
    };
  }
}
