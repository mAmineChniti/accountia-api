import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection, Model, Types } from 'mongoose';
import { Product, ProductSchema } from './schemas/product.schema';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import {
  ProductResponseDto,
  ProductListResponseDto,
} from './dto/product-response.dto';
import {
  StockInsightItemDto,
  StockInsightsResponseDto,
} from './dto/stock-insights.dto';
import { mapColumnsUsingAi } from '@/common/utils/ai-mapper.util';
import { CacheService } from '@/redis/cache.service';

@Injectable()
export class ProductsService {
  constructor(
    @InjectConnection() private connection: Connection,
    private readonly cacheService: CacheService
  ) {}

  private static readonly MIN_LOOKBACK_DAYS = 7;
  private static readonly MAX_LOOKBACK_DAYS = 180;
  private static readonly DEFAULT_LOOKBACK_DAYS = 30;
  private static readonly MIN_PLANNING_DAYS = 7;
  private static readonly MAX_PLANNING_DAYS = 180;
  private static readonly DEFAULT_PLANNING_DAYS = 30;

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

  private getInvoiceModel(databaseName: string): Model<Invoice> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });

    try {
      return tenantDb.model<Invoice>(Invoice.name);
    } catch {
      return tenantDb.model<Invoice>(Invoice.name, InvoiceSchema);
    }
  }

  private clampDays(
    value: number | undefined,
    min: number,
    max: number
  ): number {
    if (!Number.isFinite(value)) {
      return min;
    }

    return Math.max(min, Math.min(max, Math.floor(value!)));
  }

  async getStockInsights(
    businessId: string,
    databaseName: string,
    lookbackDays?: number,
    planningHorizonDays?: number
  ): Promise<StockInsightsResponseDto> {
    const effectiveLookbackDays = this.clampDays(
      lookbackDays ?? ProductsService.DEFAULT_LOOKBACK_DAYS,
      ProductsService.MIN_LOOKBACK_DAYS,
      ProductsService.MAX_LOOKBACK_DAYS
    );
    const effectivePlanningDays = this.clampDays(
      planningHorizonDays ?? ProductsService.DEFAULT_PLANNING_DAYS,
      ProductsService.MIN_PLANNING_DAYS,
      ProductsService.MAX_PLANNING_DAYS
    );

    // Cache key includes all parameters
    const cacheKey = `products:stock_insights:${businessId}:${effectiveLookbackDays}:${effectivePlanningDays}`;
    const cached =
      await this.cacheService.get<StockInsightsResponseDto>(cacheKey);
    if (cached) {
      // Return clone to prevent mutation of cached data
      return structuredClone(cached);
    }

    const productModel = this.getProductModel(databaseName);
    const invoiceModel = this.getInvoiceModel(databaseName);
    const now = new Date();
    const lookbackStartDate = new Date(now);
    lookbackStartDate.setDate(
      lookbackStartDate.getDate() - effectiveLookbackDays
    );

    const productFilter: Record<string, unknown> = { businessId };
    if (Types.ObjectId.isValid(businessId)) {
      productFilter.$or = [
        { businessId },
        { businessId: new Types.ObjectId(businessId) },
      ];
      delete productFilter.businessId;
    }

    const products = await productModel
      .find({ ...productFilter })
      .select('_id name quantity unitPrice')
      .lean();

    if (products.length === 0) {
      return {
        businessId,
        generatedAt: now,
        lookbackDays: effectiveLookbackDays,
        planningHorizonDays: effectivePlanningDays,
        summary: {
          totalProducts: 0,
          highRiskCount: 0,
          mediumRiskCount: 0,
          lowRiskCount: 0,
          totalRecommendedUnits: 0,
        },
        items: [],
      };
    }

    const invoiceFilter: Record<string, unknown> = {
      issuerBusinessId: businessId,
      createdAt: { $gte: lookbackStartDate },
      status: {
        $in: [
          InvoiceStatus.ISSUED,
          InvoiceStatus.VIEWED,
          InvoiceStatus.PARTIAL,
          InvoiceStatus.PAID,
          InvoiceStatus.OVERDUE,
        ],
      },
    };

    if (Types.ObjectId.isValid(businessId)) {
      invoiceFilter.$or = [
        { issuerBusinessId: businessId },
        { issuerBusinessId: new Types.ObjectId(businessId) },
      ];
      delete invoiceFilter.issuerBusinessId;
    }

    const soldLineItems = await invoiceModel
      .aggregate<{
        productId: string;
        soldQuantity: number;
      }>([
        { $match: invoiceFilter },
        { $unwind: '$lineItems' },
        {
          $group: {
            _id: { $toString: '$lineItems.productId' },
            soldQuantity: {
              $sum: { $ifNull: ['$lineItems.quantity', 0] },
            },
          },
        },
        {
          $project: {
            _id: 0,
            productId: '$_id',
            soldQuantity: 1,
          },
        },
      ])
      .exec();

    const soldByProduct = new Map<string, number>(
      soldLineItems.map((item) => [item.productId, item.soldQuantity])
    );

    const items: StockInsightItemDto[] = products.map((product) => {
      const productId = String(product._id);
      const soldLastPeriod = soldByProduct.get(productId) ?? 0;
      const currentQuantity = Number(product.quantity ?? 0);
      const dailySalesRateRaw = soldLastPeriod / effectiveLookbackDays;
      const dailySalesRate = Number(dailySalesRateRaw.toFixed(2));
      const estimatedDaysUntilStockout =
        dailySalesRate > 0
          ? Number((currentQuantity / dailySalesRate).toFixed(1))
          : undefined;

      const safetyStock = Math.max(5, Math.ceil(dailySalesRate * 7));
      const targetStock = Math.ceil(
        dailySalesRate * (effectivePlanningDays + 7)
      );
      const recommendedReorderQuantity = Math.max(
        0,
        targetStock - currentQuantity
      );

      let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
      let reason = 'Stock level is healthy for the current sales rhythm.';
      let recommendation =
        'Keep monitoring weekly and keep current reorder cadence.';

      if (currentQuantity <= 0) {
        riskLevel = 'HIGH';
        reason = 'Product is out of stock right now.';
        recommendation =
          'Reorder immediately and prioritize this product in procurement.';
      } else if (
        estimatedDaysUntilStockout !== undefined &&
        estimatedDaysUntilStockout <= 7
      ) {
        riskLevel = 'HIGH';
        reason = `Estimated stockout in ${estimatedDaysUntilStockout} days based on recent sales.`;
        recommendation =
          'Trigger urgent reorder and consider temporary purchase limits.';
      } else if (
        estimatedDaysUntilStockout !== undefined &&
        estimatedDaysUntilStockout <= 21
      ) {
        riskLevel = 'MEDIUM';
        reason = `Estimated stockout in ${estimatedDaysUntilStockout} days.`;
        recommendation =
          'Plan reorder this week to avoid stockout in the next cycle.';
      } else if (dailySalesRate > 0 && currentQuantity < safetyStock) {
        riskLevel = 'MEDIUM';
        reason = 'Current stock is below the 7-day safety stock threshold.';
        recommendation =
          'Increase safety stock buffer and schedule reorder in advance.';
      }

      return {
        productId,
        productName: String(product.name ?? 'Unnamed Product'),
        currentQuantity,
        soldLastPeriod,
        dailySalesRate,
        estimatedDaysUntilStockout,
        riskLevel,
        safetyStock,
        recommendedReorderQuantity,
        reason,
        recommendation,
      };
    });

    const riskRank: Record<'LOW' | 'MEDIUM' | 'HIGH', number> = {
      HIGH: 0,
      MEDIUM: 1,
      LOW: 2,
    };

    items.sort((a, b) => {
      const byRisk = riskRank[a.riskLevel] - riskRank[b.riskLevel];
      if (byRisk !== 0) {
        return byRisk;
      }

      const aDays = a.estimatedDaysUntilStockout ?? Number.POSITIVE_INFINITY;
      const bDays = b.estimatedDaysUntilStockout ?? Number.POSITIVE_INFINITY;
      return aDays - bDays;
    });

    const summary = {
      totalProducts: items.length,
      highRiskCount: items.filter((i) => i.riskLevel === 'HIGH').length,
      mediumRiskCount: items.filter((i) => i.riskLevel === 'MEDIUM').length,
      lowRiskCount: items.filter((i) => i.riskLevel === 'LOW').length,
      totalRecommendedUnits: items.reduce(
        (acc, item) => acc + item.recommendedReorderQuantity,
        0
      ),
    };

    const result = {
      businessId,
      generatedAt: now,
      lookbackDays: effectiveLookbackDays,
      planningHorizonDays: effectivePlanningDays,
      summary,
      items,
    };

    // Cache for 5 minutes (stock levels change frequently)
    await this.cacheService.set(cacheKey, result, 300);
    return result;
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
   * Delete multiple products by IDs (bulk delete)
   */
  async deleteMany(
    ids: string[],
    businessId: string,
    databaseName: string
  ): Promise<{ deleted: number; notFound: string[] }> {
    const productModel = this.getProductModel(databaseName);

    const deleted: string[] = [];
    const notFound: string[] = [];

    // Build ObjectId-aware business filter (consistent with other methods)
    const businessFilter: Record<string, unknown> = { businessId };
    if (Types.ObjectId.isValid(businessId)) {
      businessFilter.$or = [
        { businessId },
        { businessId: new Types.ObjectId(businessId) },
      ];
      delete businessFilter.businessId;
    }

    for (const id of ids) {
      const result = await productModel.deleteOne({
        _id: id,
        ...businessFilter,
      });

      if (result.deletedCount === 0) {
        notFound.push(id);
      } else {
        deleted.push(id);
      }
    }

    return {
      deleted: deleted.length,
      notFound,
    };
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

    const expectedColumns = [
      'name',
      'description',
      'unitPrice',
      'quantity',
      'cost',
    ];
    const mappedRecords = await mapColumnsUsingAi(records, expectedColumns);

    for (const [i, record] of mappedRecords.entries()) {
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
