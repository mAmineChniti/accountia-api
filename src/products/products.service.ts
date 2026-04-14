import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  Logger,
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
const pdf = require('pdf-parse');
import { parseFile } from '@/common/utils/file-parser.util';
import { fixStructureWithAi } from '@/common/utils/ai-structure-fixer.util';
import { Role } from '@/auth/enums/role.enum';

@Injectable()
export class ProductsService {
  private readonly logger = new Logger(ProductsService.name);

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
          throw new Error('Le champ "name" (Nom du produit) est obligatoire.');
        }
        if (!description) {
          throw new Error('Le champ "description" est obligatoire.');
        }

        const parsedUnitPrice = this.parseNumberField(unitPriceRaw);
        if (Number.isNaN(parsedUnitPrice) || parsedUnitPrice < 0) {
          throw new Error(
            'Le champ "unitPrice" (Prix) doit être un nombre positif valide.'
          );
        }

        const parsedQuantity = this.parseNumberField(quantityRaw);
        if (Number.isNaN(parsedQuantity) || parsedQuantity < 0) {
          throw new Error(
            'Le champ "quantity" (Quantité) doit être un nombre positif valide.'
          );
        }

        const costRaw = record.cost;
        const parsedCost = this.parseNumberField(costRaw);
        if (Number.isNaN(parsedCost) || parsedCost < 0) {
          // Default cost to 0 if not provided or invalid
        }

        // ✅ SMART UPSERT LOGIC
        // Search for existing product by name (case-insensitive) for this business
        let product = await productModel.findOne({
          businessId,
          name: { $regex: new RegExp(`^${name.trim()}$`, 'i') },
        });

        if (product) {
          // UPDATE Existing Product
          this.logger.debug(`Import: Updating existing product "${name}"`);
          product.description = description.trim();
          product.unitPrice = parsedUnitPrice;
          product.cost = Number.isNaN(parsedCost) ? product.cost : parsedCost;
          // For quantity, we overwrite with the new value (standard for inventory sync)
          product.quantity = parsedQuantity;
          await product.save();
        } else {
          // CREATE New Product
          this.logger.debug(`Import: Creating new product "${name}"`);
          product = new productModel({
            businessId,
            name: name.trim(),
            description: description.trim(),
            unitPrice: parsedUnitPrice,
            cost: Number.isNaN(parsedCost) ? 0 : parsedCost,
            quantity: parsedQuantity || 0,
          });
          await product.save();
        }

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

  /**
   * AI Powered PDF Import
   */
  async importProductsAi(
    businessId: string,
    databaseName: string,
    pdfBuffer: Buffer
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    try {
      const data = await pdf(pdfBuffer);
      const text = data.text;

      const prompt = `You are an expert data extractor. Extract products from the following text extracted from a PDF.
Return ONLY a valid JSON array of objects with these keys: "name", "description", "unitPrice", "cost", "quantity".
- "name": string
- "description": string
- "unitPrice": number
- "cost": number
- "quantity": number

If a value is missing, use sensible defaults (0 for numbers, empty string for description).
Text:
${text}`;

      let aiResponse = '';
      try {
        aiResponse = await this.callAi(prompt);
      } catch {
        throw new BadRequestException(
          "Le service IA est temporairement indisponible. Veuillez utiliser l'importation CSV classique."
        );
      }

      if (!aiResponse) {
        throw new BadRequestException(
          'Configuration IA manquante ou invalide.'
        );
      }

      const records = this.parseAiJson(aiResponse);
      if (records.length === 0) {
        throw new BadRequestException(
          "Aucun produit n'a pu être extrait du PDF."
        );
      }

      return this.importProducts(businessId, databaseName, records);
    } catch (error) {
      if (error instanceof BadRequestException) throw error;
      this.logger.error('Failed to import products with AI:', error);
      throw new BadRequestException(
        `Échec du traitement PDF : ${error.message}`
      );
    }
  }

  /**
   * Import products with AI Smart Structural Correction
   */
  async importProductsSmart(
    businessId: string,
    databaseName: string,
    fileBuffer: Buffer,
    filename: string
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    try {
      // 1. Raw parse
      const rawRecords = await parseFile(fileBuffer, filename);

      // 2. Use AI to fix structure
      const schema = {
        targetKeys: ['name', 'description', 'unitPrice', 'cost', 'quantity'],
        description: 'Product inventory items for a business',
      };

      const normalizedRecords = await fixStructureWithAi(
        rawRecords,
        schema,
        this.logger
      );

      // 3. Delegate to standard importer
      return this.importProducts(businessId, databaseName, normalizedRecords);
    } catch (error) {
      if (error instanceof BadRequestException) throw error;
      this.logger.error('Smart Import failed:', error);
      throw new BadRequestException(
        `L'IA n'a pas pu traiter ce fichier : ${error.message}`
      );
    }
  }

  /**
   * AI Powered Product Report Analysis
   */
  async generateAiReport(
    businessId: string,
    databaseName: string,
    lang = 'fr'
  ): Promise<{ summary: string }> {
    this.logger.log(
      `Generating AI report for business ${businessId} in language: ${lang}`
    );
    const normalizedLang = lang.split('-')[0].toLowerCase();
    const productModel = this.getProductModel(databaseName);
    const products = await productModel.find({ businessId }).lean();

    if (products.length === 0) {
      const emptyMsg =
        normalizedLang === 'ar'
          ? 'لم يتم العثور على منتجات لإنشاء تقرير.'
          : normalizedLang === 'en'
            ? 'No products found to generate a report.'
            : 'Aucun produit trouvé pour générer un rapport.';
      return { summary: emptyMsg };
    }

    const reportData = products.map((p) => ({
      name: p.name,
      price: p.unitPrice,
      stock: p.quantity,
    }));

    const langName =
      normalizedLang === 'ar'
        ? 'Arabic'
        : normalizedLang === 'en'
          ? 'English'
          : 'French';
    const prompt = `Analyze this inventory data for a business and provide a professional, concise strategic summary in ${langName}.
Please ensure all monetary values are expressed in TND (Tunisian Dinar).
Include:
1. Stock health (low stock alerts)
2. Revenue potential
3. 2-3 Actionable recommendations.

Data:
${JSON.stringify(reportData, null, 2)}`;

    let summary = '';
    try {
      summary = await this.callAi(prompt);
    } catch (error) {
      this.logger.warn(`AI Analysis failed: ${error.message}`);
    }

    if (!summary) {
      // Professional fallback when AI is unavailable
      const totalStock = products.reduce(
        (sum, p) => sum + (p.quantity || 0),
        0
      );
      const totalValue = products.reduce(
        (sum, p) => sum + (p.unitPrice || 0) * (p.quantity || 0),
        0
      );
      const lowStockItems = products.filter((p) => (p.quantity || 0) < 10);

      const valFormatted = totalValue
        .toFixed(2)
        .replace('.', ',')
        .replaceAll(/\B(?=(\d{3})+(?!\d))/g, ' ');

      if (normalizedLang === 'ar') {
        summary = `تقرير المخزون الاستراتيجي
        
تحليل المخزون:
- الكتالوج: ${products.length} مراجع نشطة.
- الحجم الإجمالي: ${totalStock} وحدات في المخزون.
- قيمة المخزون: ${valFormatted} TND.

نقاط الاهتمام:
- ${lowStockItems.length} عناصر تحت عتبة إعادة التعبئة (10 وحدات).
- التوصية: خطط لإعادة التعبئة لتجنب الانقطاع.

ملاحظة: للحصول على تحليل معمق، قم بتهيئة مفتاح Gemini في إعدادات النظام.`;
      } else if (normalizedLang === 'en') {
        summary = `STRATEGIC INVENTORY REPORT

Stock Analysis:
- Catalog: ${products.length} active references.
- Total Volume: ${totalStock} units in stock.
- Inventory Value: ${valFormatted} TND.

Points of Interest:
- ${lowStockItems.length} items are below the replenishment threshold (10 units).
- Recommendation: Plan replenishment to avoid stockouts.

Note: For deep AI analysis, configure your Gemini API key in system settings.`;
      } else {
        const stockMsg =
          lowStockItems.length === 1
            ? '1 article est'
            : `${lowStockItems.length} articles sont`;

        summary = `RAPPORT D'INVENTAIRE STRATÉGIQUE

Analyse de Stock :
- Catalogue : ${products.length} références actives.
- Volume Total : ${totalStock} unités en stock.
- Valeur de l'Inventaire : ${valFormatted} TND.

Points d'Attention :
- ${stockMsg} sous le seuil de réapprovisionnement (10 unités).
- Recommandation : Planifier un réapprovisionnement pour éviter les ruptures.

Note : Pour une analyse IA approfondie, configurez votre clé API Gemini dans les paramètres système.`;
      }
    }

    return { summary };
  }

  /**
   * Universal AI Caller (Gemini priority, then OpenRouter, then Local Fallback)
   */
  private async callAi(prompt: string): Promise<string> {
    let geminiKey = process.env.GEMINI_API_KEY;
    if (geminiKey) geminiKey = geminiKey.replaceAll('"', '');
    const openRouterKey = process.env.OPENROUTER_API_KEY;

    // 1. Try Google Gemini (Direct REST API)
    if (geminiKey && geminiKey.length > 20) {
      const models = [
        'gemini-2.0-flash-lite',
        'gemini-2.0-flash-001',
        'gemini-2.0-flash',
      ];

      for (const model of models) {
        try {
          this.logger.log(
            `Attempting AI Analysis with Gemini Model: ${model}...`
          );
          const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
              }),
            }
          );

          if (response.ok) {
            const data = await response.json();
            const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
            if (text) {
              this.logger.log(`AI Analysis Successful with ${model}`);
              return text;
            }
          } else {
            const errorData = await response.json().catch(() => ({}));
            this.logger.warn(
              `Gemini API (${model}) failed: ${response.status} - ${JSON.stringify(errorData)}`
            );
            // Continue to next model
          }
        } catch (error) {
          this.logger.error(`Gemini call (${model}) error:`, error.message);
        }
      }
    }

    // 2. Try OpenRouter (Fallback)
    if (openRouterKey && openRouterKey.length > 10) {
      return this.callOpenRouter(prompt);
    }

    this.logger.warn('No valid AI API keys found. Using local fallback.');
    return '';
  }

  private async callOpenRouter(prompt: string): Promise<string> {
    const apiKey = process.env.OPENROUTER_API_KEY;
    if (!apiKey) {
      this.logger.warn('OPENROUTER_API_KEY is not set');
      return '';
    }

    const response = await fetch(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: process.env.OPENROUTER_MODEL || 'google/gemini-2.0-flash-exp',
          messages: [{ role: 'user', content: prompt }],
        }),
      }
    );

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      this.logger.warn(
        `OpenRouter API responded with status ${response.status}: ${JSON.stringify(errorData)}`
      );
      return '';
    }

    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    return data.choices?.[0]?.message?.content || '';
  }

  private parseAiJson(text: string): Record<string, unknown>[] {
    try {
      const jsonMatch = /\[[\S\s]*]/.exec(text);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]) as Record<string, unknown>[];
      }
      return [];
    } catch {
      return [];
    }
  }
}
