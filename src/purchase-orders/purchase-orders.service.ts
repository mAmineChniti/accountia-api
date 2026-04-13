import { Injectable, NotFoundException, ForbiddenException, BadRequestException } from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection, Model } from 'mongoose';
import { PurchaseOrder, PurchaseOrderSchema, PurchaseOrderStatus } from './schemas/purchase-order.schema';
import {
  CreatePurchaseOrderDto, UpdatePurchaseOrderDto, ReceiveGoodsDto, ApprovePODto,
  PurchaseOrderResponseDto, PurchaseOrderListResponseDto,
} from './dto/purchase-order.dto';
import { VendorsService } from '@/vendors/vendors.service';

@Injectable()
export class PurchaseOrdersService {
  constructor(
    @InjectConnection() private connection: Connection,
    private readonly vendorsService: VendorsService
  ) {}

  private getPOModel(databaseName: string): Model<PurchaseOrder> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    try { return tenantDb.model<PurchaseOrder>(PurchaseOrder.name); }
    catch { return tenantDb.model<PurchaseOrder>(PurchaseOrder.name, PurchaseOrderSchema); }
  }

  private generatePoNumber(): string {
    return `PO-${Date.now()}-${Math.random().toString(36).slice(2, 5).toUpperCase()}`;
  }

  async create(
    businessId: string, databaseName: string, dto: CreatePurchaseOrderDto, userId: string
  ): Promise<PurchaseOrderResponseDto> {
    const model = this.getPOModel(databaseName);
    const { businessId: _, ...data } = dto;
    void _;
    const po = new model({
      businessId,
      ...data,
      orderDate: new Date(data.orderDate),
      expectedDeliveryDate: data.expectedDeliveryDate ? new Date(data.expectedDeliveryDate) : undefined,
      poNumber: this.generatePoNumber(),
      status: PurchaseOrderStatus.DRAFT,
      createdBy: userId,
      lastStatusChangeAt: new Date(),
    });
    await po.save();
    return this.formatResponse(po);
  }

  async findByBusiness(
    businessId: string, databaseName: string, page = 1, limit = 10, status?: string
  ): Promise<PurchaseOrderListResponseDto> {
    const model = this.getPOModel(databaseName);
    const conditions: Record<string, unknown> = { businessId };
    if (status) conditions.status = status;

    const [total, pos] = await Promise.all([
      model.countDocuments(conditions),
      model.find(conditions).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
    ]);

    return {
      purchaseOrders: (pos as PurchaseOrder[]).map((p) => this.formatResponse(p)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  async findById(id: string, businessId: string, databaseName: string): Promise<PurchaseOrderResponseDto> {
    const model = this.getPOModel(databaseName);
    const po = await model.findById(id);
    if (!po) throw new NotFoundException('Purchase order not found');
    if (String(po.businessId) !== businessId) throw new ForbiddenException('Access denied');
    return this.formatResponse(po);
  }

  async update(id: string, businessId: string, databaseName: string, dto: UpdatePurchaseOrderDto): Promise<PurchaseOrderResponseDto> {
    const model = this.getPOModel(databaseName);
    const po = await model.findById(id);
    if (!po) throw new NotFoundException('Purchase order not found');
    if (String(po.businessId) !== businessId) throw new ForbiddenException('Access denied');
    if (po.status !== PurchaseOrderStatus.DRAFT) throw new BadRequestException('Only draft POs can be edited');

    const { businessId: _, ...updateData } = dto;
    void _;
    const updated = await model.findByIdAndUpdate(id, updateData, { returnDocument: 'after', runValidators: true });
    if (!updated) throw new NotFoundException('Purchase order not found');
    return this.formatResponse(updated);
  }

  async submit(id: string, businessId: string, databaseName: string): Promise<PurchaseOrderResponseDto> {
    const model = this.getPOModel(databaseName);
    const po = await model.findById(id);
    if (!po) throw new NotFoundException('Purchase order not found');
    if (String(po.businessId) !== businessId) throw new ForbiddenException('Access denied');
    if (po.status !== PurchaseOrderStatus.DRAFT) throw new BadRequestException('Only draft POs can be submitted');

    po.status = PurchaseOrderStatus.PENDING_APPROVAL;
    po.lastStatusChangeAt = new Date();
    await po.save();
    return this.formatResponse(po);
  }

  async approve(id: string, businessId: string, databaseName: string, dto: ApprovePODto, userId: string): Promise<PurchaseOrderResponseDto> {
    const model = this.getPOModel(databaseName);
    const po = await model.findById(id);
    if (!po) throw new NotFoundException('Purchase order not found');
    if (String(po.businessId) !== businessId) throw new ForbiddenException('Access denied');
    if (po.status !== PurchaseOrderStatus.PENDING_APPROVAL) throw new BadRequestException('Only pending POs can be approved');

    if (dto.rejectionReason) {
      po.status = PurchaseOrderStatus.CANCELLED;
      po.rejectionReason = dto.rejectionReason;
    } else {
      po.status = PurchaseOrderStatus.APPROVED;
      po.approvedBy = userId;
      po.approvedAt = new Date();
    }
    po.lastStatusChangeAt = new Date();
    await po.save();
    return this.formatResponse(po);
  }

  async receiveGoods(id: string, businessId: string, databaseName: string, dto: ReceiveGoodsDto): Promise<PurchaseOrderResponseDto> {
    const model = this.getPOModel(databaseName);
    const po = await model.findById(id);
    if (!po) throw new NotFoundException('Purchase order not found');
    if (String(po.businessId) !== businessId) throw new ForbiddenException('Access denied');
    if (![PurchaseOrderStatus.APPROVED, PurchaseOrderStatus.SENT, PurchaseOrderStatus.PARTIALLY_RECEIVED].includes(po.status)) {
      throw new BadRequestException('PO must be approved/sent before receiving goods');
    }

    for (const lineItem of po.lineItems) {
      const receivedQty = dto.receivedQuantities[String(lineItem._id)];
      if (receivedQty !== undefined) {
        lineItem.receivedQuantity = Math.min(lineItem.orderedQuantity, (lineItem.receivedQuantity ?? 0) + receivedQty);
      }
    }

    const allReceived = po.lineItems.every((item) => item.receivedQuantity >= item.orderedQuantity);
    const anyReceived = po.lineItems.some((item) => (item.receivedQuantity ?? 0) > 0);

    if (allReceived) {
      po.status = PurchaseOrderStatus.RECEIVED;
      po.receivedAt = new Date();
      await this.vendorsService.incrementStats(String(po.vendorId), databaseName, po.totalAmount);
    } else if (anyReceived) {
      po.status = PurchaseOrderStatus.PARTIALLY_RECEIVED;
    }

    po.lastStatusChangeAt = new Date();
    await po.save();
    return this.formatResponse(po);
  }

  async delete(id: string, businessId: string, databaseName: string): Promise<void> {
    const model = this.getPOModel(databaseName);
    const po = await model.findById(id);
    if (!po) throw new NotFoundException('Purchase order not found');
    if (String(po.businessId) !== businessId) throw new ForbiddenException('Access denied');
    if (po.status !== PurchaseOrderStatus.DRAFT) throw new BadRequestException('Only draft POs can be deleted');
    await model.findByIdAndDelete(id);
  }

  private formatResponse(po: PurchaseOrder): PurchaseOrderResponseDto {
    return {
      id: String(po._id),
      businessId: String(po.businessId),
      poNumber: po.poNumber,
      vendorId: String(po.vendorId),
      vendorName: po.vendorName,
      status: po.status,
      lineItems: po.lineItems.map((item) => ({
        id: String(item._id),
        productId: item.productId ? String(item.productId) : undefined,
        productName: item.productName,
        orderedQuantity: item.orderedQuantity,
        receivedQuantity: item.receivedQuantity,
        unitPrice: item.unitPrice,
        amount: item.amount,
        description: item.description,
      })) as never[],
      totalAmount: po.totalAmount,
      currency: po.currency,
      orderDate: po.orderDate instanceof Date ? po.orderDate.toISOString() : String(po.orderDate),
      expectedDeliveryDate: po.expectedDeliveryDate?.toISOString(),
      receivedAt: po.receivedAt?.toISOString(),
      notes: po.notes,
      createdBy: po.createdBy ? String(po.createdBy) : undefined,
      approvedBy: po.approvedBy ? String(po.approvedBy) : undefined,
      approvedAt: po.approvedAt?.toISOString(),
      rejectionReason: po.rejectionReason,
      lastStatusChangeAt: po.lastStatusChangeAt?.toISOString(),
      createdAt: po.createdAt,
      updatedAt: po.updatedAt,
    };
  }
}
