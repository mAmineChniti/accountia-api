import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection, Model } from 'mongoose';
import { Vendor, VendorSchema } from './schemas/vendor.schema';
import {
  CreateVendorDto,
  UpdateVendorDto,
  VendorResponseDto,
  VendorListResponseDto,
} from './dto/vendor.dto';

@Injectable()
export class VendorsService {
  constructor(@InjectConnection() private connection: Connection) {}

  private getVendorModel(databaseName: string): Model<Vendor> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    try { return tenantDb.model<Vendor>(Vendor.name); }
    catch { return tenantDb.model<Vendor>(Vendor.name, VendorSchema); }
  }

  async create(
    businessId: string,
    databaseName: string,
    dto: CreateVendorDto
  ): Promise<VendorResponseDto> {
    const model = this.getVendorModel(databaseName);
    const { businessId: _, ...data } = dto;
    void _;
    const vendor = new model({ businessId, ...data });
    await vendor.save();
    return this.formatResponse(vendor);
  }

  async findByBusiness(
    businessId: string,
    databaseName: string,
    page = 1,
    limit = 10,
    search?: string
  ): Promise<VendorListResponseDto> {
    const model = this.getVendorModel(databaseName);
    const conditions: Record<string, unknown> = { businessId };

    let query = model.find({ ...conditions });
    let countFilter: Record<string, unknown> = { ...conditions };

    if (search) {
      const searchConditions = { $or: [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { contactName: { $regex: search, $options: 'i' } },
      ]};
      query = query.or([
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { contactName: { $regex: search, $options: 'i' } },
      ]);
      countFilter = { ...conditions, ...searchConditions };
    }

    const [total, vendors] = await Promise.all([
      model.countDocuments(countFilter),
      query.sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
    ]);

    return {
      vendors: (vendors as Vendor[]).map((v) => this.formatResponse(v)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  async findById(id: string, businessId: string, databaseName: string): Promise<VendorResponseDto> {
    const model = this.getVendorModel(databaseName);
    const vendor = await model.findById(id);
    if (!vendor) throw new NotFoundException('Vendor not found');
    if (String(vendor.businessId) !== businessId) throw new ForbiddenException('Access denied');
    return this.formatResponse(vendor);
  }

  async update(id: string, businessId: string, databaseName: string, dto: UpdateVendorDto): Promise<VendorResponseDto> {
    const model = this.getVendorModel(databaseName);
    const vendor = await model.findById(id);
    if (!vendor) throw new NotFoundException('Vendor not found');
    if (String(vendor.businessId) !== businessId) throw new ForbiddenException('Access denied');
    const { businessId: _, ...updateData } = dto;
    void _;
    const updated = await model.findByIdAndUpdate(id, updateData, { returnDocument: 'after', runValidators: true });
    if (!updated) throw new NotFoundException('Vendor not found');
    return this.formatResponse(updated);
  }

  async delete(id: string, businessId: string, databaseName: string): Promise<void> {
    const model = this.getVendorModel(databaseName);
    const vendor = await model.findById(id);
    if (!vendor) throw new NotFoundException('Vendor not found');
    if (String(vendor.businessId) !== businessId) throw new ForbiddenException('Access denied');
    await model.findByIdAndDelete(id);
  }

  async incrementStats(id: string, databaseName: string, amount: number): Promise<void> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    try {
      const model = tenantDb.model<Vendor>(Vendor.name);
      await model.findByIdAndUpdate(id, { $inc: { totalOrders: 1, totalSpend: amount } });
    } catch {
      // Vendor model may not be registered yet
    }
  }

  private formatResponse(vendor: Vendor): VendorResponseDto {
    return {
      id: String(vendor._id),
      businessId: String(vendor.businessId),
      name: vendor.name,
      contactName: vendor.contactName,
      email: vendor.email,
      phone: vendor.phone,
      address: vendor.address,
      taxId: vendor.taxId,
      website: vendor.website,
      paymentTermsDays: vendor.paymentTermsDays ?? 30,
      status: vendor.status,
      notes: vendor.notes,
      totalOrders: vendor.totalOrders ?? 0,
      totalSpend: vendor.totalSpend ?? 0,
      rating: vendor.rating,
      createdAt: vendor.createdAt,
      updatedAt: vendor.updatedAt,
    };
  }
}
