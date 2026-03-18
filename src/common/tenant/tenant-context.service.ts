import {
  Injectable,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Role } from '@/auth/enums/role.enum';
import { type UserPayload } from '@/auth/types/auth.types';
import {
  Business,
  type BusinessDocument,
} from '@/business/schemas/business.schema';
import {
  BusinessUser,
  type BusinessUserDocument,
} from '@/business/schemas/business-user.schema';
import { type TenantContext } from '@/common/tenant/tenant.types';

@Injectable()
export class TenantContextService {
  constructor(
    @InjectModel(Business.name)
    private readonly businessModel: Model<BusinessDocument>,
    @InjectModel(BusinessUser.name)
    private readonly businessUserModel: Model<BusinessUserDocument>
  ) {}

  async resolveTenantContext(
    user: UserPayload,
    businessId: string
  ): Promise<TenantContext> {
    const business = await this.businessModel
      .findById(businessId)
      .select('databaseName isActive status');

    if (!business) {
      throw new NotFoundException('Business not found');
    }

    if (!business.isActive || business.status !== 'approved') {
      throw new ForbiddenException('Business is not active');
    }

    if (
      user.role === Role.PLATFORM_OWNER ||
      user.role === Role.PLATFORM_ADMIN
    ) {
      return {
        businessId: business._id.toString(),
        databaseName: business.databaseName,
        membershipRole: 'platform-admin',
      };
    }

    const membership = await this.businessUserModel
      .findOne({
        businessId,
        userId: user.id,
        isActive: true,
      })
      .select('role');

    if (!membership) {
      throw new ForbiddenException('You do not have access to this business');
    }

    return {
      businessId: business._id.toString(),
      databaseName: business.databaseName,
      membershipRole: membership.role,
    };
  }
}
