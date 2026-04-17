import {
  Injectable,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Role } from '@/auth/enums/role.enum';
import { type UserPayload } from '@/auth/types/auth.types';
import { Business } from '@/business/schemas/business.schema';
import { BusinessUser } from '@/business/schemas/business-user.schema';
import { type TenantContext } from '@/common/tenant/tenant.types';
import { CacheService } from '@/redis/cache.service';

const CACHE_TTL_SECONDS = 300; // 5 minutes

@Injectable()
export class TenantContextService {
  constructor(
    @InjectModel(Business.name)
    private readonly businessModel: Model<Business>,
    @InjectModel(BusinessUser.name)
    private readonly businessUserModel: Model<BusinessUser>,
    private readonly cacheService: CacheService
  ) {}

  async resolveTenantContext(
    user: UserPayload,
    businessId: string
  ): Promise<TenantContext> {
    // Cache key includes user and business to handle role changes
    const cacheKey = `tenant:context:${user.id}:${businessId}`;

    // Try to get from cache first
    const cached = await this.cacheService.get<TenantContext>(cacheKey);
    if (cached) {
      return cached;
    }

    const business = await this.businessModel
      .findById(businessId)
      .select('databaseName status');

    if (!business) {
      throw new NotFoundException('Business not found');
    }

    if (business.status !== 'approved') {
      throw new ForbiddenException('Business is not active');
    }

    let result: TenantContext;

    if (
      user.role === Role.PLATFORM_OWNER ||
      user.role === Role.PLATFORM_ADMIN
    ) {
      result = {
        businessId: business._id.toString(),
        databaseName: business.databaseName,
        membershipRole: 'platform-admin',
      };
    } else {
      const membership = await this.businessUserModel
        .findOne({
          businessId,
          userId: user.id,
        })
        .select('role');

      if (!membership) {
        throw new ForbiddenException('You do not have access to this business');
      }

      result = {
        businessId: business._id.toString(),
        databaseName: business.databaseName,
        membershipRole: membership.role,
      };
    }

    // Cache the result
    await this.cacheService.set(cacheKey, result, CACHE_TTL_SECONDS);
    return result;
  }

  /**
   * Invalidate cached tenant context for a user
   * Call this when user roles change or business membership changes
   */
  async invalidateContext(userId: string, businessId: string): Promise<void> {
    const cacheKey = `tenant:context:${userId}:${businessId}`;
    await this.cacheService.del(cacheKey);
  }

  /**
   * Invalidate all contexts for a business (when business status changes)
   */
  async invalidateBusinessContexts(businessId: string): Promise<void> {
    await this.cacheService.delPattern(`tenant:context:*:${businessId}`);
  }
}
