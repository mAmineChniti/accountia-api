import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { type AuthenticatedRequest } from '@/auth/types/auth.types';
import { TenantContextService } from '@/common/tenant/tenant-context.service';
import { Types } from 'mongoose';

@Injectable()
export class TenantContextGuard implements CanActivate {
  constructor(private readonly tenantContextService: TenantContextService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const user = request.user;

    if (!user) {
      throw new UnauthorizedException('User context is missing');
    }

    const businessIdFromParam =
      typeof request.params?.id === 'string' ? request.params.id : undefined;

    const businessIdFromHeaderRaw = request.headers['x-business-id'];
    let businessIdFromHeader: string | undefined;
    if (typeof businessIdFromHeaderRaw === 'string') {
      businessIdFromHeader = businessIdFromHeaderRaw;
    } else if (Array.isArray(businessIdFromHeaderRaw)) {
      businessIdFromHeader = businessIdFromHeaderRaw.at(0);
    }

    const businessId = businessIdFromParam ?? businessIdFromHeader;

    if (!businessId) {
      throw new BadRequestException(
        'Business context is required via route param or x-business-id header'
      );
    }

    // Validate businessId format
    if (!Types.ObjectId.isValid(businessId)) {
      throw new BadRequestException('Invalid businessId format');
    }

    request.tenant = await this.tenantContextService.resolveTenantContext(
      user,
      businessId
    );

    return true;
  }
}
