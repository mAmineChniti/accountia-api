import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { type AuthenticatedRequest } from '@/auth/types/auth.types';
import { TenantContextService } from '@/common/tenant/tenant-context.service';
import { Role } from '@/auth/enums/role.enum';
import { Types } from 'mongoose';

@Injectable()
export class TenantContextGuard implements CanActivate {
  constructor(private readonly tenantContextService: TenantContextService) {}

  private static getStringValue(value: unknown): string | undefined {
    return typeof value === 'string' ? value : undefined;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const user = request.user;

    if (!user) {
      throw new UnauthorizedException('User context is missing');
    }

    const isGetRequest = request.method === 'GET';

    // For GET requests: use query params only
    // For other requests (POST, PATCH, etc.): use body only
    const businessId = TenantContextGuard.getStringValue(
      isGetRequest
        ? (request.query as Record<string, unknown>)?.businessId
        : (request.body as Record<string, unknown>)?.businessId
    );

    const isPlatformUser = [Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN].includes(
      user.role
    );

    if (!businessId) {
      if (isPlatformUser) {
        request.tenant = {
          businessId: '',
          databaseName: '',
          membershipRole: 'platform-admin',
        };
        return true;
      }
      throw new BadRequestException(
        `Business context is required (provide businessId in ${isGetRequest ? 'query params' : 'request body'})`
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
