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

  private static resolveBusinessIdFromRequest(
    request: AuthenticatedRequest,
    isGetRequest: boolean,
    isFileImport: boolean
  ): string | undefined {
    const queryBusinessId = TenantContextGuard.getStringValue(
      (request.query as Record<string, unknown>)?.businessId
    );
    const routeBusinessId = TenantContextGuard.getStringValue(
      (request.params as Record<string, unknown>)?.businessId
    );
    const routeId = TenantContextGuard.getStringValue(
      (request.params as Record<string, unknown>)?.id
    );
    const bodyBusinessId = TenantContextGuard.getStringValue(
      (request.body as Record<string, unknown>)?.businessId
    );

    // Priority order: explicit query, route businessId, body for mutations, then route id fallback.
    if (queryBusinessId) {
      return queryBusinessId;
    }

    if (routeBusinessId) {
      return routeBusinessId;
    }

    if ((!isGetRequest || isFileImport) && bodyBusinessId)
      return bodyBusinessId;

    if (routeId) {
      return routeId;
    }

    return undefined;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const user = request.user;

    if (!user) {
      throw new UnauthorizedException('User context is missing');
    }

    const isGetRequest = request.method === 'GET';
    const requestPath =
      typeof request.path === 'string'
        ? request.path
        : new URL(request.url, 'http://localhost').pathname;
    const isFileImport = requestPath.includes('/import');

    const businessId = TenantContextGuard.resolveBusinessIdFromRequest(
      request,
      isGetRequest,
      isFileImport
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
        'Business context is required (provide businessId in body or query)'
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
