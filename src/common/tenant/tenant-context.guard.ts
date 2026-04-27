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
    const requestPath =
      typeof request.path === 'string'
        ? request.path
        : new URL(request.url, 'http://localhost').pathname;
    const isFileImport = requestPath.includes('/import');

    let businessId: string | undefined;

    if (isGetRequest) {
      // GET requests: extract businessId from query params
      businessId = TenantContextGuard.getStringValue(
        (request.query as Record<string, unknown>)?.businessId
      );
    } else if (isFileImport) {
      // File import endpoints: extract businessId from query params
      businessId = TenantContextGuard.getStringValue(
        (request.query as Record<string, unknown>)?.businessId
      );
    } else {
      // Other mutations (POST, PATCH, DELETE): prefer body, fallback to query
      businessId = TenantContextGuard.getStringValue(
        (request.body as Record<string, unknown>)?.businessId
      );
      businessId ??= TenantContextGuard.getStringValue(
        (request.query as Record<string, unknown>)?.businessId
      );
    }

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

      // Auto-resolve from the user's business membership when not provided.
      // Multipart endpoints can't read body fields at guard-time (FileInterceptor
      // runs after guards), so falling back to the user's membership keeps those
      // endpoints working without forcing the client to send businessId.
      const resolved = await this.tenantContextService.resolveUserBusinessId(
        user.id
      );

      if (!resolved) {
        throw new BadRequestException(
          'Business context is required (provide businessId in body or query)'
        );
      }

      businessId = resolved;
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
