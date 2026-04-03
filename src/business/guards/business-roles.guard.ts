import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import type { AuthenticatedRequest } from '@/auth/types/auth.types';

export const BUSINESS_ROLES_KEY = 'business_roles';

/**
 * Decorator to specify allowed business-level roles for an endpoint.
 * Must be used with BusinessRolesGuard.
 * @example @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
 */
export const BusinessRoles = (...roles: BusinessUserRole[]) =>
  SetMetadata(BUSINESS_ROLES_KEY, roles);

/**
 * Guard that validates user has required business-level roles.
 * Works in conjunction with TenantContextGuard which provides membershipRole.
 * Use with @BusinessRoles decorator to specify allowed roles.
 */
@Injectable()
export class BusinessRolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const allowedRoles = this.reflector.getAllAndOverride<BusinessUserRole[]>(
      BUSINESS_ROLES_KEY,
      [context.getHandler(), context.getClass()]
    );

    // If no roles are specified, allow access (guard is not being used)
    if (!allowedRoles || allowedRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const tenant = request.tenant;

    if (!tenant) {
      throw new ForbiddenException('No tenant context found');
    }

    // Platform admins always have access
    if (tenant.membershipRole === 'platform-admin') {
      return true;
    }

    // Check if user's business role is in allowed roles
    if (!allowedRoles.includes(tenant.membershipRole)) {
      throw new ForbiddenException(
        `This action requires one of the following roles: ${allowedRoles.join(', ')}`
      );
    }

    return true;
  }
}
