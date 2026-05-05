import {
  createParamDecorator,
  type ExecutionContext,
  InternalServerErrorException,
} from '@nestjs/common';
import { type AuthenticatedRequest } from '@/auth/types/auth.types';
import { type TenantContext } from '@/common/tenant/tenant.types';

export const CurrentTenant = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): TenantContext => {
    const request = ctx.switchToHttp().getRequest<AuthenticatedRequest>();

    if (!request.tenant) {
      throw new InternalServerErrorException(
        'CurrentTenant used without tenant context guard'
      );
    }

    return request.tenant;
  }
);
