import {
  createParamDecorator,
  type ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import {
  type UserPayload,
  type AuthenticatedRequest,
} from '@/auth/types/auth.types';

export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): UserPayload => {
    const request = ctx.switchToHttp().getRequest<AuthenticatedRequest>();

    if (!request.user) {
      throw new UnauthorizedException('CurrentUser used on unprotected route');
    }

    return request.user;
  }
);
