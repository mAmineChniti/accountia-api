import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthenticatedRequest } from '@/auth/types/auth.types';
import { Role } from '@/auth/enums/role.enum';

@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const user = request.user;
    if (!user) {
      throw new UnauthorizedException('No authenticated user found');
    }
    if (
      user.role !== Role.PLATFORM_OWNER &&
      user.role !== Role.PLATFORM_ADMIN
    ) {
      throw new ForbiddenException('Insufficient permissions');
    }
    return true;
  }
}
