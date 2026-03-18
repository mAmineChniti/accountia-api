import { type Request } from 'express';
import { type Role } from '@/auth/enums/role.enum';
import { type TenantContext } from '@/common/tenant/tenant.types';

export interface UserPayload {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  phoneNumber?: string;
  role: Role;
}

export interface AuthenticatedRequest extends Request {
  user?: UserPayload;
  tenant?: TenantContext;
}
