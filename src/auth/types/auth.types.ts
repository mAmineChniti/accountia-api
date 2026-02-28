import { type Request } from 'express';
import { Role } from '@/users/schemas/user.schema';

export interface UserPayload {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  phoneNumber?: string;
  isAdmin: boolean;
  role: Role; 
}

export interface AuthenticatedRequest extends Request {
  user?: UserPayload;
}