import { type Request } from 'express';

export interface UserPayload {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  phoneNumber?: string;
}

export interface AuthenticatedRequest extends Request {
  user?: UserPayload;
}
