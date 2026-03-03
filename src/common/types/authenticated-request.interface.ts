import { type Request } from 'express';
import { type UserPayload } from './user-payload.interface';

export interface AuthenticatedRequest extends Request {
  user?: UserPayload;
}
