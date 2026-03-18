import { type BusinessUserRole } from '@/business/schemas/business-user.schema';

export type TenantContext = {
  businessId: string;
  databaseName: string;
  membershipRole: BusinessUserRole | 'platform-admin';
};

export type TenantMetadata = {
  businessName: string;
  ownerUserId: string;
  provisionedAt: Date;
  version: number;
};
