import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection, Model, Schema } from 'mongoose';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { type TenantMetadata } from '@/common/tenant/tenant.types';

@Injectable()
export class TenantConnectionService {
  private static readonly TENANT_METADATA_COLLECTION = 'tenant_metadata';
  private static readonly TENANT_USERS_COLLECTION = 'tenant_users';
  private readonly tenantModelCache = new Map<string, unknown>();

  constructor(@InjectConnection() private readonly connection: Connection) {}

  async initializeTenantDatabase(params: {
    databaseName: string;
    businessName: string;
    ownerUserId: string;
    assignedBy: string;
  }): Promise<void> {
    const tenantDb = this.connection.useDb(params.databaseName, {
      useCache: true,
    });

    await this.createCollectionIfMissing(
      tenantDb,
      TenantConnectionService.TENANT_METADATA_COLLECTION
    );

    await this.createCollectionIfMissing(
      tenantDb,
      TenantConnectionService.TENANT_USERS_COLLECTION
    );

    // Create indexes for the users collection
    const usersCollection = tenantDb.collection(
      TenantConnectionService.TENANT_USERS_COLLECTION
    );
    await usersCollection.createIndex({ userId: 1 }, { unique: true });
    await usersCollection.createIndex({ isActive: 1 });

    const metadataCollection = tenantDb.collection(
      TenantConnectionService.TENANT_METADATA_COLLECTION
    );

    await metadataCollection.updateOne(
      { key: 'tenant_info' },
      {
        $set: {
          key: 'tenant_info',
          businessName: params.businessName,
          ownerUserId: params.ownerUserId,
          provisionedAt: new Date(),
          version: 1,
        },
      },
      { upsert: true }
    );

    await metadataCollection.createIndex({ key: 1 }, { unique: true });

    await this.upsertTenantUser(params.databaseName, {
      userId: params.ownerUserId,
      role: BusinessUserRole.OWNER,
      assignedBy: params.assignedBy,
      isActive: true,
    });
  }

  async upsertTenantUser(
    databaseName: string,
    params: {
      userId: string;
      role: BusinessUserRole;
      assignedBy: string;
      isActive: boolean;
    }
  ): Promise<void> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });

    await this.createCollectionIfMissing(
      tenantDb,
      TenantConnectionService.TENANT_USERS_COLLECTION
    );

    const usersCollection = tenantDb.collection(
      TenantConnectionService.TENANT_USERS_COLLECTION
    );

    await usersCollection.updateOne(
      { userId: params.userId },
      {
        $set: {
          userId: params.userId,
          role: params.role,
          assignedBy: params.assignedBy,
          isActive: params.isActive,
          updatedAt: new Date(),
        },
        $setOnInsert: {
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );
  }

  async deactivateTenantUser(
    databaseName: string,
    userId: string,
    assignedBy: string
  ): Promise<void> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });

    const usersCollection = tenantDb.collection(
      TenantConnectionService.TENANT_USERS_COLLECTION
    );

    await usersCollection.updateOne(
      { userId },
      {
        $set: {
          isActive: false,
          assignedBy,
          updatedAt: new Date(),
        },
      }
    );
  }

  async dropTenantDatabase(databaseName: string): Promise<void> {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    await tenantDb.dropDatabase();

    // Clear cached models for the dropped database
    const keysToDelete: string[] = [];
    for (const cacheKey of this.tenantModelCache.keys()) {
      if (cacheKey.startsWith(`${databaseName}:`)) {
        keysToDelete.push(cacheKey);
      }
    }
    for (const key of keysToDelete) this.tenantModelCache.delete(key);
  }

  async getTenantMetadata(
    databaseName: string
  ): Promise<TenantMetadata | undefined> {
    const metadataCollection = this.getTenantCollection<{
      key: string;
      businessName: string;
      ownerUserId: string;
      provisionedAt: Date;
      version: number;
    }>(databaseName, TenantConnectionService.TENANT_METADATA_COLLECTION);

    const metadata = await metadataCollection.findOne({ key: 'tenant_info' });
    if (!metadata) {
      return undefined;
    }

    return {
      businessName: metadata.businessName,
      ownerUserId: metadata.ownerUserId,
      provisionedAt: metadata.provisionedAt,
      version: metadata.version,
    };
  }

  getTenantCollection<TDocument extends object>(
    databaseName: string,
    collectionName: string
  ) {
    const tenantDb = this.connection.useDb(databaseName, { useCache: true });
    return tenantDb.collection<TDocument>(collectionName);
  }

  getTenantModel<TDocument extends object>(params: {
    databaseName: string;
    modelName: string;
    schema: Schema<TDocument>;
    collectionName?: string;
  }): Model<TDocument> {
    const cacheKey = `${params.databaseName}:${params.modelName}`;
    const cachedModel = this.tenantModelCache.get(cacheKey);
    if (cachedModel) {
      return cachedModel as Model<TDocument>;
    }

    const tenantDb = this.connection.useDb(params.databaseName, {
      useCache: true,
    });

    const existingModel = tenantDb.models[params.modelName] as
      | Model<TDocument>
      | undefined;
    if (existingModel) {
      this.tenantModelCache.set(cacheKey, existingModel as unknown);
      return existingModel;
    }

    const model = tenantDb.model<TDocument>(
      params.modelName,
      params.schema,
      params.collectionName
    );
    this.tenantModelCache.set(cacheKey, model as unknown);
    return model;
  }

  private async createCollectionIfMissing(
    tenantDb: Connection,
    collectionName: string
  ): Promise<void> {
    try {
      await tenantDb.createCollection(collectionName);
    } catch (error) {
      // Check for MongoDB "collection already exists" error (code 48)
      const mongoError = error as { code?: number };
      if (
        error &&
        typeof error === 'object' &&
        'code' in error &&
        mongoError.code !== 48
      ) {
        throw new InternalServerErrorException(
          `Failed to create tenant collection: ${collectionName}`
        );
      }
    }
  }
}
