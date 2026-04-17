import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectConnection, InjectModel } from '@nestjs/mongoose';
import { ConfigService } from '@nestjs/config';
import Stripe from 'stripe';
import { Connection, Model } from 'mongoose';
import { randomBytes } from 'node:crypto';
import { AuditEmitter } from '@/audit/audit.emitter';
import { AuditAction } from '@/audit/schemas/audit-log.schema';
import { Business } from '@/business/schemas/business.schema';
import { BusinessApplication } from '@/business/schemas/business-application.schema';
import { BusinessUser } from '@/business/schemas/business-user.schema';
import { BusinessInvite } from '@/business/schemas/business-invite.schema';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { User } from '@/users/schemas/user.schema';
import { UpdateBusinessDto } from '@/business/dto/update-business.dto';
import {
  CreateBusinessApplicationDto,
  ReviewBusinessApplicationDto,
} from '@/business/dto/business-application.dto';
import { AssignBusinessUserDto } from '@/business/dto/business-user.dto';
import {
  InviteBusinessUserDto,
  BusinessInviteResponseDto,
} from '@/business/dto/business-invite.dto';
import {
  BusinessResponseDto,
  BusinessesListResponseDto,
  BusinessApplicationListResponseDto,
} from '@/business/dto/business-response.dto';
import { BusinessApplicationResponseDto } from '@/business/dto/business-application.dto';
import { BusinessUserResponseDto } from '@/business/dto/business-user.dto';
import { BusinessStatisticsResponseDto } from '@/business/dto/business-statistics.dto';
import {
  StripeOnboardingLinkDto,
  StripeConnectStatusDto,
} from '@/business/dto/stripe-onboarding.dto';
import { Role } from '@/auth/enums/role.enum';
import { type UserPayload } from '@/auth/types/auth.types';
import { EmailService } from '@/email/email.service';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';
import { ChangeClientRoleDto } from '@/business/dto/business-user.dto';
import {
  type TenantContext,
  type TenantMetadata,
} from '@/common/tenant/tenant.types';
import { NotificationsService } from '@/notifications/notifications.service';
import { NotificationType } from '@/notifications/schemas/notification.schema';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import { Invoice } from '@/invoices/schemas/invoice.schema';
import { Product } from '@/products/schemas/product.schema';
import { ObjectId } from 'mongodb';
import { TensorflowPredictionService } from '@/business/services/tensorflow-prediction.service';
import { CacheService } from '@/redis/cache.service';

const toNumberOrZero = (value: unknown): number =>
  typeof value === 'number' ? value : 0;

const toInvoiceStatus = (
  value: unknown
): 'paid' | 'pending' | 'overdue' | undefined => {
  if (typeof value !== 'string') {
    return undefined;
  }

  const normalized = value.trim().toUpperCase();
  const invoiceStatusMap: Partial<
    Record<InvoiceStatus, 'paid' | 'pending' | 'overdue'>
  > = {
    [InvoiceStatus.PAID]: 'paid',
    [InvoiceStatus.OVERDUE]: 'overdue',
    [InvoiceStatus.DRAFT]: 'pending',
    [InvoiceStatus.ISSUED]: 'pending',
    [InvoiceStatus.VIEWED]: 'pending',
    [InvoiceStatus.PARTIAL]: 'pending',
  };

  const mappedEnumStatus = invoiceStatusMap[normalized as InvoiceStatus];
  if (mappedEnumStatus) {
    return mappedEnumStatus;
  }

  if (normalized === 'PENDING') {
    return 'pending';
  }

  return undefined;
};

@Injectable()
export class BusinessService {
  private readonly logger = new Logger(BusinessService.name);
  private readonly stripeClient?: InstanceType<typeof Stripe>;

  constructor(
    @InjectConnection() private readonly connection: Connection,
    @InjectModel(Business.name) private businessModel: Model<Business>,
    @InjectModel(BusinessApplication.name)
    private businessApplicationModel: Model<BusinessApplication>,
    @InjectModel(BusinessUser.name)
    private businessUserModel: Model<BusinessUser>,
    @InjectModel(BusinessInvite.name)
    private businessInviteModel: Model<BusinessInvite>,
    @InjectModel(User.name) private userModel: Model<User>,
    private emailService: EmailService,
    private tenantConnectionService: TenantConnectionService,
    private auditEmitter: AuditEmitter,
    private notificationsService: NotificationsService,
    private tensorflowPredictionService: TensorflowPredictionService,
    private readonly configService: ConfigService,
    private readonly cacheService: CacheService
  ) {
    const stripeSecretKey = (
      this.configService.get<string>('STRIPE_SECRET_KEY') ??
      process.env.STRIPE_SECRET_KEY
    )?.trim();
    if (stripeSecretKey) {
      this.stripeClient = new Stripe(stripeSecretKey);
    }
  }

  // Business Application Flow
  async submitBusinessApplication(
    createApplicationDto: CreateBusinessApplicationDto,
    userId: string
  ): Promise<BusinessApplicationResponseDto> {
    // Check if user already has a pending application
    const existingApplication = await this.businessApplicationModel.findOne({
      applicantId: userId,
      status: 'pending',
    });

    if (existingApplication) {
      throw new BadRequestException(
        'You already have a pending business application'
      );
    }

    const application = new this.businessApplicationModel({
      ...createApplicationDto,
      applicantId: userId,
    });

    const savedApplication = await application.save();

    // Send email notification in background to avoid delaying API response.
    const applicant = await this.userModel
      .findById(userId)
      .catch((_error) => undefined as never);
    if (applicant) {
      await this.emailService
        .sendBusinessApplicationEmail(
          applicant.email,
          `${applicant.firstName} ${applicant.lastName}`,
          savedApplication.businessName
        )
        .catch((error) => {
          this.logger.warn(
            `Background business application email failed: ${
              error instanceof Error ? error.message : String(error)
            }`
          );
        });
    }

    // Send admin notification in background as well.
    await this.notificationsService
      .createNotification({
        type: NotificationType.NEW_BUSINESS_APPLICATION,
        message: `New business application: "${savedApplication.businessName}"`,
        payload: {
          applicationId: savedApplication._id.toString(),
          businessName: savedApplication.businessName,
          applicantId: userId,
        },
      })
      .catch((error) => {
        this.logger.warn(
          `Background business application notification failed: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      });

    return {
      message:
        'Business application submitted successfully. We will review your application and respond within 2-3 business days.',
      application: {
        id: savedApplication._id.toString(),
        businessName: savedApplication.businessName,
        description: savedApplication.description,
        website: savedApplication.website,
        phone: savedApplication.phone,
        businessEmail: savedApplication.businessEmail ?? '',
        applicantId: savedApplication.applicantId,
        status: savedApplication.status,
        createdAt: savedApplication.createdAt,
      },
    };
  }

  async reviewBusinessApplication(
    applicationId: string,
    reviewDto: ReviewBusinessApplicationDto,
    reviewer: UserPayload
  ): Promise<BusinessApplicationResponseDto> {
    const reviewerId = reviewer.id;
    const application =
      await this.businessApplicationModel.findById(applicationId);
    if (!application) {
      throw new NotFoundException('Business application not found');
    }

    // only allow reviewing pending applications
    if (application.status !== 'pending') {
      throw new BadRequestException('Application has already been reviewed');
    }

    application.status = reviewDto.status;
    application.reviewedBy = reviewerId;
    application.reviewNotes = reviewDto.reviewNotes;
    application.reviewedAt = new Date();

    if (reviewDto.status === 'approved') {
      if (!application.businessEmail) {
        const applicant = await this.userModel.findById(
          application.applicantId
        );
        if (!applicant?.email) {
          throw new NotFoundException(
            'Applicant record with a valid email is required to approve this business application'
          );
        }
        application.businessEmail = applicant.email;
      }

      // Create the business within a transaction
      const databaseName = await this.generateUniqueDatabaseName(
        application.businessName
      );

      await this.provisionBusinessTenantDatabase(
        databaseName,
        application.businessName,
        application.applicantId,
        reviewerId
      );

      const business = new this.businessModel({
        name: application.businessName,
        description: application.description,
        website: application.website,
        phone: application.phone,
        email: application.businessEmail,
        databaseName,
        status: 'approved',
      });

      const session = await this.connection.startSession();
      session.startTransaction();
      let approvedBusinessName: string;
      try {
        const savedBusiness = await business.save({ session });
        application.businessId = savedBusiness._id.toString();
        approvedBusinessName = savedBusiness.name;

        await this.businessUserModel.create(
          [
            {
              businessId: savedBusiness._id.toString(),
              userId: application.applicantId,
              role: BusinessUserRole.OWNER,
              assignedBy: reviewerId,
            },
          ],
          { session }
        );

        await application.save({ session });
        await session.commitTransaction();
      } catch (error) {
        await session.abortTransaction();

        // Roll back tenant DB provisioning if business creation fails.
        await this.dropTenantDatabase(databaseName);

        throw error;
      } finally {
        await session.endSession();
      }

      // Send approval email
      const appUser = await this.userModel
        .findById(application.applicantId)
        .catch((_error) => undefined as never);
      if (appUser) {
        await this.emailService
          .sendBusinessApprovalEmail(
            appUser.email,
            `${appUser.firstName} ${appUser.lastName}`,
            approvedBusinessName
          )
          .catch((error) => {
            this.logger.warn(
              `Background business approval email failed: ${
                error instanceof Error ? error.message : String(error)
              }`
            );
          });
      }

      await this.auditEmitter
        .emitAction({
          action: AuditAction.APPROVE_BUSINESS,
          userId: reviewer.id,
          userEmail: reviewer.email ?? 'Unknown',
          userRole: reviewer.role ?? 'ADMIN',
          target: approvedBusinessName,
          details: { applicationId },
        })
        .catch((error) => {
          this.logger.warn(
            `Background approve audit emit failed: ${
              error instanceof Error ? error.message : String(error)
            }`
          );
        });
    } else {
      await application.save();

      // Send rejection email
      const appUser = await this.userModel
        .findById(application.applicantId)
        .catch((_error) => undefined as never);
      if (appUser) {
        await this.emailService
          .sendBusinessRejectionEmail(
            appUser.email,
            `${appUser.firstName} ${appUser.lastName}`,
            application.businessName,
            reviewDto.reviewNotes ?? 'No specific reason provided'
          )
          .catch((error) => {
            this.logger.warn(
              `Background business rejection email failed: ${
                error instanceof Error ? error.message : String(error)
              }`
            );
          });
      }

      await this.auditEmitter
        .emitAction({
          action: AuditAction.REJECT_BUSINESS,
          userId: reviewer.id,
          userEmail: reviewer.email ?? 'Unknown',
          userRole: reviewer.role ?? 'ADMIN',
          target: application.businessName,
          details: { applicationId, reason: reviewDto.reviewNotes },
        })
        .catch((error) => {
          this.logger.warn(
            `Background reject audit emit failed: ${
              error instanceof Error ? error.message : String(error)
            }`
          );
        });
    }

    return {
      message:
        application.status === 'approved'
          ? 'Business application approved successfully'
          : 'Business application has been rejected',
      application: {
        id: application._id.toString(),
        businessName: application.businessName,
        description: application.description,
        website: application.website,
        phone: application.phone,
        businessEmail: application.businessEmail ?? '',
        applicantId: application.applicantId,
        status: application.status,
        createdAt: application.createdAt,
      },
    };
  }

  /**
   * Auto-provisions a business for BUSINESS_OWNERs who have no linked business.
   * Uses their approved application data if found, otherwise uses their profile.
   * Returns the businessId so the frontend can immediately proceed.
   */
  async getBusinessApplications(
    userRole: Role
  ): Promise<BusinessApplicationListResponseDto> {
    if (userRole !== Role.PLATFORM_OWNER && userRole !== Role.PLATFORM_ADMIN) {
      throw new ForbiddenException(
        'Only platform administrators can view business applications'
      );
    }

    const applications = await this.businessApplicationModel
      .find()
      .select(
        'businessName description website phone businessEmail applicantId status createdAt'
      )
      .sort({ createdAt: -1 })
      .lean();

    return {
      message: 'Business applications retrieved successfully',
      applications: applications.map((app) => ({
        id: app._id.toString(),
        businessName: app.businessName,
        description: app.description,
        website: app.website,
        phone: app.phone,
        businessEmail: app.businessEmail ?? '',
        applicantId: app.applicantId,
        status: app.status,
        createdAt: app.createdAt,
      })),
    };
  }

  // Business Management
  async getBusinessById(
    businessId: string,
    userId: string,
    userRole: Role
  ): Promise<BusinessResponseDto> {
    await this.checkBusinessAccess(businessId, userId, userRole);

    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    return {
      message: 'Business retrieved successfully',
      business: {
        id: business._id.toString(),
        name: business.name,
        description: business.description,
        website: business.website,
        phone: business.phone,
        email: business.email,
        databaseName: business.databaseName,
        status: business.status,
        createdAt: business.createdAt,
        updatedAt: business.updatedAt,
      },
    };
  }

  async updateBusiness(
    businessId: string,
    updateBusinessDto: UpdateBusinessDto,
    userId: string,
    userRole: Role
  ): Promise<BusinessResponseDto> {
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    Object.assign(business, updateBusinessDto);
    const updatedBusiness = await business.save();

    return {
      message: 'Business updated successfully',
      business: {
        id: updatedBusiness._id.toString(),
        name: updatedBusiness.name,
        description: updatedBusiness.description,
        website: updatedBusiness.website,
        phone: updatedBusiness.phone,
        email: updatedBusiness.email,
        databaseName: updatedBusiness.databaseName,
        status: updatedBusiness.status,
        createdAt: updatedBusiness.createdAt,
        updatedAt: updatedBusiness.updatedAt,
      },
    };
  }

  async deleteBusiness(
    businessId: string,
    userId: string,
    userRole: Role
  ): Promise<{ message: string }> {
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    const session = await this.connection.startSession();
    session.startTransaction();
    let transactionCommitted = false;
    try {
      await this.businessUserModel.deleteMany({ businessId }, { session });
      await this.businessApplicationModel.updateMany(
        { businessId },
        { $unset: { businessId: '' } },
        { session }
      );
      await this.businessModel.findByIdAndDelete(businessId, { session });
      await session.commitTransaction();
      transactionCommitted = true;
    } catch (error) {
      if (!transactionCommitted) {
        await session.abortTransaction();
      }
      throw error;
    } finally {
      await session.endSession();
    }

    try {
      await this.tenantConnectionService.dropTenantDatabase(
        business.databaseName
      );
    } catch {
      // Best-effort cleanup: platform deletion should not be blocked if DB drop fails.
    }

    // Audit: record business deletion
    try {
      const actor = await this.userModel
        .findById(userId)
        .catch(() => undefined as never);
      await this.auditEmitter.emitAction({
        action: AuditAction.DELETE_BUSINESS,
        userId: userId,
        userEmail: actor?.email ?? 'Unknown',
        userRole: actor?.role ?? userRole ?? 'Unknown',
        target: business.name,
        details: { businessId },
      });
    } catch {
      // ignore audit errors
    }

    return { message: 'Business deleted successfully' };
  }

  async getMyBusinesses(userId: string): Promise<BusinessesListResponseDto> {
    // Find all businesses where user is OWNER or ADMIN at the business level
    let businessUsers = (await this.businessUserModel
      .find({
        userId,
        role: {
          $in: [
            BusinessUserRole.OWNER,
            BusinessUserRole.ADMIN,
            BusinessUserRole.MEMBER,
          ],
        },
      })
      .select('businessId')
      .lean()) as Array<{ businessId: string }>;

    // Rescue Logic: If user has no business linked but is approved, link it now.
    if (businessUsers.length === 0) {
      const approvedApplication = await this.businessApplicationModel.findOne({
        applicantId: userId,
        status: 'approved',
        businessId: { $exists: true, $ne: '' },
      });

      if (approvedApplication?.businessId) {
        const business = await this.businessModel.findById(
          approvedApplication.businessId
        );
        if (business) {
          await this.businessUserModel.findOneAndUpdate(
            {
              businessId: approvedApplication.businessId,
              userId,
            },
            {
              role: BusinessUserRole.OWNER,
              assignedBy: userId,
            },
            { upsert: true }
          );

          businessUsers = [{ businessId: approvedApplication.businessId }];
        }
      }
    }

    const businessIds = businessUsers.map((bu) => bu.businessId);

    if (businessIds.length === 0) {
      return {
        message: 'No businesses found',
        businesses: [],
      };
    }

    const businesses = await this.businessModel
      .find({ _id: { $in: businessIds } })
      .select('name phone status createdAt')
      .sort({ createdAt: -1 })
      .lean();

    return {
      message: 'Businesses retrieved successfully',
      businesses: businesses.map((business) => ({
        id: business._id.toString(),
        name: business.name,
        phone: business.phone,
        status: business.status,
        createdAt: business.createdAt,
      })),
    };
  }

  async getAllBusinesses(userRole: Role): Promise<BusinessesListResponseDto> {
    if (userRole !== Role.PLATFORM_OWNER && userRole !== Role.PLATFORM_ADMIN) {
      throw new ForbiddenException(
        'Only platform administrators can view all businesses'
      );
    }

    const businesses = await this.businessModel
      .find()
      .select('name phone status createdAt')
      .sort({ createdAt: -1 })
      .lean();

    return {
      message: 'Businesses retrieved successfully',
      businesses: businesses.map((business) => ({
        id: business._id.toString(),
        name: business.name,
        phone: business.phone,
        status: business.status,
        createdAt: business.createdAt,
      })),
    };
  }

  async getOtherBusinesses(): Promise<{
    message: string;
    businesses: Array<{ id: string; name: string; email: string }>;
  }> {
    const businesses = await this.businessModel
      .find()
      .select('name email')
      .sort({ name: 1 })
      .lean();

    return {
      message: 'Businesses retrieved successfully',
      businesses: businesses.map((business) => ({
        id: business._id.toString(),
        name: business.name,
        email: business.email,
      })),
    };
  }

  async getTenantMetadata(tenantContext: TenantContext): Promise<{
    message: string;
    tenant: TenantContext;
    metadata: TenantMetadata;
  }> {
    const metadata = await this.tenantConnectionService.getTenantMetadata(
      tenantContext.databaseName
    );

    if (!metadata) {
      throw new NotFoundException('Tenant metadata not found');
    }

    return {
      message: 'Tenant metadata retrieved successfully',
      tenant: tenantContext,
      metadata,
    };
  }

  // Business User Management
  async assignBusinessUser(
    businessId: string,
    assignDto: AssignBusinessUserDto,
    userId: string,
    userRole: Role
  ): Promise<BusinessUserResponseDto> {
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    const business = await this.businessModel
      .findById(businessId)
      .select('databaseName');
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Check if user is already assigned to this business
    const existingAssignment = await this.businessUserModel.findOne({
      businessId,
      userId: assignDto.userId,
    });

    if (existingAssignment) {
      throw new BadRequestException(
        'User is already assigned to this business'
      );
    }

    const businessUser = new this.businessUserModel({
      businessId,
      userId: assignDto.userId,
      role: assignDto.role,
      assignedBy: userId,
    });

    const savedBusinessUser = await businessUser.save();

    try {
      await this.tenantConnectionService.upsertTenantUser(
        business.databaseName,
        {
          userId: assignDto.userId,
          role: assignDto.role,
          assignedBy: userId,
        }
      );
    } catch {
      await this.businessUserModel.findByIdAndDelete(savedBusinessUser._id);
      throw new InternalServerErrorException(
        'Failed to sync tenant user assignment'
      );
    }

    return {
      message: 'User assigned to business successfully',
      businessUser: {
        id: savedBusinessUser._id.toString(),
        businessId: savedBusinessUser.businessId,
        userId: savedBusinessUser.userId,
        role: savedBusinessUser.role,
        assignedBy: savedBusinessUser.assignedBy,
        createdAt: savedBusinessUser.createdAt,
      },
    };
  }

  async unassignBusinessUser(
    businessId: string,
    targetUserId: string,
    userId: string,
    userRole: Role
  ): Promise<{ message: string }> {
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    const businessUser = await this.businessUserModel.findOne({
      businessId,
      userId: targetUserId,
    });

    if (!businessUser) {
      throw new NotFoundException('User is not assigned to this business');
    }

    // Don't allow unassigning the business owner
    if (businessUser.role === BusinessUserRole.OWNER) {
      throw new BadRequestException('Cannot unassign business owner');
    }

    const business = await this.businessModel
      .findById(businessId)
      .select('databaseName');
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    await this.businessUserModel.deleteOne({
      _id: businessUser._id,
    });

    try {
      await this.tenantConnectionService.deactivateTenantUser(
        business.databaseName,
        targetUserId,
        userId
      );
    } catch {
      await this.businessUserModel.create({
        businessId,
        userId: targetUserId,
        role: businessUser.role,
        assignedBy: businessUser.assignedBy,
      });
      throw new InternalServerErrorException(
        'Failed to sync tenant user unassignment'
      );
    }

    return { message: 'User unassigned from business successfully' };
  }

  // Helper methods
  private async generateUniqueDatabaseName(
    businessName: string
  ): Promise<string> {
    const slug = this.generateDatabaseSlug(businessName);

    for (let attempt = 0; attempt < 5; attempt++) {
      const suffix = `${Date.now().toString(36)}_${randomBytes(3).toString('hex')}`;
      const databaseName = `${slug}_${suffix}`.slice(0, 63);

      // Just check if it's available, no need to upsert and create dup keys
      const existing = await this.businessModel.findOne({ databaseName });

      if (!existing) {
        return databaseName;
      }
    }

    throw new InternalServerErrorException(
      'Failed to allocate a unique tenant database name'
    );
  }

  private generateDatabaseSlug(businessName: string): string {
    const slug = businessName
      .toLowerCase()
      .replaceAll(/[^\da-z]/g, '_')
      .replaceAll(/_+/g, '_')
      .replaceAll(/^_+|_+$/g, '')
      .slice(0, 40);

    return slug || 'tenant';
  }

  private async provisionBusinessTenantDatabase(
    databaseName: string,
    businessName: string,
    ownerUserId: string,
    assignedBy: string
  ): Promise<void> {
    await this.tenantConnectionService.initializeTenantDatabase({
      databaseName,
      businessName,
      ownerUserId,
      assignedBy,
    });
  }

  private async dropTenantDatabase(databaseName: string): Promise<void> {
    try {
      await this.tenantConnectionService.dropTenantDatabase(databaseName);
    } catch {
      // Best-effort cleanup: provisioning rollback should not mask root failure.
    }
  }

  public async checkBusinessAccess(
    businessId: string,
    userId: string,
    userRole: Role,
    requireOwnership = false
  ): Promise<void> {
    // Platform owners and admins can access any business
    if (userRole === Role.PLATFORM_OWNER || userRole === Role.PLATFORM_ADMIN) {
      return;
    }

    // Check if user has a role in this business
    const businessUser = await this.businessUserModel.findOne({
      businessId,
      userId,
    });

    if (!businessUser) {
      throw new ForbiddenException('You do not have access to this business');
    }

    // If ownership is required (for update/delete), owners and admins can proceed
    if (
      requireOwnership &&
      ![
        BusinessUserRole.OWNER,
        BusinessUserRole.ADMIN,
        BusinessUserRole.MEMBER,
      ].includes(businessUser.role)
    ) {
      throw new ForbiddenException(
        'Only business owners, administrators and members can access this business'
      );
    }
  }

  async getBusinessClients(
    businessId: string,
    userId: string,
    userRole: Role
  ): Promise<{ message: string; clients: Array<Record<string, unknown>> }> {
    // Check basic business access
    await this.checkBusinessAccess(businessId, userId, userRole);

    // If not platform admin/owner, ensure user is business admin/owner (not client)
    if (userRole !== Role.PLATFORM_OWNER && userRole !== Role.PLATFORM_ADMIN) {
      const businessUser = await this.businessUserModel.findOne({
        businessId,
        userId,
      });

      if (
        !businessUser ||
        (businessUser.role !== BusinessUserRole.ADMIN &&
          businessUser.role !== BusinessUserRole.OWNER)
      ) {
        throw new ForbiddenException(
          'Only business owners and admins can view client list'
        );
      }
    }

    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Find all business users with role 'client'
    const businessUsers = await this.businessUserModel
      .find({ businessId, role: BusinessUserRole.CLIENT })
      .select('userId')
      .lean();

    const clientIds = businessUsers.map((bu) => bu.userId);

    const clients = await this.userModel
      .find({ _id: { $in: clientIds } })
      .select('firstName lastName email phoneNumber role createdAt')
      .lean();

    return {
      message: 'Clients retrieved successfully',
      clients: clients.map((c) => ({
        id: c._id.toString(),
        firstName: c.firstName,
        lastName: c.lastName,
        email: c.email,
        phoneNumber: c.phoneNumber,
        createdAt: c.createdAt,
      })),
    };
  }

  async changeClientRole(
    businessId: string,
    clientId: string,
    changeRoleDto: ChangeClientRoleDto,
    userId: string,
    userRole: Role
  ): Promise<{ message: string; businessUser: Record<string, unknown> }> {
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    const businessUser = await this.businessUserModel.findOne({
      businessId,
      userId: clientId,
    });

    if (!businessUser) {
      throw new NotFoundException('User not found in this business');
    }

    businessUser.role = changeRoleDto.role;
    const updatedBusinessUser = await businessUser.save();

    return {
      message: 'Client role updated successfully',
      businessUser: {
        id: updatedBusinessUser._id.toString(),
        businessId: updatedBusinessUser.businessId,
        userId: updatedBusinessUser.userId,
        role: updatedBusinessUser.role,
        assignedBy: updatedBusinessUser.assignedBy,
        createdAt: updatedBusinessUser.createdAt,
      },
    };
  }

  async deleteClient(
    businessId: string,
    clientId: string,
    userId: string,
    userRole: Role
  ): Promise<{ message: string }> {
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    // Prevent unassigning the business owner
    const businessUser = await this.businessUserModel.findOne({
      businessId,
      userId: clientId,
    });

    if (!businessUser) {
      throw new NotFoundException('User not found in this business');
    }

    if (businessUser.role === BusinessUserRole.OWNER) {
      throw new BadRequestException('Cannot remove business owner');
    }

    const result = await this.businessUserModel.deleteOne({
      businessId,
      userId: clientId,
    });

    if (result.deletedCount === 0) {
      throw new NotFoundException('User association not found');
    }

    return {
      message: 'User removed from business successfully',
    };
  }

  async getBusinessStatistics(
    businessId: string,
    userId: string,
    userRole: Role,
    predictionHorizonDays = 90
  ): Promise<BusinessStatisticsResponseDto> {
    await this.checkBusinessAccess(businessId, userId, userRole, false);

    // Check cache first (cache for 5 minutes)
    const cacheKey = `business:statistics:${businessId}:${predictionHorizonDays}`;
    const cached =
      await this.cacheService.get<BusinessStatisticsResponseDto>(cacheKey);
    if (cached) {
      // Return clone to prevent mutation of cached data
      return structuredClone(cached);
    }

    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    const tenantDb = this.connection.useDb(business.databaseName, {
      useCache: true,
    });
    const invoicesCol = tenantDb.collection<Invoice>('invoices');
    const productsCol = tenantDb.collection<Product>('products');

    const horizonMonths = Math.max(1, Math.ceil(predictionHorizonDays / 30));

    const forecasts =
      await this.tensorflowPredictionService.forecastBusinessMetrics(
        businessId,
        business.databaseName,
        horizonMonths
      );

    const revenueMonthly = forecasts.revenue.historical;
    const cogsMonthly = forecasts.cogs.historical;

    type InvoiceAggResult = {
      _id: null;
      paidAmount: number;
      partialAmount: number;
      pendingAmount: number;
      overdueAmount: number;
      totalInvoices: number;
      paidInvoices: number;
      partialInvoices: number;
      pendingInvoices: number;
      overdueInvoices: number;
    };

    const invoicePipeline: Array<Record<string, unknown>> = [
      {
        $match: {
          $or: [
            { issuerBusinessId: new ObjectId(businessId) },
            { issuerBusinessId: businessId },
          ],
        },
      },
      {
        $group: {
          // eslint-disable-next-line unicorn/no-null -- MongoDB requires null for grouping all docs
          _id: null,
          paidAmount: {
            $sum: {
              $cond: [
                { $eq: [{ $toUpper: { $ifNull: ['$status', ''] } }, 'PAID'] },
                { $ifNull: ['$totalAmount', 0] },
                0,
              ],
            },
          },
          partialAmount: {
            $sum: {
              $cond: [
                {
                  $eq: [{ $toUpper: { $ifNull: ['$status', ''] } }, 'PARTIAL'],
                },
                { $ifNull: ['$amountPaid', 0] },
                0,
              ],
            },
          },
          pendingAmount: {
            $sum: {
              $cond: [
                {
                  $in: [
                    { $toUpper: { $ifNull: ['$status', ''] } },
                    ['DRAFT', 'ISSUED', 'VIEWED'],
                  ],
                },
                { $ifNull: ['$totalAmount', 0] },
                0,
              ],
            },
          },
          overdueAmount: {
            $sum: {
              $cond: [
                {
                  $eq: [{ $toUpper: { $ifNull: ['$status', ''] } }, 'OVERDUE'],
                },
                { $ifNull: ['$totalAmount', 0] },
                0,
              ],
            },
          },
          totalInvoices: { $sum: 1 },
          paidInvoices: {
            $sum: {
              $cond: [
                { $eq: [{ $toUpper: { $ifNull: ['$status', ''] } }, 'PAID'] },
                1,
                0,
              ],
            },
          },
          partialInvoices: {
            $sum: {
              $cond: [
                {
                  $eq: [{ $toUpper: { $ifNull: ['$status', ''] } }, 'PARTIAL'],
                },
                1,
                0,
              ],
            },
          },
          pendingInvoices: {
            $sum: {
              $cond: [
                {
                  $in: [
                    { $toUpper: { $ifNull: ['$status', ''] } },
                    ['DRAFT', 'ISSUED', 'VIEWED'],
                  ],
                },
                1,
                0,
              ],
            },
          },
          overdueInvoices: {
            $sum: {
              $cond: [
                {
                  $eq: [{ $toUpper: { $ifNull: ['$status', ''] } }, 'OVERDUE'],
                },
                1,
                0,
              ],
            },
          },
        },
      },
    ];
    const invoiceAgg = await invoicesCol
      .aggregate<InvoiceAggResult>(invoicePipeline)
      .toArray();
    const inv = invoiceAgg[0];

    type LineItemDetailResult = {
      productId: string;
      quantity: number;
      revenue: number;
    };

    const lineItemPipeline: Array<Record<string, unknown>> = [
      {
        $match: {
          $or: [
            { issuerBusinessId: new ObjectId(businessId) },
            { issuerBusinessId: businessId },
          ],
          status: { $in: ['PAID', 'PARTIAL'] },
        },
      },
      { $unwind: { path: '$lineItems', preserveNullAndEmptyArrays: false } },
      {
        $group: {
          _id: { productId: '$lineItems.productId' },
          quantity: { $sum: { $ifNull: ['$lineItems.quantity', 0] } },
          revenue: { $sum: { $ifNull: ['$lineItems.amount', 0] } },
        },
      },
      {
        $project: {
          productId: '$_id.productId',
          quantity: 1,
          revenue: 1,
          _id: 0,
        },
      },
    ];

    const lineItemAgg = await invoicesCol
      .aggregate<LineItemDetailResult>(lineItemPipeline)
      .toArray();

    const salesMap = new Map<string, { quantity: number; revenue: number }>();
    for (const item of lineItemAgg) {
      salesMap.set(item.productId.toString(), {
        quantity: item.quantity,
        revenue: item.revenue,
      });
    }

    const allProducts = await productsCol
      // eslint-disable-next-line unicorn/no-array-callback-reference
      .find({
        $or: [
          { businessId: new ObjectId(businessId) as unknown as string },
          { businessId: businessId },
        ],
      } as Record<string, unknown>)
      .toArray();

    const totalProducts = allProducts.length;
    const totalInventoryValue = allProducts.reduce(
      (sum, p) => sum + (p.unitPrice ?? 0) * (p.quantity ?? 0),
      0
    );
    const lowStockProducts = allProducts.filter(
      (p) => (p.quantity ?? 0) < 10
    ).length;

    const profitabilityList = allProducts.map((p) => {
      const sales = salesMap.get(p._id.toString()) ?? {
        quantity: 0,
        revenue: 0,
      };
      const cost = p.cost ?? 0;
      const profit = sales.revenue - sales.quantity * cost;
      const margin =
        sales.revenue > 0
          ? Math.round((profit / sales.revenue) * 10_000) / 100
          : 0;

      return {
        productId: p._id.toString(),
        productName: p.name ?? 'Unnamed Product',
        unitPrice: p.unitPrice ?? 0,
        unitCost: cost,
        soldQuantity: sales.quantity,
        revenue: Math.round(sales.revenue * 100) / 100,
        totalCost: Math.round(sales.quantity * cost * 100) / 100,
        grossProfit: Math.round(profit * 100) / 100,
        profitMarginPercent: margin,
      };
    });

    const topProducts = [...profitabilityList]
      .toSorted((a, b) => b.revenue - a.revenue)
      .slice(0, 5);

    const underperformingProducts = [...profitabilityList]
      .filter((p) => p.soldQuantity > 0)
      .toSorted((a, b) => a.profitMarginPercent - b.profitMarginPercent)
      .slice(0, 5);

    const totalRevenue = revenueMonthly.reduce((s, p) => s + p.value, 0);
    const totalCOGS = cogsMonthly.reduce((s, p) => s + p.value, 0);
    const grossProfit = totalRevenue - totalCOGS;
    const profitMarginPercent =
      totalRevenue > 0
        ? Math.round((grossProfit / totalRevenue) * 10_000) / 100
        : 0;

    let revenueGrowthRatePercent: number | undefined = undefined;
    if (revenueMonthly.length >= 2) {
      const mid = Math.floor(revenueMonthly.length / 2);
      const firstHalf = revenueMonthly
        .slice(0, mid)
        .reduce((s, p) => s + p.value, 0);
      const secondHalf = revenueMonthly
        .slice(mid)
        .reduce((s, p) => s + p.value, 0);
      revenueGrowthRatePercent =
        firstHalf > 0
          ? Math.round(((secondHalf - firstHalf) / firstHalf) * 10_000) / 100
          : undefined;
    }

    let salesTrend: 'growth' | 'decline' | 'stagnation' = 'stagnation';
    if (revenueMonthly.length >= 3) {
      const recent3 = revenueMonthly.slice(-3).map((p) => p.value);
      const avgRecent = recent3.reduce((s, v) => s + v, 0) / 3;
      const earlier3 = revenueMonthly.slice(-6, -3).map((p) => p.value);
      if (earlier3.length > 0) {
        const avgEarlier =
          earlier3.reduce((s, v) => s + v, 0) / earlier3.length;
        const change =
          avgEarlier > 0 ? ((avgRecent - avgEarlier) / avgEarlier) * 100 : 0;

        if (change > 5) {
          salesTrend = 'growth';
        } else if (change < -5) {
          salesTrend = 'decline';
        }
      }
    }

    const periodStart = revenueMonthly[0]?.date ?? '';
    const periodEnd = revenueMonthly.at(-1)?.date ?? '';

    const result = {
      message: 'Business statistics retrieved successfully',
      businessId: business._id.toString(),
      period: { start: periodStart, end: periodEnd },
      kpis: {
        totalRevenue: Math.round(totalRevenue * 100) / 100,
        totalCOGS: Math.round(totalCOGS * 100) / 100,
        grossProfit: Math.round(grossProfit * 100) / 100,
        netProfit: Math.round(grossProfit * 100) / 100,
        profitMarginPercent,
        revenueGrowthRatePercent,
      },
      revenueTimeSeries: forecasts,
      invoiceStatistics: {
        totalInvoices: toNumberOrZero(inv?.totalInvoices),
        paidInvoices:
          toNumberOrZero(inv?.paidInvoices) +
          toNumberOrZero(inv?.partialInvoices),
        pendingInvoices: toNumberOrZero(inv?.pendingInvoices),
        overdueInvoices: toNumberOrZero(inv?.overdueInvoices),
        paidAmount:
          toNumberOrZero(inv?.paidAmount) + toNumberOrZero(inv?.partialAmount),
        pendingAmount: toNumberOrZero(inv?.pendingAmount),
        overdueAmount: toNumberOrZero(inv?.overdueAmount),
      },
      productStatistics: {
        totalProducts,
        totalInventoryValue: Math.round(totalInventoryValue * 100) / 100,
        lowStockProducts,
      },
      salesAnalytics: {
        salesVolume: forecasts.salesVolume,
        topProducts,
        underperformingProducts,
        salesTrend,
      },
    };

    // Cache for 5 minutes
    await this.cacheService.set(cacheKey, result, 300);
    return result;
  }

  async getClientPodium(
    businessId: string,
    userId: string,
    userRole: Role
  ): Promise<{
    businessId: string;
    podium: Array<{
      clientId: string;
      clientName: string;
      clientEmail: string;
      totalPaidAmount: number;
      totalPaidInvoices: number;
      medal: string;
    }>;
  }> {
    // Check access
    await this.checkBusinessAccess(businessId, userId, userRole, false);

    // Get business
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Connect to tenant database
    const tenantDb = this.connection.useDb(business.databaseName, {
      useCache: true,
    });
    const invoicesCollection = tenantDb.collection('invoices');

    // Calculate client podium - recipients who have paid all their invoices
    // Includes: Platform users (clients), external recipients, and businesses
    let clientPodium: Array<{
      clientId: string;
      clientName: string;
      clientEmail: string;
      totalPaidAmount: number;
      totalPaidInvoices: number;
      medal: string;
    }> = [];

    try {
      const paidStatus = toInvoiceStatus(InvoiceStatus.PAID) ?? 'paid';
      const paidLabelUpper = paidStatus.toUpperCase();

      const topRecipients = await invoicesCollection
        .aggregate<{
          recipientKey: string;
          recipientName: string;
          recipientEmail: string;
          totalPaidAmount: number;
          totalPaidInvoices: number;
        }>([
          {
            $match: {
              $or: [
                { issuerBusinessId: new ObjectId(businessId) },
                { issuerBusinessId: businessId },
              ],
            },
          },
          {
            $addFields: {
              normalizedStatus: {
                $toUpper: { $ifNull: ['$status', ''] },
              },
              recipientType: {
                $toUpper: {
                  $trim: {
                    input: { $ifNull: ['$recipient.type', ''] },
                  },
                },
              },
              recipientPlatformId: {
                $trim: {
                  input: { $ifNull: ['$recipient.platformId', ''] },
                },
              },
              recipientEmailNormalized: {
                $toLower: {
                  $trim: {
                    input: { $ifNull: ['$recipient.email', ''] },
                  },
                },
              },
              recipientDisplayNameNormalized: {
                $trim: {
                  input: { $ifNull: ['$recipient.displayName', ''] },
                },
              },
              normalizedTotalAmount: { $ifNull: ['$totalAmount', 0] },
            },
          },
          {
            $match: {
              normalizedStatus: paidLabelUpper,
            },
          },
          {
            $addFields: {
              recipientKey: {
                $cond: [
                  {
                    $and: [
                      { $eq: ['$recipientType', 'PLATFORM_INDIVIDUAL'] },
                      { $ne: ['$recipientPlatformId', ''] },
                    ],
                  },
                  { $concat: ['user_', '$recipientPlatformId'] },
                  {
                    $cond: [
                      {
                        $and: [
                          { $eq: ['$recipientType', 'PLATFORM_BUSINESS'] },
                          { $ne: ['$recipientPlatformId', ''] },
                        ],
                      },
                      { $concat: ['business_', '$recipientPlatformId'] },
                      {
                        $cond: [
                          {
                            $and: [
                              { $eq: ['$recipientType', 'EXTERNAL'] },
                              { $ne: ['$recipientEmailNormalized', ''] },
                            ],
                          },
                          {
                            $concat: ['external_', '$recipientEmailNormalized'],
                          },
                          '',
                        ],
                      },
                    ],
                  },
                ],
              },
              recipientName: {
                $cond: [
                  { $eq: ['$recipientType', 'PLATFORM_INDIVIDUAL'] },
                  {
                    $cond: [
                      { $ne: ['$recipientDisplayNameNormalized', ''] },
                      '$recipientDisplayNameNormalized',
                      {
                        $cond: [
                          { $ne: ['$recipientEmailNormalized', ''] },
                          '$recipientEmailNormalized',
                          'Unknown',
                        ],
                      },
                    ],
                  },
                  {
                    $cond: [
                      { $eq: ['$recipientType', 'PLATFORM_BUSINESS'] },
                      {
                        $cond: [
                          { $ne: ['$recipientDisplayNameNormalized', ''] },
                          '$recipientDisplayNameNormalized',
                          'Unknown Business',
                        ],
                      },
                      {
                        $cond: [
                          { $eq: ['$recipientType', 'EXTERNAL'] },
                          {
                            $cond: [
                              { $ne: ['$recipientDisplayNameNormalized', ''] },
                              '$recipientDisplayNameNormalized',
                              {
                                $cond: [
                                  { $ne: ['$recipientEmailNormalized', ''] },
                                  '$recipientEmailNormalized',
                                  'External Contact',
                                ],
                              },
                            ],
                          },
                          'Unknown',
                        ],
                      },
                    ],
                  },
                ],
              },
            },
          },
          {
            $match: {
              recipientKey: { $ne: '' },
            },
          },
          {
            $group: {
              _id: '$recipientKey',
              recipientName: { $first: '$recipientName' },
              recipientEmail: { $first: '$recipientEmailNormalized' },
              totalPaidAmount: { $sum: '$normalizedTotalAmount' },
              totalPaidInvoices: { $sum: 1 },
            },
          },
          {
            $sort: {
              totalPaidAmount: -1,
            },
          },
          {
            $limit: 3,
          },
          {
            $project: {
              _id: 0,
              recipientKey: '$_id',
              recipientName: 1,
              recipientEmail: 1,
              totalPaidAmount: 1,
              totalPaidInvoices: 1,
            },
          },
        ])
        .toArray();

      const medals = ['🥇', '🥈', '🥉'];
      clientPodium = topRecipients.map((recipient, index) => ({
        clientId: recipient.recipientKey,
        clientName: recipient.recipientName,
        clientEmail: recipient.recipientEmail,
        totalPaidAmount: toNumberOrZero(recipient.totalPaidAmount),
        totalPaidInvoices: toNumberOrZero(recipient.totalPaidInvoices),
        medal: medals[index] || '🏅',
      }));
    } catch (error) {
      throw error;
    }

    return {
      businessId: business._id.toString(),
      podium: clientPodium,
    };
  }

  // === Business Invitations Flow ===

  async inviteBusinessUser(
    businessId: string,
    inviteDto: InviteBusinessUserDto,
    inviterId: string,
    inviterRole: Role
  ): Promise<BusinessInviteResponseDto> {
    // Check if inviter has admin/owner permission
    await this.checkBusinessAccess(businessId, inviterId, inviterRole, true);

    // Validate business exists
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    const normalizedEmail = inviteDto.invitedEmail.toLowerCase().trim();
    const inviter = await this.userModel.findById(inviterId);

    const existingUser = await this.userModel.findOne({
      email: normalizedEmail,
    });
    if (existingUser) {
      const existingAssignment = await this.businessUserModel.findOne({
        businessId,
        userId: existingUser._id.toString(),
      });

      if (existingAssignment) {
        throw new BadRequestException(
          'User is already assigned to this business'
        );
      }

      const businessUser = new this.businessUserModel({
        businessId,
        userId: existingUser._id.toString(),
        role: inviteDto.businessRole,
        assignedBy: inviterId,
      });

      const savedBusinessUser = await businessUser.save();

      try {
        await this.tenantConnectionService.upsertTenantUser(
          business.databaseName,
          {
            userId: existingUser._id.toString(),
            role: inviteDto.businessRole,
            assignedBy: inviterId,
          }
        );
      } catch {
        await this.businessUserModel.findByIdAndDelete(savedBusinessUser._id);
        throw new InternalServerErrorException(
          'Failed to sync tenant user assignment'
        );
      }

      try {
        await this.auditEmitter.emitAction({
          action: AuditAction.INVITE_ACCEPTED,
          userId: existingUser._id.toString(),
          userEmail: existingUser.email,
          userRole: existingUser.role ?? inviteDto.businessRole,
          target: normalizedEmail,
          details: {
            businessId,
            businessRole: inviteDto.businessRole,
            directAssignment: true,
            assignedUserId: existingUser._id.toString(),
            inviterId,
          },
        });
      } catch {
        // ignore audit errors
      }

      return {
        message: 'User is already registered and has been assigned directly',
      };
    }

    // Check if invite already exists for this email in this business
    const existingInvite = await this.businessInviteModel.findOne({
      businessId,
      invitedEmail: normalizedEmail,
    });

    if (existingInvite) {
      throw new BadRequestException(
        'An invite already exists for this email in this business'
      );
    }

    // Create the invite in platform DB
    const invite = new this.businessInviteModel({
      businessId,
      invitedEmail: normalizedEmail,
      inviterId,
      businessRole: inviteDto.businessRole,
      status: 'pending',
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    });

    const savedInvite = await invite.save();

    // Get inviter info for email
    const inviterName = inviter
      ? `${inviter.firstName} ${inviter.lastName}`
      : 'A business owner';

    let emailSent = false;

    // Send invite email
    try {
      await this.emailService.sendBusinessInviteEmail(
        normalizedEmail,
        business.name,
        inviterName,
        inviteDto.businessRole
      );

      const updatedInvite = await this.businessInviteModel.findByIdAndUpdate(
        savedInvite._id,
        {
          emailSent: true,
        },
        { returnDocument: 'after' }
      );
      emailSent = updatedInvite?.emailSent ?? false;
    } catch (error) {
      // Log error but don't fail the request
      console.error('Failed to send invite email:', error);
    }

    if (emailSent) {
      // Audit: record invite sent
      try {
        await this.auditEmitter.emitAction({
          action: AuditAction.INVITE_SENT,
          userId: inviterId,
          userEmail: inviter?.email ?? 'Unknown',
          userRole: inviter?.role ?? inviterRole ?? 'Unknown',
          target: normalizedEmail,
          details: { businessId, businessRole: inviteDto.businessRole },
        });
      } catch {
        // ignore audit errors
      }
    }

    return {
      message: 'Invite sent successfully',
      invite: {
        id: savedInvite._id.toString(),
        businessId: savedInvite.businessId,
        invitedEmail: savedInvite.invitedEmail,
        inviterId: savedInvite.inviterId,
        businessRole: savedInvite.businessRole,
        emailSent,
        status: savedInvite.status,
        expiresAt: savedInvite.expiresAt,
        createdAt: savedInvite.createdAt,
      },
    };
  }

  async resendInvite(
    businessId: string,
    inviteId: string,
    userId: string,
    userRole: Role
  ): Promise<BusinessInviteResponseDto> {
    // Check permission
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    const invite = await this.businessInviteModel.findById(inviteId);
    if (!invite) {
      throw new NotFoundException('Invite not found');
    }

    if (invite.businessId !== businessId) {
      throw new ForbiddenException(
        'You do not have permission to resend this invite'
      );
    }

    if (invite.status !== 'pending') {
      throw new BadRequestException('Invite is not pending');
    }

    // Get business and inviter info for email
    const business = await this.businessModel.findById(businessId);
    const inviter = await this.userModel.findById(invite.inviterId);

    if (!business) {
      throw new NotFoundException('Business not found');
    }

    if (!inviter) {
      throw new NotFoundException('Inviter not found');
    }

    const inviterName = `${inviter.firstName} ${inviter.lastName}`;

    try {
      await this.emailService.sendBusinessInviteEmail(
        invite.invitedEmail,
        business.name,
        inviterName,
        invite.businessRole
      );
    } catch (error) {
      console.error('Failed to resend invite email:', error);
      throw new InternalServerErrorException('Failed to resend invite email');
    }

    invite.emailSent = true;
    await invite.save();

    // Audit: record invite resent
    if (invite.emailSent) {
      try {
        const actor = await this.userModel
          .findById(userId)
          .catch(() => undefined as never);
        await this.auditEmitter.emitAction({
          action: AuditAction.INVITE_SENT,
          userId: userId,
          userEmail: actor?.email ?? 'Unknown',
          userRole: actor?.role ?? userRole ?? 'Unknown',
          target: invite.invitedEmail,
          details: { businessId, inviteId, resend: true },
        });
      } catch {
        // ignore audit errors
      }
    }

    return {
      message: 'Invite resent successfully',
      invite: {
        id: invite._id.toString(),
        businessId: invite.businessId,
        invitedEmail: invite.invitedEmail,
        inviterId: invite.inviterId,
        businessRole: invite.businessRole,
        emailSent: invite.emailSent,
        status: invite.status,
        expiresAt: invite.expiresAt,
        createdAt: invite.createdAt,
      },
    };
  }

  async processInvitesForNewUser(userId: string, email: string): Promise<void> {
    // Find all pending invites for this email
    const invites = await this.businessInviteModel.find({
      invitedEmail: email.toLowerCase().trim(),
      status: 'pending',
    });

    if (invites.length === 0) {
      return; // No invites for this email
    }

    // Process each invite - create business user assignment and sync to tenant
    for (const invite of invites) {
      try {
        if (invite.status !== 'pending') {
          continue;
        }

        const business = await this.businessModel.findById(invite.businessId);
        if (!business) {
          console.warn(
            `Business ${invite.businessId} not found for invite processing`
          );
          continue;
        }

        // Check if user is already assigned to this business
        const existingAssignment = await this.businessUserModel.findOne({
          businessId: invite.businessId,
          userId,
        });

        if (existingAssignment) {
          continue; // Already assigned
        }

        // Create business user assignment
        const businessUser = new this.businessUserModel({
          businessId: invite.businessId,
          userId,
          role: invite.businessRole,
          assignedBy: invite.inviterId,
        });

        await businessUser.save();

        // Sync to tenant database
        try {
          await this.tenantConnectionService.upsertTenantUser(
            business.databaseName,
            {
              userId,
              role: invite.businessRole,
              assignedBy: invite.inviterId,
            }
          );
        } catch (error) {
          // Rollback if tenant sync fails
          await this.businessUserModel.findByIdAndDelete(businessUser._id);
          throw error;
        }

        try {
          await this.businessInviteModel.findByIdAndUpdate(invite._id, {
            status: 'accepted',
            acceptedAt: new Date(),
            processedBy: userId,
          });
        } catch (error) {
          console.error(
            `Failed to mark invite ${invite._id.toString()} as accepted for user ${userId}:`,
            error
          );
        }
        // Audit: record invite accepted / user assigned
        try {
          await this.auditEmitter.emitAction({
            action: AuditAction.INVITE_ACCEPTED,
            userId: userId,
            userEmail: email,
            userRole: invite.businessRole,
            target: invite.businessId,
            details: {
              inviterId: invite.inviterId,
              assignedBy: invite.inviterId,
            },
          });
        } catch {
          // ignore audit errors
        }
      } catch (error) {
        // Log but continue processing other invites
        console.error(
          `Failed to process invite ${invite._id.toString()} for user ${userId}:`,
          error
        );
      }
    }
  }

  // === Stripe Connect Integration ===

  private ensureStripeEnabled(): InstanceType<typeof Stripe> {
    if (!this.stripeClient) {
      throw new Error(
        'Stripe client not configured. Please set STRIPE_SECRET_KEY environment variable.'
      );
    }
    return this.stripeClient;
  }

  async getStripeOnboardingLink(
    businessId: string,
    userId: string,
    userRole: Role
  ): Promise<StripeOnboardingLinkDto> {
    // Check business access
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    // Get business
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Ensure Stripe is configured
    const stripe = this.ensureStripeEnabled();

    // Get frontend URL
    const frontendUrl =
      this.configService.get<string>('FRONTEND_URL') ??
      process.env.FRONTEND_URL ??
      'http://localhost:3000';

    let stripeConnectId = business.stripeConnectId;

    try {
      // Create Stripe Express account if not already connected
      if (!stripeConnectId) {
        const account = await stripe.accounts.create({
          type: 'express',
          country: 'US', // Default to US; can be made configurable per business
        });
        stripeConnectId = account.id;

        // Save the new account ID to the business
        await this.businessModel.updateOne(
          { _id: businessId },
          { stripeConnectId }
        );
      }

      // Create the account link for onboarding
      const accountLink = await stripe.accountLinks.create({
        account: stripeConnectId,
        type: 'account_onboarding',
        refresh_url: `${frontendUrl}/business/${businessId}/stripe/refresh`,
        return_url: `${frontendUrl}/business/${businessId}/stripe/callback`,
      });

      // Save the onboarding URL (temporary, expires after 24h)
      await this.businessModel.updateOne(
        { _id: businessId },
        { stripeOnboardingUrl: accountLink.url }
      );

      return {
        onboardingUrl: accountLink.url,
        message:
          'Please complete your Stripe account setup. You will be redirected back after completing onboarding.',
      };
    } catch (error) {
      const stripeErrorMessage =
        error instanceof Error ? error.message : String(error);
      this.logger.warn(
        `Stripe onboarding link generation failed for business ${businessId}: ${stripeErrorMessage}`
      );

      const normalized = stripeErrorMessage.toLowerCase();
      if (
        normalized.includes('signed up for connect') ||
        normalized.includes('dashboard.stripe.com/connect')
      ) {
        throw new BadRequestException(
          'Stripe Connect is not enabled on your Stripe platform account. Activate Connect at https://dashboard.stripe.com/connect, then retry.'
        );
      }

      throw new InternalServerErrorException(
        'Unable to generate Stripe onboarding link right now. Please try again later.'
      );
    }
  }

  async getStripeConnectStatus(
    businessId: string,
    userId: string,
    userRole: Role
  ): Promise<StripeConnectStatusDto> {
    // Check business access
    await this.checkBusinessAccess(businessId, userId, userRole, false);

    // Get business
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // If no Stripe Connect ID, account is not connected
    if (!business.stripeConnectId) {
      return {
        isConnected: false,
        message:
          'Stripe Connect account not yet connected. Complete the onboarding to start receiving payments.',
      };
    }

    // Verify the account status with Stripe
    try {
      const stripe = this.ensureStripeEnabled();
      const account = await stripe.accounts.retrieve(business.stripeConnectId);

      // Check if account is fully onboarded (charges_enabled)
      const isFullyConnected = account.charges_enabled ?? false;

      return {
        isConnected: isFullyConnected,
        stripeConnectId: business.stripeConnectId,
        message: isFullyConnected
          ? 'Stripe Connect account is fully configured. Ready to receive payments.'
          : 'Stripe Connect account is connected but not fully set up. Please complete the required information.',
      };
    } catch (error) {
      // If we can't verify with Stripe, assume not connected
      const errorMessage =
        error instanceof Error
          ? error.message
          : 'Unknown error verifying account';
      this.logger.warn(
        `Failed to verify Stripe account ${business.stripeConnectId}: ${errorMessage}`
      );

      return {
        isConnected: false,
        stripeConnectId: business.stripeConnectId,
        message:
          'Could not verify Stripe account status. Please try connecting again.',
      };
    }
  }

  // Team Management
  async getTeamMembers(
    businessId: string,
    userId: string,
    userRole: Role
  ): Promise<{
    message: string;
    members: Array<{
      id: string;
      userId: string;
      firstName: string;
      lastName: string;
      email: string;
      phoneNumber?: string;
      role: BusinessUserRole;
      createdAt: Date;
    }>;
  }> {
    await this.checkBusinessAccess(businessId, userId, userRole);

    const businessUsers = await this.businessUserModel
      .find({ businessId })
      .lean();

    const userIds = businessUsers.map((bu) => bu.userId);
    const users = await this.userModel
      .find({ _id: { $in: userIds } })
      .select('firstName lastName email phoneNumber role createdAt')
      .lean();

    const members = businessUsers.map((bu) => {
      const user = users.find((u) => u._id.toString() === bu.userId);
      return {
        id: bu._id.toString(),
        userId: bu.userId,
        firstName: user?.firstName ?? 'Unknown',
        lastName: user?.lastName ?? 'User',
        email: user?.email ?? '',
        phoneNumber: user?.phoneNumber,
        role: bu.role,
        createdAt: bu.createdAt,
      };
    });

    return {
      message: 'Team members retrieved successfully',
      members,
    };
  }

  async getPendingInvites(
    businessId: string,
    userId: string,
    userRole: Role
  ): Promise<{
    message: string;
    invites: Array<{
      id: string;
      invitedEmail: string;
      businessRole: string;
      inviterName: string;
      emailSent: boolean;
      expiresAt: Date | undefined;
      createdAt: Date;
    }>;
  }> {
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    const invites = await this.businessInviteModel
      .find({
        businessId,
        status: 'pending',
        expiresAt: { $gt: new Date() },
      })
      .sort({ createdAt: -1 })
      .lean();

    const inviterIds = invites.map((i) => i.inviterId);
    const inviters = await this.userModel
      .find({ _id: { $in: inviterIds } })
      .select('firstName lastName')
      .lean();

    const formattedInvites = invites.map((invite) => {
      const inviter = inviters.find(
        (u) => u._id.toString() === invite.inviterId
      );
      return {
        id: invite._id.toString(),
        invitedEmail: invite.invitedEmail,
        businessRole: invite.businessRole,
        inviterName: inviter
          ? `${inviter.firstName} ${inviter.lastName}`
          : 'System',
        emailSent: invite.emailSent,
        expiresAt: invite.expiresAt,
        createdAt: invite.createdAt,
      };
    });

    return {
      message: 'Pending invites retrieved successfully',
      invites: formattedInvites,
    };
  }

  async revokeInvite(
    businessId: string,
    inviteId: string,
    userId: string,
    userRole: Role
  ): Promise<{ message: string }> {
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    const invite = await this.businessInviteModel.findById(inviteId);
    if (!invite) {
      throw new NotFoundException('Invite not found');
    }

    if (invite.businessId !== businessId) {
      throw new ForbiddenException(
        'You do not have permission to revoke this invite'
      );
    }

    invite.status = 'revoked';
    await invite.save();

    return { message: 'Invite revoked successfully' };
  }
}
