import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectConnection, InjectModel } from '@nestjs/mongoose';
import { Connection, Model } from 'mongoose';
import { randomBytes } from 'node:crypto';
import { AuditService } from '@/audit/audit.service';
import { AuditAction } from '@/audit/schemas/audit-log.schema';
import { Business, BusinessDocument } from '@/business/schemas/business.schema';
import {
  BusinessApplication,
  BusinessApplicationDocument,
} from '@/business/schemas/business-application.schema';
import {
  BusinessUser,
  BusinessUserDocument,
  BusinessUserRole,
} from '@/business/schemas/business-user.schema';
import { User, UserDocument } from '@/users/schemas/user.schema';
import { UpdateBusinessDto } from '@/business/dto/update-business.dto';
import {
  CreateBusinessApplicationDto,
  ReviewBusinessApplicationDto,
} from '@/business/dto/business-application.dto';
import { AssignBusinessUserDto } from '@/business/dto/business-user.dto';
import {
  BusinessResponseDto,
  BusinessesListResponseDto,
  BusinessApplicationListResponseDto,
} from '@/business/dto/business-response.dto';
import { BusinessApplicationResponseDto } from '@/business/dto/business-application.dto';
import { BusinessUserResponseDto } from '@/business/dto/business-user.dto';
import { Role } from '@/auth/enums/role.enum';
import { type UserPayload } from '@/auth/types/auth.types';
import { EmailService } from '@/auth/email.service';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';
import {
  type TenantContext,
  type TenantMetadata,
} from '@/common/tenant/tenant.types';
import { NotificationsService } from '@/notifications/notifications.service';
import { NotificationType } from '@/notifications/schemas/notification.schema';

@Injectable()
export class BusinessService {
  constructor(
    @InjectConnection() private readonly connection: Connection,
    @InjectModel(Business.name) private businessModel: Model<BusinessDocument>,
    @InjectModel(BusinessApplication.name)
    private businessApplicationModel: Model<BusinessApplicationDocument>,
    @InjectModel(BusinessUser.name)
    private businessUserModel: Model<BusinessUserDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private emailService: EmailService,
    private tenantConnectionService: TenantConnectionService,
    private auditService: AuditService,
    private notificationsService: NotificationsService
  ) {}

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

    // Send email notification about application submission (non-blocking)
    this.emailService.sendBusinessApplicationEmail(
      userId,
      savedApplication.businessName
    ).catch(err => console.error('Failed to send application email in background:', err));

    // Send real-time admin notification (non-blocking)
    this.notificationsService.createNotification({
      type: NotificationType.NEW_BUSINESS_APPLICATION,
      message: `New business application: "${savedApplication.businessName}"`,
      payload: {
        applicationId: savedApplication._id.toString(),
        businessName: savedApplication.businessName,
        applicantId: userId,
      },
    }).catch(err => console.error('Failed to create notification:', err));

    return {
      message:
        'Business application submitted successfully. We will review your application and respond within 2-3 business days.',
      application: {
        id: savedApplication._id.toString(),
        businessName: savedApplication.businessName,
        description: savedApplication.description,
        website: savedApplication.website,
        phone: savedApplication.phone,
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

    if (application.status === 'approved') {
      throw new BadRequestException('Application has already been approved');
    }

    application.status = reviewDto.status;
    application.reviewedBy = reviewerId;
    application.reviewNotes = reviewDto.reviewNotes;

    if (reviewDto.status === 'approved') {
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
        databaseName,
        status: 'approved',
        isActive: true,
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

        // Upgrade the applicant's role from CLIENT to BUSINESS_OWNER
        await this.userModel.updateOne(
          { _id: application.applicantId, role: Role.CLIENT },
          { $set: { role: Role.BUSINESS_OWNER } },
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

      // Send approval email (non-blocking)
      this.emailService.sendBusinessApprovalEmail(
        application.applicantId,
        approvedBusinessName
      ).catch(err => console.error('Failed to send approval email in background:', err));

      this.auditService.logAction({
        action: AuditAction.APPROVE_BUSINESS,
        userId: reviewer.id,
        userEmail: reviewer.email || 'Unknown',
        userRole: reviewer.role || 'ADMIN',
        target: approvedBusinessName,
        details: { applicationId },
      });

    } else {
      await application.save();

      // Send rejection email (non-blocking)
      this.emailService.sendBusinessRejectionEmail(
        application.applicantId,
        application.businessName,
        reviewDto.reviewNotes
      ).catch(err => console.error('Failed to send rejection email in background:', err));

      this.auditService.logAction({
        action: AuditAction.REJECT_BUSINESS,
        userId: reviewer.id,
        userEmail: reviewer.email || 'Unknown',
        userRole: reviewer.role || 'ADMIN',
        target: application.businessName,
        details: { applicationId, reason: reviewDto.reviewNotes },
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
        applicantId: application.applicantId,
        status: application.status,
        createdAt: application.createdAt,
      },
    };
  }

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
        'businessName description website phone applicantId status createdAt'
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
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Check if user has access to this business
    await this.checkBusinessAccess(businessId, userId, userRole);

    return {
      message: 'Business retrieved successfully',
      business: {
        id: business._id.toString(),
        name: business.name,
        description: business.description,
        website: business.website,
        phone: business.phone,
        databaseName: business.databaseName,
        status: business.status,
        isActive: business.isActive,
        logo: business.logo,
        tags: business.tags,
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
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Check if user has owner access to this business
    await this.checkBusinessAccess(businessId, userId, userRole, true);

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
        databaseName: updatedBusiness.databaseName,
        status: updatedBusiness.status,
        isActive: updatedBusiness.isActive,
        logo: updatedBusiness.logo,
        tags: updatedBusiness.tags,
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
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Check if user has owner access to this business
    await this.checkBusinessAccess(businessId, userId, userRole, true);

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

    return { message: 'Business deleted successfully' };
  }

  async getMyBusinesses(userId: string): Promise<BusinessesListResponseDto> {
    // Get all businesses where user has a role
    const businessUsers = await this.businessUserModel
      .find({ userId, isActive: true })
      .select('businessId')
      .lean();

    const businessIds = businessUsers.map((bu) => bu.businessId);

    if (businessIds.length === 0) {
      return {
        message: 'No businesses found',
        businesses: [],
      };
    }

    const businesses = await this.businessModel
      .find({ _id: { $in: businessIds } })
      .select('name phone status isActive createdAt')
      .sort({ createdAt: -1 })
      .lean();

    return {
      message: 'Businesses retrieved successfully',
      businesses: businesses.map((business) => ({
        id: business._id.toString(),
        name: business.name,
        phone: business.phone,
        status: business.status,
        isActive: business.isActive,
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
      .select('name phone status isActive createdAt')
      .sort({ createdAt: -1 })
      .lean();

    return {
      message: 'Businesses retrieved successfully',
      businesses: businesses.map((business) => ({
        id: business._id.toString(),
        name: business.name,
        phone: business.phone,
        status: business.status,
        isActive: business.isActive,
        createdAt: business.createdAt,
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
    const business = await this.businessModel
      .findById(businessId)
      .select('databaseName');
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Check if assigner has owner access to this business
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    // Check if user is already assigned to this business
    const existingAssignment = await this.businessUserModel.findOne({
      businessId,
      userId: assignDto.userId,
      isActive: true,
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
          isActive: true,
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
        isActive: savedBusinessUser.isActive,
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
    // Check if unassigner has owner access to this business
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    const businessUser = await this.businessUserModel.findOne({
      businessId,
      userId: targetUserId,
      isActive: true,
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

    await this.businessUserModel.findByIdAndUpdate(businessUser._id, {
      isActive: false,
    });

    try {
      await this.tenantConnectionService.deactivateTenantUser(
        business.databaseName,
        targetUserId,
        userId
      );
    } catch {
      await this.businessUserModel.findByIdAndUpdate(businessUser._id, {
        isActive: true,
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

  private async checkBusinessAccess(
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
      isActive: true,
    });

    if (!businessUser) {
      throw new ForbiddenException('You do not have access to this business');
    }

    // If ownership is required (for update/delete), only owners can proceed
    if (requireOwnership && businessUser.role !== BusinessUserRole.OWNER) {
      throw new ForbiddenException(
        'Only business owners can modify business settings'
      );
    }
  }
}
