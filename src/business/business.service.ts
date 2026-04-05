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
import { Business } from '@/business/schemas/business.schema';
import { BusinessApplication } from '@/business/schemas/business-application.schema';
import { BusinessUser } from '@/business/schemas/business-user.schema';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { User } from '@/users/schemas/user.schema';
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
import { BusinessStatisticsResponseDto } from '@/business/dto/business-statistics.dto';
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

const isObjectRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

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

const isMissingCollectionError = (error: unknown): boolean => {
  if (!isObjectRecord(error)) {
    return false;
  }

  const code = error.code;
  const codeName = error.codeName;
  const name = error.name;
  const message = error.message;

  const isNamespaceCode = code === 26;
  const isNamespaceCodeName =
    typeof codeName === 'string' &&
    codeName.toUpperCase() === 'NAMESPACENOTFOUND';
  const isNamespaceName =
    typeof name === 'string' &&
    name.toUpperCase().includes('NAMESPACENOTFOUND');
  const isNamespaceMessage =
    typeof message === 'string' &&
    message.toUpperCase().includes('NAMESPACE NOT FOUND');

  return (
    isNamespaceCode ||
    isNamespaceCodeName ||
    isNamespaceName ||
    isNamespaceMessage
  );
};

@Injectable()
export class BusinessService {
  constructor(
    @InjectConnection() private readonly connection: Connection,
    @InjectModel(Business.name) private businessModel: Model<Business>,
    @InjectModel(BusinessApplication.name)
    private businessApplicationModel: Model<BusinessApplication>,
    @InjectModel(BusinessUser.name)
    private businessUserModel: Model<BusinessUser>,
    @InjectModel(User.name) private userModel: Model<User>,
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

    // Send email notification about application submission
    const applicant = await this.userModel
      .findById(userId)
      .catch((_error) => undefined as never);
    if (applicant) {
      try {
        await this.emailService.sendBusinessApplicationEmail(
          applicant.email,
          `${applicant.firstName} ${applicant.lastName}`,
          savedApplication.businessName
        );
      } catch {
        // Email service handles errors internally, but catch any unexpected issues
      }
    }

    // Send real-time admin notification
    try {
      await this.notificationsService.createNotification({
        type: NotificationType.NEW_BUSINESS_APPLICATION,
        message: `New business application: "${savedApplication.businessName}"`,
        payload: {
          applicationId: savedApplication._id.toString(),
          businessName: savedApplication.businessName,
          applicantId: userId,
        },
      });
    } catch {
      // Notification service handles errors internally
    }

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
        try {
          await this.emailService.sendBusinessApprovalEmail(
            appUser.email,
            `${appUser.firstName} ${appUser.lastName}`,
            approvedBusinessName
          );
        } catch {
          // Email service handles errors internally
        }
      }

      await this.auditService.logAction({
        action: AuditAction.APPROVE_BUSINESS,
        userId: reviewer.id,
        userEmail: reviewer.email ?? 'Unknown',
        userRole: reviewer.role ?? 'ADMIN',
        target: approvedBusinessName,
        details: { applicationId },
      });
    } else {
      await application.save();

      // Send rejection email
      const appUser = await this.userModel
        .findById(application.applicantId)
        .catch((_error) => undefined as never);
      if (appUser) {
        try {
          await this.emailService.sendBusinessRejectionEmail(
            appUser.email,
            `${appUser.firstName} ${appUser.lastName}`,
            application.businessName,
            reviewDto.reviewNotes ?? 'No specific reason provided'
          );
        } catch {
          // Email service handles errors internally
        }
      }

      await this.auditService.logAction({
        action: AuditAction.REJECT_BUSINESS,
        userId: reviewer.id,
        userEmail: reviewer.email ?? 'Unknown',
        userRole: reviewer.role ?? 'ADMIN',
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

    return { message: 'Business deleted successfully' };
  }

  async getMyBusinesses(userId: string): Promise<BusinessesListResponseDto> {
    // Find all businesses where user is OWNER or ADMIN at the business level
    let businessUsers = (await this.businessUserModel
      .find({
        userId,
        role: { $in: [BusinessUserRole.OWNER, BusinessUserRole.ADMIN] },
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
          await this.businessUserModel.create({
            businessId: approvedApplication.businessId,
            userId,
            role: BusinessUserRole.OWNER,
            assignedBy: userId,
          });

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
      ![BusinessUserRole.OWNER, BusinessUserRole.ADMIN].includes(
        businessUser.role
      )
    ) {
      throw new ForbiddenException(
        'Only business owners and administrators can modify business settings'
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
    userRole: Role
  ): Promise<BusinessStatisticsResponseDto> {
    // Check access
    await this.checkBusinessAccess(businessId, userId, userRole, false);

    // Get business
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Connect to tenant database to fetch statistics
    const tenantDb = this.connection.useDb(business.databaseName, {
      useCache: true,
    });

    // Get products statistics
    const productsCollection = tenantDb.collection('products');
    const invoicesCollection = tenantDb.collection('invoices');

    let productsStats = {
      totalProducts: 0,
      totalValue: 0,
      lowStockProducts: 0,
    };
    let invoicesStats = {
      totalInvoices: 0,
      paidAmount: 0,
      pendingAmount: 0,
      overdueAmount: 0,
      paidInvoices: 0,
      pendingInvoices: 0,
      overdueInvoices: 0,
    };

    const paidStatus = toInvoiceStatus(InvoiceStatus.PAID);
    const pendingStatus = toInvoiceStatus('PENDING');
    const overdueStatus = toInvoiceStatus(InvoiceStatus.OVERDUE);

    const paidLabelUpper = (paidStatus ?? 'paid').toUpperCase();
    const pendingLabelUpper = (pendingStatus ?? 'pending').toUpperCase();
    const overdueLabelUpper = (overdueStatus ?? 'overdue').toUpperCase();

    const pendingStatusVariants = [
      pendingLabelUpper,
      InvoiceStatus.DRAFT,
      InvoiceStatus.ISSUED,
      InvoiceStatus.VIEWED,
      InvoiceStatus.PARTIAL,
    ];

    try {
      const [productsAggregation] = await productsCollection
        .aggregate<{
          totalProducts: number;
          totalValue: number;
          lowStockProducts: number;
        }>([
          {
            $group: {
              _id: '_all',
              totalProducts: { $sum: 1 },
              totalValue: {
                $sum: {
                  $multiply: [
                    { $ifNull: ['$unitPrice', 0] },
                    { $ifNull: ['$quantity', 0] },
                  ],
                },
              },
              lowStockProducts: {
                $sum: {
                  $cond: [{ $lt: [{ $ifNull: ['$quantity', 0] }, 10] }, 1, 0],
                },
              },
            },
          },
        ])
        .toArray();

      if (productsAggregation) {
        productsStats = {
          totalProducts: toNumberOrZero(productsAggregation.totalProducts),
          totalValue: toNumberOrZero(productsAggregation.totalValue),
          lowStockProducts: toNumberOrZero(
            productsAggregation.lowStockProducts
          ),
        };
      }

      const [invoicesAggregation] = await invoicesCollection
        .aggregate<{
          totalInvoices: number;
          paidAmount: number;
          pendingAmount: number;
          overdueAmount: number;
          paidInvoices: number;
          pendingInvoices: number;
          overdueInvoices: number;
        }>([
          {
            $addFields: {
              normalizedStatus: {
                $toUpper: { $ifNull: ['$status', ''] },
              },
              normalizedTotalAmount: {
                $ifNull: ['$totalAmount', 0],
              },
            },
          },
          {
            $group: {
              _id: '_all',
              totalInvoices: { $sum: 1 },
              paidAmount: {
                $sum: {
                  $cond: [
                    { $eq: ['$normalizedStatus', paidLabelUpper] },
                    '$normalizedTotalAmount',
                    0,
                  ],
                },
              },
              pendingAmount: {
                $sum: {
                  $cond: [
                    {
                      $in: ['$normalizedStatus', pendingStatusVariants],
                    },
                    '$normalizedTotalAmount',
                    0,
                  ],
                },
              },
              overdueAmount: {
                $sum: {
                  $cond: [
                    { $eq: ['$normalizedStatus', overdueLabelUpper] },
                    '$normalizedTotalAmount',
                    0,
                  ],
                },
              },
              paidInvoices: {
                $sum: {
                  $cond: [{ $eq: ['$normalizedStatus', paidLabelUpper] }, 1, 0],
                },
              },
              pendingInvoices: {
                $sum: {
                  $cond: [
                    {
                      $in: ['$normalizedStatus', pendingStatusVariants],
                    },
                    1,
                    0,
                  ],
                },
              },
              overdueInvoices: {
                $sum: {
                  $cond: [
                    { $eq: ['$normalizedStatus', overdueLabelUpper] },
                    1,
                    0,
                  ],
                },
              },
            },
          },
        ])
        .toArray();

      if (invoicesAggregation) {
        invoicesStats = {
          totalInvoices: toNumberOrZero(invoicesAggregation.totalInvoices),
          paidAmount: toNumberOrZero(invoicesAggregation.paidAmount),
          pendingAmount: toNumberOrZero(invoicesAggregation.pendingAmount),
          overdueAmount: toNumberOrZero(invoicesAggregation.overdueAmount),
          paidInvoices: toNumberOrZero(invoicesAggregation.paidInvoices),
          pendingInvoices: toNumberOrZero(invoicesAggregation.pendingInvoices),
          overdueInvoices: toNumberOrZero(invoicesAggregation.overdueInvoices),
        };
      }
    } catch (error) {
      if (!isMissingCollectionError(error)) {
        console.error('Business statistics query failed', error);
        throw error;
      }
      // Missing collections are treated as empty statistics.
    }

    return {
      businessId: business._id.toString(),
      businessName: business.name,
      products: productsStats,
      invoices: invoicesStats,
      lastUpdated: new Date(),
    };
  }
}
