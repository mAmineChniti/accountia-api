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
import { Transaction, TransactionDocument } from '@/business/schemas/transaction.schema';
import { Invoice, InvoiceDocument, InvoiceStatus } from '@/business/schemas/invoice.schema';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';
import { OnboardClientDto, UpdateClientDto } from '@/business/dto/business-user.dto';
import { hash } from 'bcrypt';
import { readFile } from 'node:fs/promises';
import { parse } from 'csv-parse/sync';
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
    @InjectModel(Transaction.name) private transactionModel: Model<TransactionDocument>,
    @InjectModel(Invoice.name) private invoiceModel: Model<InvoiceDocument>,
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

  async setupInitialBusiness(
    setupDto: CreateBusinessApplicationDto,
    ownerId: string
  ): Promise<BusinessResponseDto> {
    // Check if user already has any business
    const existingBusiness = await this.businessUserModel.findOne({
      userId: ownerId,
      isActive: true,
    });

    if (existingBusiness) {
      throw new BadRequestException('You already have an active business associated with your account');
    }

    // Regular setup logic (same as approval but direct)
    const databaseName = await this.generateUniqueDatabaseName(setupDto.businessName);

    await this.provisionBusinessTenantDatabase(
      databaseName,
      setupDto.businessName,
      ownerId,
      ownerId // Self-assigned
    );

    const business = new this.businessModel({
      name: setupDto.businessName,
      description: setupDto.description,
      website: setupDto.website,
      phone: setupDto.phone,
      databaseName,
      status: 'approved',
      isActive: true,
    });

    const session = await this.connection.startSession();
    session.startTransaction();
    let savedBusiness: BusinessDocument;

    try {
      savedBusiness = await business.save({ session });
      
      await this.businessUserModel.create(
        [
          {
            businessId: savedBusiness._id.toString(),
            userId: ownerId,
            role: BusinessUserRole.OWNER,
            assignedBy: ownerId,
          },
        ],
        { session }
      );

      await session.commitTransaction();
    } catch (error) {
      await session.abortTransaction();
      await this.dropTenantDatabase(databaseName);
      throw error;
    } finally {
      await session.endSession();
    }

    this.auditService.logAction({
      action: AuditAction.CREATE_BUSINESS,
      userId: ownerId,
      userEmail: 'Internal',
      userRole: Role.BUSINESS_OWNER,
      target: savedBusiness.name,
      details: { directSetup: true },
    });

    return {
      message: 'Business profile created successfully',
      business: {
        id: savedBusiness._id.toString(),
        name: savedBusiness.name,
        description: savedBusiness.description,
        website: savedBusiness.website,
        phone: savedBusiness.phone,
        databaseName: savedBusiness.databaseName,
        status: savedBusiness.status as string,
        isActive: savedBusiness.isActive,
        tags: savedBusiness.tags || [],
        createdAt: savedBusiness.createdAt,
        updatedAt: savedBusiness.updatedAt,
      },
    };
  }

  /**
   * Auto-provisions a business for BUSINESS_OWNERs who have no linked business.
   * Uses their approved application data if found, otherwise uses their profile.
   * Returns the businessId so the frontend can immediately proceed.
   */
  async autoProvisionBusiness(userId: string): Promise<{ businessId: string }> {
    // Check if already linked
    const existing = await this.businessUserModel.findOne({ userId, isActive: true });
    if (existing) {
      return { businessId: existing.businessId };
    }

    // Try to find approved application (with or without businessId)
    const application = await this.businessApplicationModel.findOne({
      applicantId: userId,
      status: 'approved',
    });

    // If the application already has a businessId, just link the user
    if (application?.businessId) {
      const business = await this.businessModel.findById(application.businessId);
      if (business) {
        await this.businessUserModel.create({
          businessId: application.businessId,
          userId,
          role: BusinessUserRole.OWNER,
          assignedBy: userId,
        });
        return { businessId: application.businessId };
      }
    }

    // No business exists — create one from application data or user profile
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('User not found');

    const businessName = application?.businessName
      ?? `${user.firstName ?? ''} ${user.lastName ?? ''}`.trim()
      ?? 'Mon Entreprise';

    const databaseName = await this.generateUniqueDatabaseName(businessName);

    await this.provisionBusinessTenantDatabase(databaseName, businessName, userId, userId);

    const business = new this.businessModel({
      name: businessName,
      description: application?.description ?? '',
      website: application?.website ?? '',
      phone: application?.phone ?? user.phoneNumber ?? '',
      databaseName,
      status: 'approved',
      isActive: true,
    });

    const session = await this.connection.startSession();
    session.startTransaction();
    let savedBusiness: BusinessDocument;

    try {
      savedBusiness = await business.save({ session });

      await this.businessUserModel.create(
        [{ businessId: savedBusiness._id.toString(), userId, role: BusinessUserRole.OWNER, assignedBy: userId }],
        { session }
      );

      // Update the application with the new businessId if it exists
      if (application) {
        application.businessId = savedBusiness._id.toString();
        await application.save({ session });
      }

      await session.commitTransaction();
    } catch (error) {
      await session.abortTransaction();
      await this.dropTenantDatabase(databaseName);
      throw error;
    } finally {
      await session.endSession();
    }

    return { businessId: savedBusiness._id.toString() };
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

  async findOne(id: string): Promise<BusinessDocument | null> {
    return this.businessModel.findById(id);
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
    let businessUsers = await this.businessUserModel
      .find({ userId, isActive: true })
      .select('businessId')
      .lean() as any[];

    // Rescue Logic: If user has no business linked but is a BUSINESS_OWNER, 
    // check if they have an APPROVED application and link it now.
    if (businessUsers.length === 0) {
      const approvedApplication = await this.businessApplicationModel.findOne({
        applicantId: userId,
        status: 'approved',
        businessId: { $exists: true, $ne: '' },
      });

      if (approvedApplication && approvedApplication.businessId) {
        const business = await this.businessModel.findById(approvedApplication.businessId);
        if (business) {
          await this.businessUserModel.create({
            businessId: approvedApplication.businessId as string,
            userId,
            role: BusinessUserRole.OWNER,
            assignedBy: userId,
          });
          
          businessUsers = [{ businessId: approvedApplication.businessId as string } as any];
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
  async onboardClient(
    businessId: string,
    onboardDto: OnboardClientDto,
    userId: string, // current user (Business Owner)
    userRole: Role
  ): Promise<BusinessUserResponseDto> {
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Check if current user has owner access to this business
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    // 1. Check if user already exists
    let clientUser = await this.userModel.findOne({ email: onboardDto.email });
    const isNewUser = !clientUser;
    let toSharePassword = '';

    if (!clientUser) {
      // Use the provided password, or generate a random one
      toSharePassword = onboardDto.password || randomBytes(4).toString('hex');
      const passwordHash = await hash(toSharePassword, 10);
      
      const newUser = new this.userModel({
        username: onboardDto.email.split('@')[0] + '_' + randomBytes(2).toString('hex'),
        email: onboardDto.email,
        passwordHash,
        firstName: onboardDto.firstName,
        lastName: onboardDto.lastName,
        phoneNumber: onboardDto.phoneNumber,
        birthdate: new Date(),
        role: Role.CLIENT,
        emailConfirmed: true,
        acceptTerms: true,
      });

      clientUser = await newUser.save();
    }

    if (!clientUser) {
      throw new InternalServerErrorException('Failed to create or retrieve client user');
    }

    // 2. Link user to business
    const existingLink = await this.businessUserModel.findOne({
      businessId,
      userId: clientUser._id.toString(),
    });

    if (existingLink) {
      throw new BadRequestException('User is already assigned to this business');
    }

    const businessUser = new this.businessUserModel({
      businessId,
      userId: clientUser._id.toString(),
      role: BusinessUserRole.CLIENT,
      assignedBy: userId,
    });

    const savedBusinessUser = await businessUser.save();

    // 2.5 Seed initial financial data for the client so they don't see an empty dashboard
    await this.seedInitialFinancialData(businessId, clientUser._id.toString());

    // 3. Send email credentials/notification
    const displayPassword = isNewUser ? toSharePassword : '*(Use your existing password)*';
    
    this.emailService.sendClientOnboardingEmail(
      clientUser.email,
      `${clientUser.firstName} ${clientUser.lastName}`,
      business.name,
      displayPassword,
      clientUser.email
    ).catch(err => console.error('Failed to send onboarding email:', err));


    return {
      message: isNewUser ? 'Client account created and linked successfully' : 'Existing user linked to business successfully',
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


  async getBusinessClients(
    businessId: string,
    userId: string,
    userRole: Role
  ): Promise<{ message: string; clients: any[] }> {
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Check if current user has access to this business
    await this.checkBusinessAccess(businessId, userId, userRole);

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
        address: c.address,
        vatNumber: c.vatNumber,
        iban: c.iban,
        createdAt: c.createdAt,
      })),
    };
  }

  async updateClient(
    businessId: string,
    clientId: string,
    updateClientDto: UpdateClientDto,
    userId: string,
    userRole: Role
  ): Promise<{ message: string; client: any }> {
    await this.checkBusinessAccess(businessId, userId, userRole);

    const businessUser = await this.businessUserModel.findOne({
      businessId,
      userId: clientId,
      role: BusinessUserRole.CLIENT,
    });

    if (!businessUser) {
      throw new NotFoundException('Client not found in this business');
    }

    const client = await this.userModel.findByIdAndUpdate(
      clientId,
      { $set: updateClientDto },
      { new: true }
    );

    if (!client) {
      throw new NotFoundException('User account not found');
    }

    return {
      message: 'Client updated successfully',
      client: {
        id: client._id.toString(),
        firstName: client.firstName,
        lastName: client.lastName,
        email: client.email,
        phoneNumber: client.phoneNumber,
        address: client.address,
        vatNumber: client.vatNumber,
        iban: client.iban,
      },
    };
  }

  async deleteClient(
    businessId: string,
    clientId: string,
    userId: string,
    userRole: Role
  ): Promise<{ message: string }> {
    await this.checkBusinessAccess(businessId, userId, userRole);

    const result = await this.businessUserModel.deleteOne({
      businessId,
      userId: clientId,
      role: BusinessUserRole.CLIENT,
    });

    if (result.deletedCount === 0) {
      throw new NotFoundException('Client association not found');
    }

    // Check if this user is linked to any other business
    const otherAssociations = await this.businessUserModel.countDocuments({
      userId: clientId,
    });

    if (otherAssociations === 0) {
      // If no other associations, we could potentially delete the user, 
      // but for safety in this version we just keep the orphaned account 
      // or we can delete if it was ONLY a managed client.
      // For now, unlinking is the core requirement.
    }

    return {
      message: 'Client removed from business successfully',
    };
  }

  // Seed mock financial data for a specific client
  private async seedInitialFinancialData(businessId: string, clientId: string): Promise<void> {
    console.log(`[DEBUG] Seeding initial financial data for client ${clientId} in business ${businessId}`);
    
    try {
      // 1. Generate 30 days of mock transactions
      const transactions: any[] = [];
      const now = new Date();
      
      // Use the last digit of the clientId to create a unique seed for variance
      const seed = parseInt(clientId.slice(-1), 16) || 0;
      const baseAmount = 500 + (seed * 100); // Varied base: 500 to 2000
      const volatility = 0.2 + (seed % 5) * 0.1; // Varied volatility

      for (let i = 0; i < 30; i++) {
        const date = new Date();
        date.setDate(now.getDate() - i);
        
        const isExpense = i % 3 === 0;
        const amount = baseAmount + Math.random() * baseAmount * volatility;
        
        transactions.push({
          transactionId: `TXN-${clientId.substring(0, 5)}-${i}-${Date.now()}`,
          date,
          accountType: isExpense ? 'Accounts Payable' : 'Accounts Receivable',
          amount: parseFloat(amount.toFixed(2)),
          cashFlow: isExpense ? -parseFloat(amount.toFixed(2)) : parseFloat(amount.toFixed(2)),
          netIncome: isExpense ? -parseFloat(amount.toFixed(2)) : parseFloat((amount * 0.4).toFixed(2)),
          revenue: isExpense ? 0 : parseFloat(amount.toFixed(2)),
          expenditure: isExpense ? parseFloat(amount.toFixed(2)) : 0,
          profitMargin: isExpense ? 0 : 40,
          operatingExpenses: isExpense ? parseFloat((amount * 0.1).toFixed(2)) : 0,
          grossProfit: isExpense ? 0 : parseFloat((amount * 0.9).toFixed(2)),
          accuracyScore: 98,
          hasMissingData: false,
          businessId,
          clientId,
        });
      }
      
      await this.transactionModel.insertMany(transactions);
      console.log(`[DEBUG] Seeded ${transactions.length} mock transactions for client ${clientId}`);

      // 2. Generate 2 mock invoices with varied descriptions
      const desc1 = seed % 2 === 0 ? 'Consulting Services' : 'Software Subscription';
      const desc2 = seed % 3 === 0 ? 'Maintenance Fee' : 'Hardware Supply';

      const invoices: any[] = [
        {
          invoiceNumber: `INV-${clientId.substring(0, 5)}-1`,
          description: desc1,
          amount: parseFloat((baseAmount * 2).toFixed(2)),
          currency: 'EUR',
          status: 'PAID',
          dueDate: new Date(),
          paidAt: new Date(),
          businessId,
          clientId,
        },
        {
          invoiceNumber: `INV-${clientId.substring(0, 5)}-2`,
          description: desc2,
          amount: parseFloat((baseAmount * 0.5).toFixed(2)),
          currency: 'EUR',
          status: 'PENDING',
          dueDate: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000),
          businessId,
          clientId,
        }
      ];
      
      await this.invoiceModel.insertMany(invoices);
      console.log(`[DEBUG] Seeded ${invoices.length} mock invoices for client ${clientId}`);
      
    } catch (error: any) {
      console.error('[DEBUG] Failed to seed initial data:', error.message);
      // We don't throw here to avoid blocking onboarding if seeding fails
    }
  }

  // Financial Data Management
  async importFinancialData(
    businessId: string,
    csvPath: string,
    userId: string,
    userRole: Role
  ): Promise<{ message: string; count: number }> {
    console.log(`[DEBUG importFinancialData] businessId=${businessId}, userId=${userId}, userRole=${userRole}, csvPath=${csvPath}`);
    
    try {
      await this.checkBusinessAccess(businessId, userId, userRole);
    } catch (err: any) {
      console.error('[DEBUG] checkBusinessAccess failed:', err.message);
      throw err;
    }

    // Fetch all clients for this business to distribute data
    const managedClients = await this.businessUserModel.find({ 
      businessId, 
      role: BusinessUserRole.CLIENT 
    });
    console.log(`[DEBUG] Found ${managedClients.length} managed clients for business ${businessId}`);

    try {
      const fileContent = await readFile(csvPath, 'utf-8');
      console.log(`[DEBUG] CSV file read successfully, length=${fileContent.length}`);
      const records = parse(fileContent, {
        columns: true,
        skip_empty_lines: true,
        trim: true,
      });
      console.log(`[DEBUG] Parsed ${records.length} records from CSV`);

      const transactions = records.map((record: any) => {
        // Randomly assign to one of the managed clients if any exist
        const randomClient = managedClients.length > 0 
          ? managedClients[Math.floor(Math.random() * managedClients.length)]
          : null;

        return {
          transactionId: record['Transaction ID'],
          date: new Date(record['Date']),
          accountType: record['Account Type'],
          amount: Number(record['Transaction Amount']),
          cashFlow: Number(record['Cash Flow']),
          netIncome: Number(record['Net Income']),
          revenue: Number(record['Revenue']),
          expenditure: Number(record['Expenditure']),
          profitMargin: Number(record['Profit Margin']),
          operatingExpenses: Number(record['Operating Expenses']),
          grossProfit: Number(record['Gross Profit']),
          accuracyScore: Number(record['Accuracy Score']),
          hasMissingData: record['Missing Data Indicator']?.toLowerCase() === 'true',
          businessId,
          clientId: randomClient ? randomClient.userId : undefined,
        };
      });

      // Clear existing transactions and invoices for this business to avoid duplicates during re-import
      await this.transactionModel.deleteMany({ businessId });
      await this.invoiceModel.deleteMany({ businessId });
      
      try {
        await this.invoiceModel.collection.dropIndex('invoiceNumber_1_businessOwnerId_1');
        console.log('[DEBUG] Dropped deprecated invoice index');
      } catch (e) {
        // Index might not exist, ignore
      }
      
      const result = await this.transactionModel.insertMany(transactions);
      console.log(`[DEBUG] Inserted ${result.length} transactions`);

      // --- Seed Invoices for each client ---
      for (const client of managedClients) {
        const clientInvoices = [
          {
            invoiceNumber: `INV-${businessId.substring(0, 4)}-${client.userId.substring(0, 3)}-1`,
            description: 'Consultation Services',
            amount: 1500 + Math.random() * 1000,
            currency: 'USD',
            status: 'PAID',
            dueDate: new Date(),
            businessId,
            clientId: client.userId,
          },
          {
            invoiceNumber: `INV-${businessId.substring(0, 4)}-${client.userId.substring(0, 3)}-2`,
            description: 'Monthly Maintenance',
            amount: 500 + Math.random() * 500,
            currency: 'USD',
            status: 'PENDING',
            dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            businessId,
            clientId: client.userId,
          }
        ];
        console.log(`[DEBUG] Seeding ${clientInvoices.length} invoices for client ${client.userId}`);
        await this.invoiceModel.insertMany(clientInvoices);
      }

      console.log(`[DEBUG] Successfully seeded invoices for ${managedClients.length} clients`);
      return {
        message: 'Financial data imported successfully',
        count: result.length,
      };
    } catch (error: any) {
      console.error('[DEBUG] CSV Import Error:', error.message, error.stack);
      throw new BadRequestException(`Failed to import CSV: ${error.message}`);
    }
  }

  async getManagedFinancials(
    businessId: string,
    userId: string,
    userRole: Role,
    clientId?: string
  ): Promise<{ transactions: any[] }> {
    await this.checkBusinessAccess(businessId, userId, userRole);

    const query: any = { businessId };
    let clientEmail: string | null = null;
    
    // Strict isolation: Clients only see their own assigned transactions
    if (userRole === Role.CLIENT) {
      query.clientId = userId;
      // Get the client's email to fetch associated invoices
      const user = await this.userModel.findById(userId).select('email').lean();
      clientEmail = user?.email || null;
    } else if (clientId) {
      // Owners can filter by a specific client if provided
      query.clientId = clientId;
      const user = await this.userModel.findById(clientId).select('email').lean();
      clientEmail = user?.email || null;
    }

    const transactions = await this.transactionModel
      .find(query)
      .sort({ date: 1 })
      .lean() as any[];

    // Include invoices as real data points (treated as expenditures for the client)
    const invoiceTransactions: any[] = [];
    if (clientEmail) {
      const invoices = await this.invoiceModel.find({
        clientEmail,
        status: { $in: [InvoiceStatus.SENT, InvoiceStatus.PAID, InvoiceStatus.PENDING] },
        $or: [
          { deletedAt: { $exists: false } },
          { deletedAt: null }
        ]
      }).lean();

      for (const inv of invoices) {
        invoiceTransactions.push({
          id: inv._id.toString(),
          date: inv.issueDate,
          amount: inv.total,
          revenue: 0,
          expenditure: inv.total,
          netIncome: -inv.total,
          cashFlow: inv.status === InvoiceStatus.PAID ? -inv.total : 0,
          accountType: 'Invoice',
          description: `Invoice ${inv.invoiceNumber}`
        });
      }
    }

    const combinedTransactions = [
      ...transactions.map(t => ({
        id: t._id.toString(),
        date: t.date,
        amount: t.amount,
        revenue: t.revenue,
        expenditure: t.expenditure,
        netIncome: t.netIncome,
        cashFlow: t.cashFlow,
        accountType: t.accountType,
      })),
      ...invoiceTransactions
    ].sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

    return {
      transactions: combinedTransactions,
    };
  }

  async getBusinessInvoices(
    businessId: string,
    userId: string,
    userRole: Role,
    clientId?: string
  ): Promise<{ invoices: any[] }> {
    await this.checkBusinessAccess(businessId, userId, userRole);

    const query: any = { businessOwnerId: businessId };
    
    // The invoices module now handles the strict isolation
    // This is a legacy method - use the InvoicesController instead
    // Only return non-deleted invoices
    query.deletedAt = { $exists: false };

    console.log(`[DEBUG] Fetching invoices for business ${businessId} with query:`, query);

    const invoices = await this.invoiceModel
      .find(query)
      .sort({ createdAt: -1 })
      .lean();

    console.log(`[DEBUG] Found ${invoices.length} invoices for query:`, query);

    return {
      invoices: invoices.map(inv => ({
        id: inv._id.toString(),
        invoiceNumber: inv.invoiceNumber,
        clientName: inv.clientName,
        clientEmail: inv.clientEmail,
        currency: inv.currency,
        status: inv.status,
        subtotal: inv.subtotal,
        taxAmount: inv.taxAmount,
        total: inv.total,
        issueDate: inv.issueDate,
        dueDate: inv.dueDate,
        createdAt: inv.createdAt,
        paidAt: inv.paidAt,
        notes: inv.notes,
      })),
    };
  }
}
