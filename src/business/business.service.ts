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
import { EmailService } from '@/auth/email.service';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';
import {
  type TenantContext,
  type TenantMetadata,
} from '@/common/tenant/tenant.types';
import { AuthService } from '@/auth/auth.service'; // Assuming AuthService is needed for the new logic
import { StatisticsService } from '@/statistics/statistics.service';

@Injectable()
export class BusinessService {
  constructor(
    @InjectConnection() private readonly connection: Connection,
    @InjectModel(Business.name) private businessModel: Model<BusinessDocument>,
    @InjectModel(BusinessApplication.name)
    private businessApplicationModel: Model<BusinessApplicationDocument>,
    @InjectModel(BusinessUser.name)
    private businessUserModel: Model<BusinessUserDocument>,
    private emailService: EmailService,
    private tenantConnectionService: TenantConnectionService,
    private readonly authService: AuthService, // Added AuthService
    private readonly statisticsService: StatisticsService // Added StatisticsService
  ) { }

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

    // Send email notification about application submission asynchronously
    this.emailService.sendBusinessApplicationEmail(
      userId,
      savedApplication.businessName
    ).catch(err => console.error('Failed to send business application email:', err));

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
    reviewerId: string,
    reviewerUsername: string
  ): Promise<BusinessApplicationResponseDto> {
    const application =
      await this.businessApplicationModel.findById(applicationId);
    if (!application) {
      throw new NotFoundException('Business application not found');
    }

    if (application.status !== 'pending') {
      throw new BadRequestException('Application has already been reviewed');
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

      const session = await this.connection.startSession();
      session.startTransaction();
      let approvedBusinessName: string;
      try {
        // Use findOneAndUpdate to "claim" the reservation and fill in the details
        const savedBusiness = await this.businessModel.findOneAndUpdate(
          { databaseName, _isReservation: true },
          {
            $set: {
              name: application.businessName,
              description: application.description,
              website: application.website,
              phone: application.phone,
              status: 'approved',
              isActive: true,
              _isReservation: false,
            },
          },
          { session, new: true, runValidators: true, lean: true }
        );

        if (!savedBusiness) {
          throw new InternalServerErrorException('Database name reservation not found');
        }

        application.businessId = (savedBusiness._id as any).toString();
        approvedBusinessName = savedBusiness.name;

        await this.businessUserModel.create(
          [
            {
              businessId: (savedBusiness._id as any).toString(),
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

      // Send approval email asynchronously after successful commit
      this.emailService.sendBusinessApprovalEmail(
        application.applicantId,
        approvedBusinessName
      ).catch(e => console.error('Failed to send approval email', e));
    } else {
      await application.save();

      // Send rejection email asynchronously
      this.emailService.sendBusinessRejectionEmail(
        application.applicantId,
        application.businessName,
        reviewDto.reviewNotes
      ).catch(e => console.error('Failed to send rejection email', e));
    }

    // Log the review asynchronously
    this.statisticsService.createLog(
      reviewerId,
      reviewerUsername || 'System',
      reviewDto.status === 'approved' ? 'APPROVE' : 'REJECT',
      'BusinessApplication',
      { applicationId, businessName: application.businessName, notes: reviewDto.reviewNotes }
    ).catch(e => console.error('Failed to create audit log', e));

    return {
      message:
        reviewDto.status === 'approved'
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
        templateSettings: business.templateSettings,
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
        templateSettings: updatedBusiness.templateSettings,
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

  async createAndAssignClient(
    businessId: string,
    createClientDto: import('@/business/dto/create-client.dto').CreateClientDto,
    userId: string,
    userRole: Role
  ): Promise<{ message: string; client: any }> {
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    await this.checkBusinessAccess(businessId, userId, userRole, true);

    const clientUser = await this.authService.createClientUser(
      createClientDto.email,
      createClientDto.firstName,
      createClientDto.lastName,
      createClientDto.phoneNumber,
      createClientDto.password
    );

    const existingAssignment = await this.businessUserModel.findOne({
      businessId,
      userId: clientUser._id.toString(),
      isActive: true,
    });

    if (existingAssignment) {
      throw new BadRequestException('Client is already assigned to this business');
    }

    const businessUser = new this.businessUserModel({
      businessId,
      userId: clientUser._id.toString(),
      role: BusinessUserRole.CLIENT,
      assignedBy: userId,
    });

    const savedBusinessUser = await businessUser.save();

    try {
      await this.tenantConnectionService.upsertTenantUser(
        business.databaseName,
        {
          userId: clientUser._id.toString(),
          role: BusinessUserRole.CLIENT,
          assignedBy: userId,
          isActive: true,
        }
      );
    } catch {
      await this.businessUserModel.findByIdAndDelete(savedBusinessUser._id);
      throw new InternalServerErrorException('Failed to sync tenant user assignment');
    }

    return {
      message: 'Client created and assigned successfully',
      client: {
        id: clientUser._id,
        email: clientUser.email,
        firstName: clientUser.firstName,
        lastName: clientUser.lastName,
      },
    };
  }

  async getBusinessClients(
    businessId: string,
    userId: string,
    userRole: Role
  ) {
    await this.checkBusinessAccess(businessId, userId, userRole, true);

    const clientAssignments = await this.businessUserModel.find({
      businessId,
      role: BusinessUserRole.CLIENT,
      isActive: true,
    }).lean();

    if (clientAssignments.length === 0) {
      return { message: 'No clients found', clients: [] };
    }

    const userIds = clientAssignments.map((a) => a.userId);
    const usersData = await this.authService.fetchUsers(userIds);

    return {
      message: 'Clients retrieved successfully',
      clients: clientAssignments.map((ca) => ({
        id: ca.userId,
        createdAt: ca.createdAt,
      })),
      users: usersData,
    };
  }

  // Helper methods
  private async generateUniqueDatabaseName(
    businessName: string
  ): Promise<string> {
    const slug = this.generateDatabaseSlug(businessName);

    for (let attempt = 0; attempt < 5; attempt++) {
      const suffix = `${Date.now().toString(36)}_${randomBytes(3).toString('hex')}`;
      const databaseName = `${slug}_${suffix}`.slice(0, 63);

      // Atomically reserve the database name
      const reservation = await this.businessModel.findOneAndUpdate(
        { databaseName },
        {
          $setOnInsert: {
            databaseName,
            // Add a temporary flag to identify this as a reservation
            _isReservation: true,
            createdAt: new Date(),
          },
        },
        {
          upsert: true,
          new: true,
          lean: true,
        }
      );

      if (reservation) {
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
