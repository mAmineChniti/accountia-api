import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Business, BusinessDocument } from './schemas/business.schema';
import {
  BusinessApplication,
  BusinessApplicationDocument,
} from './schemas/business-application.schema';
import {
  BusinessUser,
  BusinessUserDocument,
  BusinessUserRole,
} from './schemas/business-user.schema';
import { UpdateBusinessDto } from './dto/update-business.dto';
import {
  CreateBusinessApplicationDto,
  ReviewBusinessApplicationDto,
} from './dto/business-application.dto';
import { AssignBusinessUserDto } from './dto/business-user.dto';
import {
  BusinessResponseDto,
  BusinessesListResponseDto,
  BusinessApplicationListResponseDto,
} from './dto/business-response.dto';
import { BusinessApplicationResponseDto } from './dto/business-application.dto';
import { BusinessUserResponseDto } from './dto/business-user.dto';
import { Role } from '@/auth/enums/role.enum';
import { EmailService } from '@/auth/email.service';

@Injectable()
export class BusinessService {
  constructor(
    @InjectModel(Business.name) private businessModel: Model<BusinessDocument>,
    @InjectModel(BusinessApplication.name)
    private businessApplicationModel: Model<BusinessApplicationDocument>,
    @InjectModel(BusinessUser.name)
    private businessUserModel: Model<BusinessUserDocument>,
    private emailService: EmailService
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
    await this.emailService.sendBusinessApplicationEmail(
      userId,
      savedApplication.businessName
    );

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
    reviewerId: string
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
      // Create the business
      const databaseName = this.generateDatabaseName(application.businessName);
      const business = new this.businessModel({
        name: application.businessName,
        description: application.description,
        website: application.website,
        phone: application.phone,
        databaseName,
        status: 'approved',
        isActive: true,
      });

      const savedBusiness = await business.save();
      application.businessId = savedBusiness._id.toString();

      // Assign the applicant as business owner
      await this.businessUserModel.create({
        businessId: savedBusiness._id.toString(),
        userId: application.applicantId,
        role: BusinessUserRole.OWNER,
        assignedBy: reviewerId,
      });

      // Send approval email
      await this.emailService.sendBusinessApprovalEmail(
        application.applicantId,
        savedBusiness.name
      );
    } else {
      // Send rejection email
      await this.emailService.sendBusinessRejectionEmail(
        application.applicantId,
        application.businessName,
        reviewDto.reviewNotes
      );
    }

    const updatedApplication = await application.save();

    return {
      message: `Business application ${reviewDto.status} successfully`,
      application: {
        id: updatedApplication._id.toString(),
        businessName: updatedApplication.businessName,
        description: updatedApplication.description,
        website: updatedApplication.website,
        phone: updatedApplication.phone,
        applicantId: updatedApplication.applicantId,
        status: updatedApplication.status,
        createdAt: updatedApplication.createdAt,
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
      .select('businessName phone applicantId status createdAt')
      .sort({ createdAt: -1 })
      .lean();

    return {
      message: 'Business applications retrieved successfully',
      applications: applications.map((app) => ({
        id: app._id.toString(),
        businessName: app.businessName,
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

    // Delete all business user relationships
    await this.businessUserModel.deleteMany({ businessId });

    // Delete the business
    await this.businessModel.findByIdAndDelete(businessId);

    return { message: 'Business deleted successfully' };
  }

  async getMyBusinesses(
    userId: string,
    userRole: Role
  ): Promise<BusinessesListResponseDto> {
    // Check if user has permission to view businesses
    if (
      userRole !== Role.BUSINESS_OWNER &&
      userRole !== Role.BUSINESS_ADMIN &&
      userRole !== Role.PLATFORM_OWNER &&
      userRole !== Role.PLATFORM_ADMIN
    ) {
      throw new ForbiddenException(
        'You do not have permission to view businesses'
      );
    }

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

  // Business User Management
  async assignBusinessUser(
    businessId: string,
    assignDto: AssignBusinessUserDto,
    userId: string,
    userRole: Role
  ): Promise<BusinessUserResponseDto> {
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

    await this.businessUserModel.findByIdAndUpdate(businessUser._id, {
      isActive: false,
    });

    return { message: 'User unassigned from business successfully' };
  }

  // Helper methods
  private generateDatabaseName(businessName: string): string {
    return (
      businessName
        .toLowerCase()
        .replaceAll(/[^\da-z]/g, '_')
        .replaceAll(/_+/g, '_')
        .slice(0, 50) +
      '_' +
      Date.now()
    );
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
