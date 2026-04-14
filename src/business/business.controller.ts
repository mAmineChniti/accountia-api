import {
  Controller,
  Get,
  Post,
  Put,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
  ApiBody,
  ApiQuery,
  ApiOkResponse,
} from '@nestjs/swagger';
import { BusinessService } from '@/business/business.service';
import {
  CreateBusinessApplicationDto,
  BusinessApplicationResponseDto,
  ReviewBusinessApplicationDto,
} from '@/business/dto/business-application.dto';
import { UpdateBusinessDto } from '@/business/dto/update-business.dto';
import {
  AssignBusinessUserDto,
  ChangeClientRoleDto,
  BusinessUserResponseDto,
} from '@/business/dto/business-user.dto';
import {
  InviteBusinessUserDto,
  BusinessInviteResponseDto,
  ResendInviteDto,
} from '@/business/dto/business-invite.dto';
import {
  BusinessResponseDto,
  BusinessesListResponseDto,
  BusinessApplicationListResponseDto,
} from '@/business/dto/business-response.dto';
import { BusinessStatisticsResponseDto } from '@/business/dto/business-statistics.dto';
import {
  StripeOnboardingLinkDto,
  StripeConnectStatusDto,
} from '@/business/dto/stripe-onboarding.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RolesGuard } from '@/auth/guards/roles.guard';
import { Roles } from '@/auth/decorators/roles.decorator';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';
import { Role } from '@/auth/enums/role.enum';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import {
  BusinessRolesGuard,
  BusinessRoles,
} from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import {
  type TenantContext,
  type TenantMetadata,
} from '@/common/tenant/tenant.types';

@ApiTags('Business')
@Controller('business')
@ApiResponse({
  status: 401,
  description: 'Unauthorized - Invalid or missing JWT token',
})
@ApiResponse({
  status: 403,
  description: 'Forbidden - Insufficient permissions',
})
@ApiResponse({ status: 500, description: 'Internal Server Error' })
export class BusinessController {
  private readonly logger = new Logger(BusinessController.name);

  constructor(private readonly businessService: BusinessService) {}

  // Business Application Endpoints
  @Post('apply')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB] Submit a business application',
    description:
      'Submit a new business application for review by platform administrators. Data is stored in: Platform-wide MongoDB database (accountia)',
  })
  @ApiResponse({
    status: 201,
    description: 'Business application submitted successfully',
    type: BusinessApplicationResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid input data or validation errors',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 409,
    description: 'Conflict - User already has a pending application',
  })
  async submitBusinessApplication(
    @Body() createApplicationDto: CreateBusinessApplicationDto,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessApplicationResponseDto> {
    return this.businessService.submitBusinessApplication(
      createApplicationDto,
      user.id
    );
  }

  @Get('applications')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB] Get all business applications (Admin only)',
    description:
      'Retrieve all business applications submitted to the platform. Data is queried from: Platform-wide MongoDB database (accountia). Only accessible by platform owners and administrators.',
  })
  @ApiResponse({
    status: 200,
    description: 'Business applications retrieved successfully',
    type: BusinessApplicationListResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - Insufficient permissions (Platform Owner/Admin required)',
  })
  async getBusinessApplications(
    @CurrentUser() user: UserPayload
  ): Promise<BusinessApplicationListResponseDto> {
    return this.businessService.getBusinessApplications(user.role);
  }

  @Post('applications/:id/review')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB] Review business application (Admin only)',
    description:
      'Review and approve/reject a business application. Data is updated in: Platform-wide MongoDB database (accountia). Only accessible by platform owners and administrators.',
  })
  @ApiResponse({
    status: 200,
    description: 'Business application reviewed successfully',
    type: BusinessApplicationResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid review data or status',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - Insufficient permissions (Platform Owner/Admin required)',
  })
  @ApiResponse({
    status: 404,
    description: 'Application not found',
  })
  async reviewBusinessApplication(
    @Param('id') id: string,
    @Body() reviewDto: ReviewBusinessApplicationDto,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessApplicationResponseDto> {
    return this.businessService.reviewBusinessApplication(id, reviewDto, user);
  }

  // Business Management Endpoints
  @Get('my-businesses')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB] Get my businesses (for Owners/Admins)',
    description:
      'Retrieve all businesses where current user is owner or admin. Data is queried from: Platform-wide MongoDB database (accountia). Only returns businesses managed by the user.',
  })
  @ApiResponse({
    status: 200,
    description: 'Businesses retrieved successfully',
    type: BusinessesListResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - Only business owners and admins can view their businesses',
  })
  async getMyBusinesses(
    @CurrentUser() user: UserPayload
  ): Promise<BusinessesListResponseDto> {
    return this.businessService.getMyBusinesses(user.id);
  }

  @Get('all')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB] Get all businesses (Admin only)',
    description:
      'Retrieve all businesses in the platform. Data is queried from: Platform-wide MongoDB database (accountia). Only accessible by platform owners and administrators.',
  })
  @ApiResponse({
    status: 200,
    description: 'Businesses retrieved successfully',
    type: BusinessesListResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - Insufficient permissions (Platform Owner/Admin required)',
  })
  async getAllBusinesses(
    @CurrentUser() user: UserPayload
  ): Promise<BusinessesListResponseDto> {
    return this.businessService.getAllBusinesses(user.role);
  }

  @Get('other')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get all other businesses basic info',
    description:
      'Retrieve a list of all businesses with id, name, and email only. Accessible by any authenticated user.',
  })
  @ApiResponse({
    status: 200,
    description: 'Businesses retrieved successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  async getOtherBusinesses(): Promise<{
    message: string;
    businesses: Array<{ id: string; name: string; email: string }>;
  }> {
    return this.businessService.getOtherBusinesses();
  }

  @Get('tenant/metadata')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[TENANT DB] Get tenant metadata for business',
    description:
      'Resolve and retrieve tenant context metadata using businessId from query parameter. Data is queried from: Tenant-specific MongoDB database. Endpoint: GET /business/tenant/metadata?businessId=<businessId>',
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiResponse({
    status: 200,
    description: 'Tenant metadata retrieved successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions to access this tenant',
  })
  @ApiResponse({
    status: 404,
    description: 'Business or tenant metadata not found',
  })
  async getTenantMetadata(@CurrentTenant() tenant: TenantContext): Promise<{
    message: string;
    tenant: TenantContext;
    metadata: TenantMetadata;
  }> {
    return this.businessService.getTenantMetadata(tenant);
  }

  @Get('details')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB → TENANT DB] Get business details',
    description:
      'Retrieve detailed information about a specific business. Data is queried from: Platform database (accountia) for business info and Tenant database for additional context. businessId is REQUIRED as a query parameter. Endpoint: GET /business/details?businessId=<businessId>',
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiResponse({
    status: 200,
    description: 'Business retrieved successfully',
    type: BusinessResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions to access this business',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async getBusinessById(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessResponseDto> {
    return this.businessService.getBusinessById(
      tenant.businessId,
      user.id,
      user.role
    );
  }

  @Put('update')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB] Update business',
    description:
      'Update business information. Data is updated in: Platform-wide MongoDB database (accountia). Only accessible by business owners or administrators. Include businessId in the request body to resolve tenant context.',
  })
  @ApiBody({
    description:
      'Update business payload with businessId to resolve tenant context.',
    type: UpdateBusinessDto,
  })
  @ApiResponse({
    status: 200,
    description: 'Business updated successfully',
    type: BusinessResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid update data or validation errors',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions to update this business',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async updateBusiness(
    @CurrentTenant() tenant: TenantContext,
    @Body() updateBusinessDto: UpdateBusinessDto,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessResponseDto> {
    return this.businessService.updateBusiness(
      tenant.businessId,
      updateBusinessDto,
      user.id,
      user.role
    );
  }

  @Delete('delete')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[PLATFORM DB] Delete business',
    description:
      'Delete a business. Data is deleted from: Platform-wide MongoDB database (accountia). Only accessible by business owners. Include businessId in the request body to resolve tenant context.',
  })
  @ApiResponse({
    status: 200,
    description: 'Business deleted successfully',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions',
  })
  @ApiResponse({ status: 404, description: 'Business not found' })
  async deleteBusiness(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<{ message: string }> {
    return this.businessService.deleteBusiness(
      tenant.businessId,
      user.id,
      user.role
    );
  }

  // Business User Management Endpoints
  @Post('users')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB + TENANT DB] Assign user to business',
    description:
      'Assign a user to a business with a specific role. Data is updated in: Platform database (accountia) for business user links and Tenant database for team management. Include businessId in the request body to resolve tenant context. Only accessible by business owners or administrators.',
  })
  @ApiBody({
    description:
      'Assign business user payload with businessId to resolve tenant context.',
    type: AssignBusinessUserDto,
  })
  @ApiResponse({
    status: 201,
    description: 'User assigned to business successfully',
    type: BusinessUserResponseDto,
  })
  @ApiResponse({
    status: 400,
    description:
      'Bad request - Invalid assignment data or user already assigned',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - Insufficient permissions to assign users to this business',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async assignBusinessUser(
    @CurrentTenant() tenant: TenantContext,
    @Body() assignDto: AssignBusinessUserDto,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessUserResponseDto> {
    return this.businessService.assignBusinessUser(
      tenant.businessId,
      assignDto,
      user.id,
      user.role
    );
  }

  @Delete('users/:userId')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[PLATFORM DB + TENANT DB] Unassign user from business',
    description:
      'Remove a user assignment from a business. Data is updated in: Platform database (accountia) and Tenant database. businessId is REQUIRED as a query parameter. Only accessible by business owners or administrators.',
  })
  @ApiParam({
    name: 'userId',
    description: 'User ID to unassign (MongoDB ObjectId)',
    example: '507f1f77bcf86cd799439012',
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiResponse({
    status: 200,
    description: 'User unassigned from business successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - Insufficient permissions to unassign users from this business',
  })
  @ApiResponse({
    status: 404,
    description: 'Business or user assignment not found',
  })
  async unassignBusinessUser(
    @Param('userId') userId: string,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<{ message: string }> {
    return this.businessService.unassignBusinessUser(
      tenant.businessId,
      userId,
      user.id,
      user.role
    );
  }

  @Get('clients')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[TENANT DB] Get all clients for a business',
    description:
      'Retrieve all users linked to this business with the role client. Data is queried from: Tenant-specific MongoDB database. businessId is REQUIRED as a query parameter. Endpoint: GET /business/clients?businessId=<businessId>',
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiResponse({
    status: 200,
    description: 'Clients retrieved successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions to access this business',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async getBusinessClients(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<{ message: string; clients: unknown[] }> {
    this.logger.log(
      `Getting business clients for businessId: ${tenant.businessId}, requested by userId: ${user.id}`
    );
    const result = await this.businessService.getBusinessClients(
      tenant.businessId,
      user.id,
      user.role
    );
    this.logger.log(
      `Retrieved ${result.clients.length} clients for businessId: ${tenant.businessId}`
    );
    this.logger.debug(`Clients data: ${JSON.stringify(result.clients)}`);
    return result;
  }

  @Patch(':id/clients/:clientId/role')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[TENANT DB] Change a client role in the business',
    description:
      'Change the role of a user within the business. Data is updated in: Tenant-specific MongoDB database. Include businessId in the request body to resolve tenant context. Only accessible by business owners or administrators.',
  })
  @ApiBody({
    description:
      'Client role change payload with businessId to resolve tenant context.',
    type: ChangeClientRoleDto,
  })
  @ApiParam({ name: 'clientId', description: 'Client User ID' })
  @ApiResponse({
    status: 200,
    description: 'Client role changed successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid role data',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions to change client role',
  })
  @ApiResponse({
    status: 404,
    description: 'Business or user not found',
  })
  async changeClientRole(
    @Param('clientId') clientId: string,
    @CurrentTenant() tenant: TenantContext,
    @Body() changeRoleDto: ChangeClientRoleDto,
    @CurrentUser() user: UserPayload
  ) {
    return this.businessService.changeClientRole(
      tenant.businessId,
      clientId,
      changeRoleDto,
      user.id,
      user.role
    );
  }

  @Delete('clients/:clientId')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[TENANT DB] Remove a user from the business',
    description:
      'Unlink/remove a user from this business. Data is updated in: Tenant-specific MongoDB database. businessId is REQUIRED as a query parameter. Cannot remove business owner. Only accessible by business owners or administrators.',
  })
  @ApiParam({ name: 'clientId', description: 'User ID to remove' })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiResponse({
    status: 200,
    description: 'User removed successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Cannot remove business owner',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions to remove users',
  })
  @ApiResponse({
    status: 404,
    description: 'Business or user not found',
  })
  async deleteClient(
    @Param('clientId') clientId: string,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ) {
    return this.businessService.deleteClient(
      tenant.businessId,
      clientId,
      user.id,
      user.role
    );
  }

  @Get('statistics')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[TENANT DB] Get business statistics with TensorFlow predictions',
    description:
      'Retrieve comprehensive business statistics including historical data and future predictions using TensorFlow models. Features revenue forecasting, product demand prediction, customer payment behavior analysis, product profitability optimization, and customer churn prediction. Data is aggregated from: Tenant-specific MongoDB database. businessId is REQUIRED as a query parameter. Endpoint: GET /business/statistics?businessId=<businessId>',
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiQuery({
    name: 'horizonDays',
    required: false,
    type: Number,
    description: 'Prediction horizon in days (default: 30)',
  })
  @ApiResponse({
    status: 200,
    description: 'Business statistics with predictions retrieved successfully',
    type: BusinessStatisticsResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - insufficient permissions',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async getBusinessStatistics(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload,
    @Query('businessId') businessId?: string,
    @Query('predictionHorizonDays') predictionHorizonDays?: string
  ): Promise<BusinessStatisticsResponseDto> {
    // If businessId is provided in query, validate it matches tenant context
    const effectiveBusinessId = businessId ?? tenant.businessId;
    if (businessId && businessId !== tenant.businessId) {
      throw new ForbiddenException(
        `Business ID in query parameter (${businessId}) does not match tenant context (${tenant.businessId})`
      );
    }
    const horizonDays = predictionHorizonDays
      ? Number.parseInt(predictionHorizonDays, 10)
      : 90;
    return this.businessService.getBusinessStatistics(
      effectiveBusinessId,
      user.id,
      user.role,
      horizonDays
    );
  }

  @Get('client-podium')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[TENANT DB] Get top paid clients podium',
    description:
      'Retrieve the top 3 recipients ranked by total amount of paid invoices only. This endpoint considers paid invoices for ranking and does not validate whether recipients have zero pending or overdue invoices. Includes platform users, external email-based recipients, and registered businesses. Data is aggregated from: Tenant-specific MongoDB database. businessId is REQUIRED as a query parameter. Endpoint: GET /business/client-podium?businessId=<businessId>',
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiResponse({
    status: 200,
    description: 'Client podium retrieved successfully',
    schema: {
      example: {
        businessId: '507f1f77bcf86cd799439011',
        podium: [
          {
            clientId: 'user_507f1f77bcf86cd799439012',
            clientName: 'John Doe',
            clientEmail: 'john@example.com',
            totalPaidAmount: 50_000,
            totalPaidInvoices: 5,
            medal: '🥇',
          },
          {
            clientId: 'external_jane@example.com',
            clientName: 'Jane Smith',
            clientEmail: 'jane@example.com',
            totalPaidAmount: 35_000,
            totalPaidInvoices: 3,
            medal: '🥈',
          },
          {
            clientId: 'business_507f1f77bcf86cd799439013',
            clientName: 'Acme Corp',
            clientEmail: '',
            totalPaidAmount: 25_000,
            totalPaidInvoices: 2,
            medal: '🥉',
          },
        ],
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions to access this business',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async getClientPodium(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
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
    return this.businessService.getClientPodium(
      tenant.businessId,
      user.id,
      user.role
    );
  }

  @Post('invites')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB] Send a business invitation',
    description:
      'Send an invitation to a user to join the business. Data is created in: Platform-wide MongoDB database (accountia). If the user exists, they are assigned directly. If not, a registration link is sent via email. businessId must be provided in the request body.',
  })
  @ApiBody({
    type: InviteBusinessUserDto,
    description: 'Invitation details with businessId',
  })
  @ApiResponse({
    status: 201,
    description: 'Invitation sent successfully',
    type: BusinessInviteResponseDto,
  })
  @ApiResponse({
    status: 400,
    description:
      'Bad request - Invalid email, invalid role, or user already invited',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async inviteBusinessUser(
    @Body() inviteDto: InviteBusinessUserDto,
    @CurrentUser() user: UserPayload,
    @CurrentTenant() _tenant: TenantContext
  ): Promise<BusinessInviteResponseDto> {
    return this.businessService.inviteBusinessUser(
      inviteDto.businessId,
      inviteDto,
      user.id,
      user.role
    );
  }

  @Post('invites/resend')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB] Resend a pending business invitation',
    description:
      'Resend an invitation email to a user. Data is queried and updated in: Platform-wide MongoDB database (accountia). Only pending invitations can be resent. businessId must be provided in the request body.',
  })
  @ApiBody({
    type: ResendInviteDto,
    description: 'Invite ID and businessId to resend',
  })
  @ApiResponse({
    status: 200,
    description: 'Invitation resent successfully',
    type: BusinessInviteResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invite is not pending',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions',
  })
  @ApiResponse({
    status: 404,
    description: 'Business or invite not found',
  })
  async resendInvite(
    @Body() resendDto: ResendInviteDto,
    @CurrentUser() user: UserPayload,
    @CurrentTenant() _tenant: TenantContext
  ): Promise<BusinessInviteResponseDto> {
    return this.businessService.resendInvite(
      resendDto.businessId,
      resendDto.inviteId,
      user.id,
      user.role
    );
  }

  // Team Management Endpoints
  @Get('team')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(
    BusinessUserRole.OWNER,
    BusinessUserRole.ADMIN,
    BusinessUserRole.MEMBER
  )
  @ApiBearerAuth()
  @ApiOperation({ summary: '[PLATFORM DB] Get business team members' })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiResponse({
    status: 200,
    description: 'Team members retrieved successfully',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions',
  })
  @ApiResponse({ status: 404, description: 'Business not found' })
  async getTeamMembers(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<{ message: string; members: unknown[] }> {
    return this.businessService.getTeamMembers(
      tenant.businessId,
      user.id,
      user.role
    );
  }

  @Get('invites/pending')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: '[PLATFORM DB] Get pending invitations' })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiOkResponse({
    description: 'Pending invites retrieved successfully',
    schema: {
      example: {
        message: 'Pending invites retrieved successfully',
        invites: [
          {
            id: '507f1f77bcf86cd799439013',
            invitedEmail: 'user@example.com',
            businessRole: 'CLIENT',
            inviterName: 'John Smith',
            emailSent: true,
            expiresAt: '2026-04-20T10:30:00.000Z',
            createdAt: '2026-04-13T10:30:00.000Z',
          },
        ],
      },
    },
  })
  async getPendingInvites(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<{ message: string; invites: unknown[] }> {
    return this.businessService.getPendingInvites(
      tenant.businessId,
      user.id,
      user.role
    );
  }

  @Delete('invites/:inviteId')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: '[PLATFORM DB] Revoke an invitation' })
  @ApiParam({ name: 'inviteId', description: 'Invitation ID to revoke' })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiOkResponse({
    description: 'Invitation revoked successfully',
    schema: {
      example: {
        message: 'Invite revoked successfully',
      },
    },
  })
  async revokeInvite(
    @Param('inviteId') inviteId: string,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<{ message: string }> {
    return this.businessService.revokeInvite(
      tenant.businessId,
      inviteId,
      user.id,
      user.role
    );
  }

  // Stripe Connect Integration Endpoints
  @Get('stripe/onboarding-link')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB] Get Stripe Connect onboarding link',
    description:
      'Generate a Stripe Connect onboarding link for this business. The business owner/admin can use this link to connect their Stripe account. businessId is REQUIRED as a query parameter.',
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiResponse({
    status: 200,
    description: 'Onboarding link generated successfully',
    type: StripeOnboardingLinkDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Must be business owner or admin',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async getStripeOnboardingLink(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<StripeOnboardingLinkDto> {
    return this.businessService.getStripeOnboardingLink(
      tenant.businessId,
      user.id,
      user.role
    );
  }

  @Get('stripe/status')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(
    BusinessUserRole.OWNER,
    BusinessUserRole.ADMIN,
    BusinessUserRole.CLIENT
  )
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[PLATFORM DB] Check Stripe Connect status',
    description:
      'Check if the business has a connected Stripe account and if it is fully set up for payments. businessId is REQUIRED as a query parameter.',
  })
  @ApiQuery({
    name: 'businessId',
    required: true,
    type: String,
    description:
      'Business ID (MongoDB ObjectId) - REQUIRED to resolve tenant context',
  })
  @ApiResponse({
    status: 200,
    description: 'Stripe Connect status retrieved successfully',
    type: StripeConnectStatusDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Must be part of the business',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async getStripeConnectStatus(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<StripeConnectStatusDto> {
    return this.businessService.getStripeConnectStatus(
      tenant.businessId,
      user.id,
      user.role
    );
  }
}
