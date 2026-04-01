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
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
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
  OnboardClientDto,
  UpdateClientDto,
  BusinessUserResponseDto,
} from '@/business/dto/business-user.dto';
import {
  BusinessResponseDto,
  BusinessesListResponseDto,
  BusinessApplicationListResponseDto,
} from '@/business/dto/business-response.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RolesGuard } from '@/auth/guards/roles.guard';
import { Roles } from '@/auth/decorators/roles.decorator';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';
import { Role } from '@/auth/enums/role.enum';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
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
  constructor(private readonly businessService: BusinessService) {}

  // Business Application Endpoints
  @Post('apply')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Submit a business application',
    description:
      'Submit a new business application for review. The application will be reviewed by platform administrators.',
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
    console.log('🔐 submitBusinessApplication - Current User:', {
      id: user?.id,
      email: user?.email,
      role: user?.role,
    });
    return this.businessService.submitBusinessApplication(
      createApplicationDto,
      user.id
    );
  }

  /* 
  @Get(':id/invoices')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get all invoices for a business',
    description: 'Retrieve invoices. Strictly isolated for clients.',
  })
  @ApiParam({ name: 'id', description: 'Business ID' })
  async getBusinessInvoices(
    @Param('id') id: string,
    @CurrentUser() user: UserPayload,
    @Query('clientId') clientId?: string
  ) {
    return this.businessService.getBusinessInvoices(id, user.id, user.role, clientId);
  }
  */

  @Post('setup')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.BUSINESS_OWNER)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Directly setup a business profile (Business Owners only)',
    description:
      'Allow users with the BUSINESS_OWNER role to create their business profile directly if they do not have one yet.',
  })
  @ApiResponse({
    status: 201,
    description: 'Business profile created successfully',
    type: BusinessResponseDto,
  })
  async setupInitialBusiness(
    @Body() setupDto: CreateBusinessApplicationDto,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessResponseDto> {
    return this.businessService.setupInitialBusiness(setupDto, user.id);
  }

  @Post('auto-provision')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.BUSINESS_OWNER)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Auto-provision a business for an approved owner',
    description:
      'Silently links or creates a business for an approved BUSINESS_OWNER.',
  })
  @ApiResponse({
    status: 200,
    description: 'Business auto-provisioned successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - Insufficient permissions (BUSINESS_OWNER required)',
  })
  async autoProvisionBusiness(
    @CurrentUser() user: UserPayload
  ): Promise<{ businessId: string }> {
    return this.businessService.autoProvisionBusiness(user.id);
  }

  @Get('applications')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get all business applications (Platform Admin only)',
    description:
      'Retrieve all business applications submitted to the platform. Only accessible by platform owners and administrators.',
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
    summary: 'Review business application (Platform Admin only)',
    description:
      'Review and approve/reject a business application. Only accessible by platform owners and administrators.',
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
  @Get('my')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get my businesses',
    description:
      'Retrieve all businesses associated with the current user. Includes businesses where user is owner or assigned member.',
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
    summary: 'Get all businesses (Platform Admin only)',
    description:
      'Retrieve all businesses in the platform. Only accessible by platform owners and administrators.',
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

  @Get(':id/tenant/metadata')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get tenant metadata for business',
    description:
      'Resolve tenant context from the business route and fetch tenant database metadata.',
  })
  @ApiParam({
    name: 'id',
    description: 'Business ID (MongoDB ObjectId)',
    example: '507f1f77bcf86cd799439011',
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

  @Get(':id')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get business by ID',
    description:
      'Retrieve detailed information about a specific business. User must have access to the business (owner, assigned member, or platform admin).',
  })
  @ApiParam({
    name: 'id',
    description: 'Business ID (MongoDB ObjectId)',
    example: '507f1f77bcf86cd799439011',
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
    @Param('id') id: string,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessResponseDto> {
    return this.businessService.getBusinessById(id, user.id, user.role);
  }

  @Put(':id')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Update business',
    description:
      'Update business information. Only accessible by business owners or platform administrators.',
  })
  @ApiParam({
    name: 'id',
    description: 'Business ID (MongoDB ObjectId)',
    example: '507f1f77bcf86cd799439011',
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
    @Param('id') id: string,
    @Body() updateBusinessDto: UpdateBusinessDto,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessResponseDto> {
    return this.businessService.updateBusiness(
      id,
      updateBusinessDto,
      user.id,
      user.role
    );
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Delete business' })
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
    @Param('id') id: string,
    @CurrentUser() user: UserPayload
  ): Promise<{ message: string }> {
    return this.businessService.deleteBusiness(id, user.id, user.role);
  }

  // Business User Management Endpoints
  @Post(':id/users')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Assign user to business',
    description:
      'Assign a user to a business with a specific role. Only accessible by business owners.',
  })
  @ApiParam({
    name: 'id',
    description: 'Business ID (MongoDB ObjectId)',
    example: '507f1f77bcf86cd799439011',
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
    @Param('id') id: string,
    @Body() assignDto: AssignBusinessUserDto,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessUserResponseDto> {
    return this.businessService.assignBusinessUser(
      id,
      assignDto,
      user.id,
      user.role
    );
  }

  @Delete(':id/users/:userId')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Unassign user from business',
    description:
      'Remove a user assignment from a business. Only accessible by business owners.',
  })
  @ApiParam({
    name: 'id',
    description: 'Business ID (MongoDB ObjectId)',
    example: '507f1f77bcf86cd799439011',
  })
  @ApiParam({
    name: 'userId',
    description: 'User ID to unassign (MongoDB ObjectId)',
    example: '507f1f77bcf86cd799439012',
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
    @Param('id') id: string,
    @Param('userId') userId: string,
    @CurrentUser() user: UserPayload
  ): Promise<{ message: string }> {
    return this.businessService.unassignBusinessUser(
      id,
      userId,
      user.id,
      user.role
    );
  }

  @Post(':id/onboard-client')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Onboard a new client for a business',
    description:
      'Create a new client user account and link it to the business. Only accessible by business owners.',
  })
  @ApiParam({
    name: 'id',
    description: 'Business ID (MongoDB ObjectId)',
    example: '507f1f77bcf86cd799439011',
  })
  @ApiResponse({
    status: 201,
    description: 'Client onboarded successfully',
    type: BusinessUserResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid client data or already assigned',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - Insufficient permissions to onboard clients for this business',
  })
  async onboardClient(
    @Param('id') id: string,
    @Body() onboardDto: OnboardClientDto,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessUserResponseDto> {
    return this.businessService.onboardClient(
      id,
      onboardDto,
      user.id,
      user.role
    );
  }

  @Get(':id/clients')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get all clients for a business',
    description:
      'Retrieve all users linked to this business with the role client. Only accessible by business owners.',
  })
  @ApiParam({
    name: 'id',
    description: 'Business ID (MongoDB ObjectId)',
    example: '507f1f77bcf86cd799439011',
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
    @Param('id') id: string,
    @CurrentUser() user: UserPayload
  ): Promise<{ message: string; clients: Array<Record<string, unknown>> }> {
    return this.businessService.getBusinessClients(id, user.id, user.role);
  }

  @Patch(':id/clients/:clientId')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Update a client profile and billing info',
    description: 'Update user data and billing fields for a specific client.',
  })
  @ApiParam({ name: 'id', description: 'Business ID' })
  @ApiParam({ name: 'clientId', description: 'Client User ID' })
  @ApiResponse({
    status: 200,
    description: 'Client updated successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid update data',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions to update this client',
  })
  @ApiResponse({
    status: 404,
    description: 'Business or client not found',
  })
  async updateClient(
    @Param('id') id: string,
    @Param('clientId') clientId: string,
    @Body() updateClientDto: UpdateClientDto,
    @CurrentUser() user: UserPayload
  ) {
    return this.businessService.updateClient(
      id,
      clientId,
      updateClientDto,
      user.id,
      user.role
    );
  }

  @Delete(':id/clients/:clientId')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Remove a client from the business',
    description: 'Unlink a client from this business.',
  })
  @ApiParam({ name: 'id', description: 'Business ID' })
  @ApiParam({ name: 'clientId', description: 'Client User ID' })
  @ApiResponse({
    status: 200,
    description: 'Client removed successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Insufficient permissions to remove clients',
  })
  @ApiResponse({
    status: 404,
    description: 'Business or client not found',
  })
  async deleteClient(
    @Param('id') id: string,
    @Param('clientId') clientId: string,
    @CurrentUser() user: UserPayload
  ) {
    return this.businessService.deleteClient(id, clientId, user.id, user.role);
  }

  @Post(':id/import-financials')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Roles(Role.BUSINESS_OWNER)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Import financial data from CSV',
    description: 'Import financial data for the business from a CSV file.',
  })
  @ApiParam({ name: 'id', description: 'Business ID' })
  @ApiResponse({
    status: 200,
    description: 'Financial data imported successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid file or format',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - Insufficient permissions (BUSINESS_OWNER required)',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async importFinancials(
    @Param('id') businessId: string,
    @CurrentUser() user: UserPayload
  ) {
    // For now, we use the local path to accounting_data.csv provided by the user
    const csvPath = String.raw`C:\Users\Asus\Downloads\accounting_data.csv`;
    return this.businessService.importFinancialData(
      businessId,
      csvPath,
      user.id,
      user.role
    );
  }

  @Get(':id/managed-financials')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Roles(Role.BUSINESS_OWNER, Role.CLIENT)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get financial data for managed clients',
    description: 'Retrieve financial data for managed clients in the business.',
  })
  @ApiParam({ name: 'id', description: 'Business ID' })
  @ApiResponse({
    status: 200,
    description: 'Financial data retrieved successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - Insufficient permissions (BUSINESS_OWNER or CLIENT required)',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async getManagedFinancials(
    @Param('id') businessId: string,
    @CurrentUser() user: UserPayload,
    @Query('clientId') clientId?: string
  ) {
    return this.businessService.getManagedFinancials(
      businessId,
      user.id,
      user.role,
      clientId
    );
  }

  @Get(':id/dashboard')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @Roles(Role.BUSINESS_OWNER, Role.BUSINESS_ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get business dashboard statistics',
    description: 'Retrieve dashboard statistics and metrics for the business.',
  })
  @ApiParam({ name: 'id', description: 'Business ID' })
  @ApiResponse({
    status: 200,
    description: 'Dashboard statistics retrieved successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  @ApiResponse({
    status: 403,
    description:
      'Forbidden - Insufficient permissions (BUSINESS_OWNER or BUSINESS_ADMIN required)',
  })
  @ApiResponse({
    status: 404,
    description: 'Business not found',
  })
  async getBusinessDashboard(
    @Param('id') businessId: string,
    @CurrentUser() user: UserPayload
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ): Promise<Record<string, any>> {
    return this.businessService.getBusinessDashboard(
      businessId,
      user.id,
      user.role
    );
  }
}
