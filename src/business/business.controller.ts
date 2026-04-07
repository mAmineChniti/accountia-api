import {
  Controller,
  Get,
  Post,
  Put,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiOkResponse,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
  ApiBody,
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
  BusinessResponseDto,
  BusinessesListResponseDto,
  BusinessApplicationListResponseDto,
  AcceptInviteResponseDto,
  BusinessTeamResponseDto,
  CancelInviteResponseDto,
  InvitationPreviewResponseDto,
  InviteTeamMemberResponseDto,
} from '@/business/dto/business-response.dto';
import { BusinessStatisticsResponseDto } from '@/business/dto/business-statistics.dto';
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

import { InviteMemberDto } from '@/business/dto/invite-member.dto';
import { AcceptInviteDto } from '@/business/dto/accept-invite.dto';

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
  @Get('my-businesses')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get my businesses (Owners and Admins)',
    description:
      'Retrieve all businesses where current user is owner or admin. Only returns businesses managed by the user.',
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
      'Resolve tenant context using businessId from the request body and fetch tenant database metadata.',
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
      'Retrieve detailed information about a specific business. User must have access to the business and businessId must be provided in the request body to resolve tenant context.',
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
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Update business',
    description:
      'Update business information. Only accessible by business owners or administrators. Include businessId in the request body to resolve tenant context.',
  })
  @ApiBody({
    description:
      'Update business payload with businessId to resolve tenant context.',
    type: UpdateBusinessDto,
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
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER)
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
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Assign user to business',
    description:
      'Assign a user to a business with a specific role. BusinessId must be provided in the request body to resolve tenant context. Only accessible by business owners or administrators.',
  })
  @ApiBody({
    description:
      'Assign business user payload with businessId to resolve tenant context.',
    type: AssignBusinessUserDto,
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
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Unassign user from business',
    description:
      'Remove a user assignment from a business. Only accessible by business owners or administrators.',
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

  @Get(':id/clients')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get all clients for a business',
    description:
      'Retrieve all users linked to this business with the role client. Only accessible by business owners or administrators.',
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

  @Patch(':id/clients/:clientId/role')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Change a client role in the business',
    description:
      'Change the role of a user within the business. Include businessId in the request body to resolve tenant context. Only accessible by business owners or administrators.',
  })
  @ApiBody({
    description:
      'Client role change payload with businessId to resolve tenant context.',
    type: ChangeClientRoleDto,
  })
  @ApiParam({ name: 'id', description: 'Business ID' })
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
    @Param('id') id: string,
    @Param('clientId') clientId: string,
    @Body() changeRoleDto: ChangeClientRoleDto,
    @CurrentUser() user: UserPayload
  ) {
    return this.businessService.changeClientRole(
      id,
      clientId,
      changeRoleDto,
      user.id,
      user.role
    );
  }

  @Delete(':id/clients/:clientId')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Remove a user from the business',
    description:
      'Unlink/remove a user from this business. Cannot remove business owner. Only accessible by business owners or administrators.',
  })
  @ApiParam({ name: 'id', description: 'Business ID' })
  @ApiParam({ name: 'clientId', description: 'User ID to remove' })
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
    @Param('id') id: string,
    @Param('clientId') clientId: string,
    @CurrentUser() user: UserPayload
  ) {
    return this.businessService.deleteClient(id, clientId, user.id, user.role);
  }

  @Get(':id/statistics')
  @UseGuards(JwtAuthGuard, TenantContextGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get business statistics',
    description:
      'Retrieve business statistics showing product and invoice summary. Only accessible by authorized business members.',
  })
  @ApiParam({
    name: 'id',
    description: 'Business ID',
    example: '507f1f77bcf86cd799439011',
  })
  @ApiResponse({
    status: 200,
    description: 'Business statistics retrieved successfully',
    type: BusinessStatisticsResponseDto,
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
  async getBusinessStatistics(
    @Param('id') id: string,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessStatisticsResponseDto> {
    return this.businessService.getBusinessStatistics(id, user.id, user.role);
  }

  // --- Team & Invitations ---

  @Post(':id/invite')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Invite a team member',
    description:
      'Send an email invitation to join the business with a specific role.',
  })
  @ApiOkResponse({
    description: 'Invitation created successfully',
    type: InviteTeamMemberResponseDto,
  })
  async inviteTeamMember(
    @Param('id') id: string,
    @Body() inviteDto: InviteMemberDto,
    @CurrentUser() user: UserPayload
  ): Promise<InviteTeamMemberResponseDto> {
    return this.businessService.inviteTeamMember(id, inviteDto, user.id);
  }

  @Post('invite/accept')
  @ApiOperation({
    summary: 'Accept an invitation',
    description:
      'Accept an invitation using the token provided in the email and set up the user account.',
  })
  @ApiOkResponse({
    description: 'Invitation accepted successfully',
    type: AcceptInviteResponseDto,
  })
  async acceptInvite(
    @Body() acceptDto: AcceptInviteDto
  ): Promise<AcceptInviteResponseDto> {
    return this.businessService.acceptInvite(acceptDto);
  }

  @Get('invite/:token')
  @ApiOperation({
    summary: 'Get invitation preview',
    description:
      'Retrieve invitation details (email, business name, status) before account setup.',
  })
  @ApiOkResponse({
    description: 'Invitation preview retrieved',
    type: InvitationPreviewResponseDto,
  })
  async getInvitationPreview(
    @Param('token') token: string
  ): Promise<InvitationPreviewResponseDto> {
    return this.businessService.getInvitationPreview(token);
  }

  @Get(':id/team')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get all team members and pending invites',
    description: 'Retrieve all users and pending invitations for the business.',
  })
  @ApiOkResponse({
    description: 'Team members and pending invites retrieved successfully',
    type: BusinessTeamResponseDto,
  })
  async getBusinessTeam(
    @Param('id') id: string,
    @CurrentUser() user: UserPayload
  ): Promise<BusinessTeamResponseDto> {
    return this.businessService.getBusinessTeam(id, user.id, user.role);
  }

  @Delete(':id/invite/:inviteId')
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Cancel an invitation',
    description: 'Cancel a pending invitation for a user to join the business.',
  })
  @ApiOkResponse({
    description: 'Invitation cancelled successfully',
    type: CancelInviteResponseDto,
  })
  async cancelInvite(
    @Param('id') id: string,
    @Param('inviteId') inviteId: string
  ): Promise<CancelInviteResponseDto> {
    return this.businessService.cancelInvite(id, inviteId);
  }
}
