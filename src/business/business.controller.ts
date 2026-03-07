import {
  Controller,
  Get,
  Post,
  Put,
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
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
} from '@nestjs/swagger';
import { BusinessService } from '@/business/business.service';
import {
  CreateBusinessApplicationDto,
  ReviewBusinessApplicationDto,
} from '@/business/dto/business-application.dto';
import { UpdateBusinessDto } from '@/business/dto/update-business.dto';
import { AssignBusinessUserDto } from '@/business/dto/business-user.dto';
import {
  BusinessResponseDto,
  BusinessesListResponseDto,
  BusinessApplicationListResponseDto,
} from '@/business/dto/business-response.dto';
import { BusinessApplicationResponseDto } from '@/business/dto/business-application.dto';
import { BusinessUserResponseDto } from '@/business/dto/business-user.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RolesGuard } from '@/auth/guards/roles.guard';
import { Roles } from '@/auth/decorators/roles.decorator';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';
import { Role } from '@/auth/enums/role.enum';

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
    return this.businessService.reviewBusinessApplication(
      id,
      reviewDto,
      user.id
    );
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

  @Get(':id')
  @UseGuards(JwtAuthGuard)
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
  @UseGuards(JwtAuthGuard)
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
  @UseGuards(JwtAuthGuard)
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
  @UseGuards(JwtAuthGuard)
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
  @UseGuards(JwtAuthGuard)
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
}
