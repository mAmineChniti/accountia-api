import {
  Controller,
  Post,
  Get,
  Patch,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { BusinessApplicationService } from './business-application.service';
import {
  CreateBusinessApplicationDto,
  BusinessApplicationResponseDto,
} from './dto/business-application.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { AdminGuard } from '@/auth/guards/admin.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';

@ApiTags('Business Application')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('business-application')
export class BusinessApplicationController {
  constructor(
    private readonly businessApplicationService: BusinessApplicationService
  ) {}

  // ─── CLIENT ────────────────────────────────────────────────────────────

  @Post()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'CLIENT — Apply for Business Owner access' })
  @ApiResponse({ status: 200, type: BusinessApplicationResponseDto })
  @ApiResponse({ status: 400, description: 'Not a client or invalid data' })
  @ApiResponse({ status: 409, description: 'Already applied' })
  async apply(
    @CurrentUser() user: UserPayload,
    @Body() dto: CreateBusinessApplicationDto
  ): Promise<BusinessApplicationResponseDto> {
    return this.businessApplicationService.apply(user.id, dto);
  }

  // ─── ADMIN ─────────────────────────────────────────────────────────────

  @Get()
  @UseGuards(AdminGuard)
  @ApiOperation({ summary: 'ADMIN — List all applications' })
  @ApiResponse({ status: 200, description: 'List of applications' })
  async findAll() {
    return this.businessApplicationService.findAll();
  }

  @Patch(':id/approve')
  @UseGuards(AdminGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'ADMIN — Approve application → user becomes BUSINESS_OWNER' })
  @ApiResponse({ status: 200, type: BusinessApplicationResponseDto })
  @ApiResponse({ status: 404, description: 'Application not found' })
  async approve(
    @Param('id') id: string
  ): Promise<BusinessApplicationResponseDto> {
    return this.businessApplicationService.approve(id);
  }

  @Patch(':id/reject')
  @UseGuards(AdminGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'ADMIN — Reject application' })
  @ApiResponse({ status: 200, type: BusinessApplicationResponseDto })
  @ApiResponse({ status: 404, description: 'Application not found' })
  async reject(
    @Param('id') id: string
  ): Promise<BusinessApplicationResponseDto> {
    return this.businessApplicationService.reject(id);
  }
}