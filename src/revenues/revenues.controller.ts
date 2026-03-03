import { Controller, Post, Get, Body, Req, UseGuards } from '@nestjs/common';
import { RevenuesService } from './revenues.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AdminGuard } from '../auth/guards/admin.guard';
import { ApiBearerAuth, ApiTags, ApiResponse } from '@nestjs/swagger';
import { type CreateRevenueDto } from './dto/create-revenue.dto';
import { type AuthenticatedRequest } from '../common/types/authenticated-request.interface';

@ApiTags('Revenues')
@ApiBearerAuth()
@Controller('revenues')
export class RevenuesController {
  constructor(private readonly revenuesService: RevenuesService) {}

  @UseGuards(JwtAuthGuard, AdminGuard)
  @Get('statistics')
  @ApiResponse({
    status: 200,
    description: 'Admin statistics retrieved successfully',
  })
  getAdminStatistics() {
    return this.revenuesService.getAdminStatistics();
  }

  @UseGuards(JwtAuthGuard)
  @Post()
  @ApiResponse({ status: 201, description: 'Revenue created successfully' })
  create(@Req() req: AuthenticatedRequest, @Body() body: CreateRevenueDto) {
    return this.revenuesService.create({
      ...body,
      user: req.user?.id ?? '',
    });
  }
}
