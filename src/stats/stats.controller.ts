import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { StatsService } from './stats.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiBearerAuth, ApiTags, ApiResponse } from '@nestjs/swagger';
import { type AuthenticatedRequest } from '../common/types/authenticated-request.interface';

@ApiTags('Stats')
@ApiBearerAuth() // <<< هذا يضيف زر Authorize في Swagger
@Controller('stats')
export class StatsController {
  constructor(private readonly statsService: StatsService) {}

  @UseGuards(JwtAuthGuard)
  @Get('monthly')
  @ApiResponse({
    status: 200,
    description: 'Monthly statistics retrieved successfully',
  })
  getMonthly(@Req() req: AuthenticatedRequest) {
    return this.statsService.getMonthlyStats(req.user?.id ?? '');
  }
}
