import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { StatsService } from './stats.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';

@ApiTags('Stats')
@ApiBearerAuth() // <<< هذا يضيف زر Authorize في Swagger
@Controller('stats')
export class StatsController {
  constructor(private readonly statsService: StatsService) {}

  @UseGuards(JwtAuthGuard)
  @Get('monthly')
  getMonthly(@Req() req) {
    return this.statsService.getMonthlyStats(req.user.id);
  }
}