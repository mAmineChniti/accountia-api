import { Controller, Post, Get, Body, Req, UseGuards } from '@nestjs/common';
import { RevenuesService } from './revenues.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';

@ApiTags('Revenues')
@ApiBearerAuth()
@Controller('revenues')
export class RevenuesController {
  constructor(private readonly revenuesService: RevenuesService) { }

  @UseGuards(JwtAuthGuard)
  @Get('statistics')
  getAdminStatistics() {
    return this.revenuesService.getAdminStatistics();
  }

  @UseGuards(JwtAuthGuard)
  @Post()
  create(@Req() req, @Body() body: { amount: number; date: Date }) {
    return this.revenuesService.create({
      ...body,
      user: req.user.id,
    });
  }
}