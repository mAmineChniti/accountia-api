import { Controller, Post, Get, Body, Req, UseGuards } from '@nestjs/common';
import { ExpensesService } from './expenses.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';

@ApiTags('Expenses')
@ApiBearerAuth()
@Controller('expenses') // 🔥 url correcte
export class ExpensesController {
  constructor(private readonly expensesService: ExpensesService) { } // 🔥 nom correct

  @UseGuards(JwtAuthGuard)
  @Get('statistics')
  getAdminStatistics() {
    return this.expensesService.getAdminStatistics();
  }

  @UseGuards(JwtAuthGuard)
  @Post()
  create(@Req() req, @Body() body: { amount: number; date: Date }) {
    return this.expensesService.create({
      ...body,
      user: req.user.id,
    });
  }
}