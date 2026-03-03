import { Controller, Post, Get, Body, Req, UseGuards } from '@nestjs/common';
import { ExpensesService } from './expenses.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AdminGuard } from '../auth/guards/admin.guard';
import { ApiBearerAuth, ApiTags, ApiResponse } from '@nestjs/swagger';
import { type CreateExpenseDto } from './dto/create-expense.dto';
import { type AuthenticatedRequest } from '../common/types/authenticated-request.interface';

@ApiTags('Expenses')
@ApiBearerAuth()
@Controller('expenses') // 🔥 url correcte
export class ExpensesController {
  constructor(private readonly expensesService: ExpensesService) {} // 🔥 nom correct

  @UseGuards(JwtAuthGuard, AdminGuard)
  @Get('statistics')
  @ApiResponse({
    status: 200,
    description: 'Admin statistics retrieved successfully',
  })
  getAdminStatistics() {
    return this.expensesService.getAdminStatistics();
  }

  @UseGuards(JwtAuthGuard)
  @Post()
  @ApiResponse({ status: 201, description: 'Expense created successfully' })
  create(@Req() req: AuthenticatedRequest, @Body() body: CreateExpenseDto) {
    return this.expensesService.create({
      ...body,
      user: req.user?.id ?? '',
    });
  }
}
