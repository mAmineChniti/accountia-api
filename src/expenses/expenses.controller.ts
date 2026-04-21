import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  Query as QueryParam,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiBearerAuth,
  ApiQuery,
  ApiParam,
  ApiConsumes,
  ApiBody,
} from '@nestjs/swagger';
import { ExpensesService } from './expenses.service';
import { ReceiptExtractionService } from './services/receipt-extraction.service';
import {
  CreateExpenseDto,
  UpdateExpenseDto,
  ReviewExpenseDto,
  ExpenseResponseDto,
  ExpenseListResponseDto,
  ExpenseSummaryDto,
} from './dto/expense.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import { BusinessRolesGuard, BusinessRoles } from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import type { TenantContext } from '@/common/tenant/tenant.types';
import type { UserPayload } from '@/auth/types/auth.types';

@ApiTags('Expenses')
@Controller('expenses')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
@BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN, BusinessUserRole.MEMBER)
export class ExpensesController {
  constructor(
    private readonly expensesService: ExpensesService,
    private readonly receiptExtractionService: ReceiptExtractionService
  ) {}

  @Post('extract-receipt')
  @ApiOperation({ summary: 'Extract expense data from a receipt image or PDF using AI' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        file: { type: 'string', format: 'binary' },
        businessId: { type: 'string' },
      },
    },
  })
  @UseInterceptors(FileInterceptor('file', { limits: { fileSize: 10 * 1024 * 1024 } }))
  async extractReceipt(
    @UploadedFile() file: Express.Multer.File
  ) {
    if (!file) throw new Error('No file uploaded');
    return this.receiptExtractionService.extractFromFile(file);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a new expense' })
  @ApiCreatedResponse({ type: ExpenseResponseDto })
  async create(
    @Body() dto: CreateExpenseDto,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<ExpenseResponseDto> {
    const userName = `${user.firstName} ${user.lastName}`.trim() || user.username;
    return this.expensesService.create(
      tenant.businessId,
      tenant.databaseName,
      dto,
      user.id,
      userName
    );
  }

  @Get()
  @ApiOperation({ summary: 'List expenses' })
  @ApiOkResponse({ type: ExpenseListResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'status', required: false, type: String })
  @ApiQuery({ name: 'category', required: false, type: String })
  async findAll(
    @CurrentTenant() tenant: TenantContext,
    @Query('page') page = 1,
    @Query('limit') limit = 10,
    @Query('status') status?: string,
    @Query('category') category?: string
  ): Promise<ExpenseListResponseDto> {
    return this.expensesService.findByBusiness(
      tenant.businessId,
      tenant.databaseName,
      page,
      limit,
      status,
      category
    );
  }

  @Get('summary')
  @ApiOperation({ summary: 'Get expense analytics summary' })
  @ApiOkResponse({ type: ExpenseSummaryDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  async getSummary(
    @CurrentTenant() tenant: TenantContext
  ): Promise<ExpenseSummaryDto> {
    return this.expensesService.getSummary(tenant.businessId, tenant.databaseName);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get expense by ID' })
  @ApiOkResponse({ type: ExpenseResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async findById(
    @Param('id') id: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<ExpenseResponseDto> {
    return this.expensesService.findById(id, tenant.businessId, tenant.databaseName);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a draft expense' })
  @ApiOkResponse({ type: ExpenseResponseDto })
  @ApiParam({ name: 'id', type: String })
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateExpenseDto,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<ExpenseResponseDto> {
    return this.expensesService.update(id, tenant.businessId, tenant.databaseName, dto, user.id);
  }

  @Patch(':id/submit')
  @ApiOperation({ summary: 'Submit expense for review' })
  @ApiOkResponse({ type: ExpenseResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async submit(
    @Param('id') id: string,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<ExpenseResponseDto> {
    return this.expensesService.submit(id, tenant.businessId, tenant.databaseName, user.id);
  }

  @Patch(':id/review')
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({ summary: 'Approve or reject an expense (Admin/Owner only)' })
  @ApiOkResponse({ type: ExpenseResponseDto })
  @ApiParam({ name: 'id', type: String })
  async review(
    @Param('id') id: string,
    @Body() dto: ReviewExpenseDto,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<ExpenseResponseDto> {
    return this.expensesService.review(id, tenant.businessId, tenant.databaseName, dto, user.id);
  }

  @Patch(':id/reimburse')
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @ApiOperation({ summary: 'Mark expense as reimbursed' })
  @ApiOkResponse({ type: ExpenseResponseDto })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async markReimbursed(
    @Param('id') id: string,
    @Query('businessId') _businessId: string,
    @CurrentTenant() tenant: TenantContext
  ): Promise<ExpenseResponseDto> {
    void _businessId;
    return this.expensesService.markReimbursed(id, tenant.businessId, tenant.databaseName);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete a draft expense' })
  @ApiQuery({ name: 'businessId', required: true, type: String })
  @ApiParam({ name: 'id', type: String })
  async delete(
    @Param('id') id: string,
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: UserPayload
  ): Promise<void> {
    return this.expensesService.delete(id, tenant.businessId, tenant.databaseName, user.id);
  }
}
