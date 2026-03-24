import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
  ApiResponse,
} from '@nestjs/swagger';
import { AuditService } from './audit.service';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { RolesGuard } from '@/auth/guards/roles.guard';
import { Roles } from '@/auth/decorators/roles.decorator';
import { Role } from '@/auth/enums/role.enum';
import { AuditAction } from './schemas/audit-log.schema';
import { PaginatedAuditLogsDto } from './dto/audit-log.dto';

@ApiTags('Audit')
@Controller('audit')
// On restreint l'accès aux Platform Admins / Owners pour la sécurité et la conformité
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.PLATFORM_OWNER, Role.PLATFORM_ADMIN)
@ApiBearerAuth()
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get()
  @ApiOperation({ summary: 'Get paginated audit logs (Admins only)' })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'action', required: false, enum: AuditAction })
  @ApiResponse({
    status: 200,
    description: 'Audit logs retrieved',
    type: PaginatedAuditLogsDto,
  })
  async getLogs(
    @Query('page') page?: string,
    @Query('limit') limit?: string,
    @Query('action') action?: AuditAction
  ): Promise<PaginatedAuditLogsDto> {
    const pageNumber = Math.max(1, parseInt(page || '1', 10));
    const limitNumber = Math.max(1, parseInt(limit || '10', 10));
    return this.auditService.getLogs(pageNumber, limitNumber, action);
  }
}
