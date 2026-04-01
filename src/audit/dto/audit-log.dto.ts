import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { AuditAction } from '../schemas/audit-log.schema';

export class CreateAuditLogDto {
  @ApiProperty({ enum: AuditAction, enumName: 'AuditAction' })
  action: AuditAction;

  @ApiProperty()
  userId: string;

  @ApiProperty()
  userEmail: string;

  @ApiProperty()
  userRole: string;

  @ApiPropertyOptional()
  details?: Record<string, unknown>;

  @ApiPropertyOptional()
  target?: string;

  @ApiPropertyOptional()
  ipAddress?: string;
}

export class AuditLogResponseDto {
  @ApiProperty()
  id: string;

  @ApiProperty({ enum: AuditAction, enumName: 'AuditAction' })
  action: AuditAction;

  @ApiProperty()
  userId: string;

  @ApiProperty()
  userEmail: string;

  @ApiProperty()
  userRole: string;

  @ApiPropertyOptional()
  details?: Record<string, unknown>;

  @ApiPropertyOptional()
  target?: string;

  @ApiPropertyOptional()
  ipAddress?: string;

  @ApiProperty()
  createdAt: string;
}

export class PaginatedAuditLogsDto {
  @ApiProperty({ type: [AuditLogResponseDto], isArray: true })
  logs: AuditLogResponseDto[];

  @ApiProperty()
  total: number;

  @ApiProperty()
  page: number;

  @ApiProperty()
  limit: number;

  @ApiProperty()
  totalPages: number;
}
