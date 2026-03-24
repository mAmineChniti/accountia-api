import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { AuditLog, AuditAction } from './schemas/audit-log.schema';
import { CreateAuditLogDto, PaginatedAuditLogsDto } from './dto/audit-log.dto';

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(
    @InjectModel(AuditLog.name) private auditLogModel: Model<AuditLog>
  ) {}

  async logAction(createDto: CreateAuditLogDto): Promise<AuditLog | null> {
    try {
      const log = new this.auditLogModel(createDto);
      const savedLog = await log.save();
      return savedLog;
    } catch (error) {
      // Non-blocking log action (ne pas crasher l'app si l'audit échoue)
      this.logger.error(`Failed to save audit log: ${error.message}`);
      return null;
    }
  }

  async getLogs(
    page: number = 1,
    limit: number = 10,
    action?: AuditAction
  ): Promise<PaginatedAuditLogsDto> {
    const skip = (page - 1) * limit;
    const query = action ? { action } : {};

    const [logs, total] = await Promise.all([
      this.auditLogModel
        .find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .exec(),
      this.auditLogModel.countDocuments(query),
    ]);

    return {
      logs: logs.map((log) => ({
        id: log._id.toString(),
        action: log.action,
        userId: log.userId.toString(),
        userEmail: log.userEmail,
        userRole: log.userRole,
        target: log.target,
        details: log.details || {},
        ipAddress: log.ipAddress,
        createdAt: log.createdAt.toISOString(),
      })),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }
}
