import { Injectable, Logger } from '@nestjs/common';
import { CreateAuditLogDto } from './dto/audit-log.dto';
import { AuditService } from './audit.service';

@Injectable()
export class AuditEmitter {
  private readonly logger = new Logger(AuditEmitter.name);

  constructor(private readonly auditService: AuditService) {}

  /**
   * Emit an audit action. This is fire-and-forget by design; failures are
   * swallowed so that auditing does not impact main flows.
   */
  emitAction(createDto: CreateAuditLogDto): Promise<void> {
    // Delegate to the AuditService without blocking caller execution.
    this.auditService.logAction(createDto).catch((error) => {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Failed to emit audit action: ${message}`);
    });
    return Promise.resolve();
  }
}
