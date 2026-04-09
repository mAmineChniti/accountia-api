import { Module, Global } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuditService } from './audit.service';
import { AuditController } from './audit.controller';
import { AuditLog, AuditLogSchema } from './schemas/audit-log.schema';
import { AuditEmitter } from './audit.emitter';

@Global() // @Global permet d'injecter facilement l'AuditService partout
@Module({
  imports: [
    MongooseModule.forFeature([
      { name: AuditLog.name, schema: AuditLogSchema },
    ]),
  ],
  controllers: [AuditController],
  providers: [AuditService, AuditEmitter],
  exports: [AuditService, AuditEmitter],
})
export class AuditModule {}
