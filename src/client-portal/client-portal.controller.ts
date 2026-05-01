import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiParam,
} from '@nestjs/swagger';
import { IsString, IsOptional, IsEmail, IsNumber, Min } from 'class-validator';
import { ClientPortalService } from './client-portal.service';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';
import {
  BusinessRolesGuard,
  BusinessRoles,
} from '@/business/guards/business-roles.guard';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { CurrentTenant } from '@/common/tenant/current-tenant.decorator';
import type { TenantContext } from '@/common/tenant/tenant.types';

export class GeneratePortalTokenDto {
  @IsString()
  businessId!: string;

  @IsEmail()
  clientEmail!: string;

  @IsOptional()
  @IsString()
  clientName?: string;

  @IsOptional()
  @IsNumber()
  @Min(1)
  expiryDays?: number;
}

@ApiTags('Client Portal')
@Controller('client-portal')
export class ClientPortalController {
  constructor(private readonly clientPortalService: ClientPortalService) {}

  @Post('generate-token')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, TenantContextGuard, BusinessRolesGuard)
  @BusinessRoles(BusinessUserRole.OWNER, BusinessUserRole.ADMIN)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Generate a portal access token for a client' })
  async generateToken(
    @Body() dto: GeneratePortalTokenDto,
    @CurrentTenant() tenant: TenantContext
  ): Promise<{ token: string; expiresAt: Date; portalUrl: string }> {
    const result = await this.clientPortalService.generatePortalToken(
      tenant.businessId,
      dto.clientEmail,
      dto.clientName,
      dto.expiryDays
    );
    return {
      ...result,
      portalUrl: `/portal/${result.token}`,
    };
  }

  @Get('verify/:token')
  @ApiOperation({ summary: 'Verify portal token and get basic portal info' })
  @ApiParam({ name: 'token', type: String })
  async verifyToken(@Param('token') token: string) {
    return this.clientPortalService.getPortalInfo(token);
  }

  @Get(':token/invoices')
  @ApiOperation({ summary: 'Get all invoices for the portal client' })
  @ApiParam({ name: 'token', type: String })
  async getInvoices(@Param('token') token: string) {
    return this.clientPortalService.getClientInvoices(token);
  }

  @Get(':token/invoices/:invoiceId')
  @ApiOperation({ summary: 'Get full invoice details from portal' })
  @ApiParam({ name: 'token', type: String })
  @ApiParam({ name: 'invoiceId', type: String })
  async getInvoiceDetail(
    @Param('token') token: string,
    @Param('invoiceId') invoiceId: string
  ) {
    return this.clientPortalService.getClientInvoiceDetail(token, invoiceId);
  }
}
