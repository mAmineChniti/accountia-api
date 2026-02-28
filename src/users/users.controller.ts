import { Controller, Patch, UseGuards, Req, Body, ForbiddenException } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags, ApiBody } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { UsersService } from '@/users/users.service';
import { Role } from './schemas/user.schema';
import type { Request } from 'express';

class UpdateRoleDto {
  role: Role;
}

@ApiTags('users')
@ApiBearerAuth()
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Patch('role')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Met à jour le rôle de l’utilisateur authentifié' })
  @ApiBody({ type: UpdateRoleDto })
  @ApiResponse({ status: 200, description: 'Rôle mis à jour', schema: { example: { message: 'Role updated', role: 'BUSINESS_ADMIN' } } })
  @ApiResponse({ status: 403, description: 'Accès refusé' })
  async updateRole(@Req() req: Request, @Body() body: UpdateRoleDto) {
    // Le payload JWT injecté dans req.user ne contient pas forcément le champ role, il faut l'ajouter dans la stratégie
    const user = req['user'] as { id: string; role?: Role };
    if (!user) throw new ForbiddenException('Utilisateur non authentifié');
    if ([Role.PLATFORM_ADMIN, Role.PLATFORM_OWNER].includes(user.role as Role)) {
      throw new ForbiddenException('Accès refusé');
    }
    if (![Role.BUSINESS_OWNER, Role.BUSINESS_ADMIN, Role.CLIENT].includes(body.role)) {
      throw new ForbiddenException('Rôle non autorisé');
    }
    const updated = await this.usersService.updateRole(user.id, body.role);
    return { message: 'Role updated', role: updated.role };
  }
}
