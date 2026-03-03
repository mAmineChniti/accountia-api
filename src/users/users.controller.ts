import {
  Controller,
  Patch,
  Param,
  UseGuards,
  Body,
  ForbiddenException,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
  ApiBody,
} from '@nestjs/swagger';
import { IsEnum, IsNotEmpty } from 'class-validator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AdminGuard } from '../auth/guards/admin.guard';
import { UsersService } from '@/users/users.service';
import { Role } from './schemas/user.schema';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';

class UpdateRoleDto {
  @IsNotEmpty()
  @IsEnum(Role)
  role: Role;
}

@ApiTags('users')
@ApiBearerAuth()
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Patch('role')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: "Met à jour le rôle de l'utilisateur authentifié" })
  @ApiBody({ type: UpdateRoleDto })
  @ApiResponse({
    status: 200,
    description: 'Rôle mis à jour',
    schema: { example: { message: 'Role updated', role: 'BUSINESS_ADMIN' } },
  })
  @ApiResponse({ status: 403, description: 'Accès refusé' })
  async updateRole(
    @CurrentUser() currentUser: UserPayload,
    @Body() body: UpdateRoleDto
  ) {
    // Prevent self-service elevation to privileged roles
    if (
      (body.role === Role.BUSINESS_OWNER ||
        body.role === Role.BUSINESS_ADMIN) &&
      currentUser.id === currentUser.id // This is always true, but shows the intent
    ) {
      throw new ForbiddenException(
        'Cannot assign privileged roles to yourself'
      );
    }

    if ([Role.PLATFORM_ADMIN, Role.PLATFORM_OWNER].includes(currentUser.role)) {
      throw new ForbiddenException('Accès refusé');
    }
    if (
      ![Role.BUSINESS_OWNER, Role.BUSINESS_ADMIN, Role.CLIENT].includes(
        body.role
      )
    ) {
      throw new ForbiddenException('Rôle non autorisé');
    }
    const updated = await this.usersService.updateRole(
      currentUser.id,
      body.role
    );
    return { message: 'Role updated', role: updated.role };
  }

  @Patch(':id/role')
  @UseGuards(JwtAuthGuard, AdminGuard)
  @ApiOperation({
    summary: "ADMIN — Modifier le rôle d'un utilisateur par son ID",
  })
  @ApiBody({ type: UpdateRoleDto })
  @ApiResponse({
    status: 200,
    description: 'Rôle mis à jour',
    schema: { example: { message: 'Role updated', role: 'BUSINESS_OWNER' } },
  })
  @ApiResponse({ status: 403, description: 'Accès refusé' })
  async updateUserRoleByAdmin(
    @Param('id') userId: string,
    @Body() body: UpdateRoleDto
  ) {
    if (!Object.values(Role).includes(body.role)) {
      throw new ForbiddenException('Rôle invalide');
    }
    const updated = await this.usersService.updateRole(userId, body.role);
    return { message: 'Role updated', role: updated.role };
  }
}
