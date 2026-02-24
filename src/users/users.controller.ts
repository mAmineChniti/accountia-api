import {
  Controller,
  Patch,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
  Get,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
} from '@nestjs/swagger';
import { UsersService } from '@/users/users.service';
import { UpdateProfileDto } from '@/users/dto/update-profile.dto';
import { ChangePasswordDto } from '@/users/dto/change-password.dto';
import { ProfileResponseDto } from '@/users/dto/profile-response.dto';
import { MessageResponseDto } from '@/users/dto/message-response.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  /**
   * Get current user profile
   */
  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiResponse({
    status: 200,
    description: 'User profile retrieved successfully',
    type: ProfileResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  async getProfile(
    @CurrentUser() user: UserPayload
  ): Promise<ProfileResponseDto> {
    return this.usersService.getProfile(user.id);
  }

  /**
   * Update user profile (firstName, lastName, email)
   */
  @Patch('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Update user profile information',
    description:
      'Update firstName, lastName, or email of the authenticated user',
  })
  @ApiBody({
    type: UpdateProfileDto,
    description: 'Update profile data (all fields optional)',
    examples: {
      example1: {
        value: {
          firstName: 'Jean',
          lastName: 'Martin',
          email: 'jean@example.com',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'User profile updated successfully',
    type: ProfileResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid input data',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  @ApiResponse({
    status: 409,
    description: 'Email is already in use',
  })
  async updateProfile(
    @CurrentUser() user: UserPayload,
    @Body() updateProfileDto: UpdateProfileDto
  ): Promise<ProfileResponseDto> {
    return this.usersService.updateProfile(user.id, updateProfileDto);
  }

  /**
   * Change user password
   */
  @Patch('change-password')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Change user password',
    description: 'Change the password of the authenticated user',
  })
  @ApiBody({
    type: ChangePasswordDto,
    description: 'Current and new password',
    examples: {
      example1: {
        value: {
          currentPassword: 'OldP@ssw0rd!',
          newPassword: 'NewP@ssw0rd!',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Password changed successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid input or new password same as current password',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized or current password is incorrect',
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  async changePassword(
    @CurrentUser() user: UserPayload,
    @Body() changePasswordDto: ChangePasswordDto
  ): Promise<MessageResponseDto> {
    return this.usersService.changePassword(user.id, changePasswordDto);
  }
}
