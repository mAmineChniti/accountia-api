import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { hash, compare } from 'bcrypt';
import { User, UserDocument } from '@/users/schemas/user.schema';
import { UpdateProfileDto } from '@/users/dto/update-profile.dto';
import { ChangePasswordDto } from '@/users/dto/change-password.dto';
import { ProfileResponseDto } from '@/users/dto/profile-response.dto';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  /**
   * Get user profile by ID
   */
  async getProfile(userId: string): Promise<ProfileResponseDto> {
    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.mapUserToProfileDto(user);
  }

  /**
   * Update user profile information
   */
  async updateProfile(
    userId: string,
    updateProfileDto: UpdateProfileDto
  ): Promise<ProfileResponseDto> {
    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if email is being updated and if it's already in use
    if (updateProfileDto.email && updateProfileDto.email !== user.email) {
      const existingUser = await this.userModel.findOne({
        email: updateProfileDto.email,
      });

      if (existingUser) {
        throw new ConflictException('Email is already in use');
      }
    }

    // Update allowed fields
    if (updateProfileDto.firstName) {
      user.firstName = updateProfileDto.firstName;
    }

    if (updateProfileDto.lastName) {
      user.lastName = updateProfileDto.lastName;
    }

    if (updateProfileDto.email) {
      user.email = updateProfileDto.email;
    }

    const updatedUser = await user.save();

    return this.mapUserToProfileDto(updatedUser);
  }

  /**
   * Change user password
   */
  async changePassword(
    userId: string,
    changePasswordDto: ChangePasswordDto
  ): Promise<{ message: string }> {
    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const { currentPassword, newPassword } = changePasswordDto;

    // Verify current password
    const isPasswordValid = await compare(currentPassword, user.passwordHash);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Prevent using the same password
    const isSamePassword = await compare(newPassword, user.passwordHash);

    if (isSamePassword) {
      throw new BadRequestException(
        'New password must be different from the current password'
      );
    }

    // Hash and update password
    const passwordHash = await hash(newPassword, 10);
    user.passwordHash = passwordHash;

    await user.save();

    return { message: 'Password changed successfully' };
  }

  /**
   * Map user document to ProfileResponseDto
   */
  private mapUserToProfileDto(user: UserDocument): ProfileResponseDto {
    return {
      id: user._id.toString(),
      username: user.username,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      birthdate: user.birthdate,
      phoneNumber: user.phoneNumber,
      isActive: user.isActive,
      emailConfirmed: user.emailConfirmed,
      profilePicture: user.profilePicture,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
