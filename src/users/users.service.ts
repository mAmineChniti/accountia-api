import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument, Role } from './schemas/user.schema';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async updateRole(userId: string, role: Role): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { role },
      { new: true }
    );
    if (!user) throw new NotFoundException('Utilisateur non trouvé');
    return user;
  }

  async findById(userId: string): Promise<User | null> {
    return this.userModel.findById(userId);
  }
}
