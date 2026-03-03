import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { User, UserDocument, Role } from './schemas/user.schema';

// ObjectId validation utility
function validateObjectId(id: string): void {
  if (!Types.ObjectId.isValid(id)) {
    throw new BadRequestException('Invalid user ID format');
  }
}

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async updateRole(userId: string, role: Role): Promise<User> {
    validateObjectId(userId);

    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { role },
      { new: true, runValidators: true }
    );
    if (!user) throw new NotFoundException('Utilisateur non trouvé');
    return user;
  }

  async findById(userId: string): Promise<User | null> {
    validateObjectId(userId);
    return this.userModel.findById(userId);
  }
}
