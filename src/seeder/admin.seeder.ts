import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument, Role } from '../users/schemas/user.schema';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AdminSeeder implements OnApplicationBootstrap {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async onApplicationBootstrap() {
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;
    if (!adminEmail || !adminPassword) {
      Logger.warn('ADMIN_EMAIL or ADMIN_PASSWORD not set in env');
      return;
    }
    const existing = await this.userModel.findOne({
      role: Role.PLATFORM_ADMIN,
    });
    if (existing) {
      Logger.log('ℹ️ Admin already exists');
      return;
    }
    const passwordHash = await bcrypt.hash(adminPassword, 10);
    await this.userModel.create({
      username: 'platform_admin',
      email: adminEmail,
      passwordHash,
      firstName: 'Platform',
      lastName: 'Admin',
      birthdate: new Date('1970-01-01'),
      acceptTerms: true,
      emailConfirmed: true,
      isAdmin: true,
      role: Role.PLATFORM_ADMIN,
    });
    Logger.log('✅ Platform Admin created');
  }
}
