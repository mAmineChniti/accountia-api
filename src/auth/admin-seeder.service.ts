import { Injectable, OnApplicationBootstrap, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { hash } from 'bcrypt';
import { User, UserDocument } from '@/users/schemas/user.schema';
import { Role } from '@/auth/enums/role.enum';

@Injectable()
export class AdminSeederService implements OnApplicationBootstrap {
  private readonly logger = new Logger(AdminSeederService.name);

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    private readonly configService: ConfigService
  ) {}

  async onApplicationBootstrap() {
    await this.seedAdmin();
  }

  private async seedAdmin() {
    const adminEmail = this.configService.get<string>('ADMIN_EMAIL');
    const adminPassword = this.configService.get<string>('ADMIN_PASSWORD');

    if (!adminEmail || !adminPassword) {
      this.logger.warn(
        'Admin credentials not provided in environment variables. Skipping seeding.'
      );
      return;
    }

    const existingAdmin = await this.userModel.findOne({ email: adminEmail });

    if (existingAdmin) {
      this.logger.log('Admin user already exists.');
      return;
    }

    try {
      const passwordHash = await hash(adminPassword, 10);
      const adminUser = new this.userModel({
        username: 'admin',
        email: adminEmail,
        passwordHash,
        firstName: 'System',
        lastName: 'Admin',
        birthdate: new Date('1970-01-01'),
        role: Role.PLATFORM_ADMIN,
        emailConfirmed: true,
        acceptTerms: true,
      });

      await adminUser.save();
      this.logger.log(`Admin user ${adminEmail} created successfully.`);
    } catch (error) {
      this.logger.error('Failed to seed admin user:', error);
    }
  }
}
