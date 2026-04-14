import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { hash } from 'bcrypt';
import { User } from '@/users/schemas/user.schema';
import { Role } from '@/auth/enums/role.enum';

@Injectable()
export class AdminSeederService implements OnModuleInit {
  private readonly logger = new Logger(AdminSeederService.name);

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private readonly configService: ConfigService
  ) {}

  async onModuleInit() {
    await this.seedAdmin();
  }

  private async seedAdmin() {
    const adminEmail = this.configService.get<string>('ADMIN_EMAIL');
    const adminPassword = this.configService.get<string>('ADMIN_PASSWORD');

    if (!adminEmail || !adminPassword) {
      this.logger.warn(
        'ADMIN_EMAIL or ADMIN_PASSWORD not set in environment. Skipping admin seeding.'
      );
      return;
    }

    try {
      const existingAdmin = await this.userModel.findOne({
        email: adminEmail.toLowerCase().trim(),
      });

      if (existingAdmin) {
        this.logger.log(`Admin user (${adminEmail}) already exists.`);
        return;
      }

      this.logger.log(`Seeding admin user: ${adminEmail}...`);

      const passwordHash = await hash(adminPassword, 10);

      const adminUser = new this.userModel({
        username: 'admin',
        email: adminEmail.toLowerCase().trim(),
        passwordHash,
        firstName: 'System',
        lastName: 'Admin',
        birthdate: new Date('1990-01-01'),
        role: Role.PLATFORM_OWNER,
        emailConfirmed: true,
        acceptTerms: true,
      });

      await adminUser.save();
      this.logger.log('Admin user seeded successfully!');
    } catch (error) {
      this.logger.error('Failed to seed admin user:', error);
    }
  }
}
