import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersService } from '@/users/users.service';
import { UsersController } from '@/users/users.controller';
import { User, UserSchema } from '@/users/schemas/user.schema';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  providers: [UsersService, JwtAuthGuard],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}
