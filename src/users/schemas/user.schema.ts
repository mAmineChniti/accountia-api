import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true, unique: true })
  username: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  passwordHash: string;

  @Prop({ required: true })
  firstName: string;

  @Prop({ required: true })
  lastName: string;

  @Prop({ type: Date, required: true })
  birthdate: Date;

  @Prop()
  phoneNumber?: string;

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ default: false })
  emailConfirmed: boolean;

  @Prop({ required: true })
  acceptTerms: boolean;

  @Prop()
  profilePicture?: string;

  @Prop({
    type: [{ token: String, expiresAt: Date }],
    default: [],
    max: 10,
  })
  refreshTokens: Array<{
    token: string;
    expiresAt: Date;
  }>;

  @Prop()
  emailToken?: string;

  @Prop({ default: 0 })
  emailConfirmationAttempts: number;

  @Prop()
  lastEmailAttemptTime?: Date;

  @Prop()
  passwordResetToken?: string;

  @Prop()
  passwordResetExpires?: Date;

  @Prop({ default: 0 })
  failedLoginAttempts: number;

  @Prop()
  lockUntil?: Date;

  @Prop()
  createdAt: Date;

  @Prop()
  updatedAt?: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);

UserSchema.pre(
  'save',
  function (this: UserDocument, next: (err?: Error) => void) {
    if (this.refreshTokens && this.refreshTokens.length > 10) {
      this.refreshTokens = this.refreshTokens.slice(-10);
    }
    next();
  }
);
