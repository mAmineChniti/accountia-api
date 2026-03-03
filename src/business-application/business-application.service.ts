import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import {
  BusinessApplication,
  BusinessApplicationDocument,
  ApplicationStatus,
} from './schemas/business-application.schema';
import {
  CreateBusinessApplicationDto,
  BusinessApplicationResponseDto,
} from './dto/business-application.dto';
import { User, UserDocument } from '@/users/schemas/user.schema';
import { Role } from '@/users/schemas/user.schema';
import { EmailService } from '@/auth/email.service';

@Injectable()
export class BusinessApplicationService {
  constructor(
    @InjectModel(BusinessApplication.name)
    private applicationModel: Model<BusinessApplicationDocument>,

    @InjectModel(User.name)
    private userModel: Model<UserDocument>,

    private readonly emailService: EmailService
  ) {}

  // ─── CLIENT: soumettre une candidature ─────────────────────────────────

  async apply(
    userId: string,
    dto: CreateBusinessApplicationDto
  ): Promise<BusinessApplicationResponseDto> {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.role !== Role.CLIENT) {
      throw new BadRequestException(
        'Only clients can apply for business access'
      );
    }

    // Vérifier si une candidature existe déjà
    const existing = await this.applicationModel.findOne({
      userId: new Types.ObjectId(userId),
    });

    if (existing) {
      throw new ConflictException(
        'You have already submitted a business application. Please wait for our team to review it.'
      );
    }

    // Créer la candidature en base
    await this.applicationModel.create({
      userId: new Types.ObjectId(userId),
      businessName: dto.businessName,
      businessType: dto.businessType,
      description: dto.description,
      website: dto.website,
      status: ApplicationStatus.PENDING,
    });

    // Marquer l'utilisateur comme ayant postulé
    user.hasApplied = true;
    await user.save();

    // Email admin (en arrière-plan)
    this.emailService
      .sendBusinessApplicationEmail(
        user.email,
        user.firstName,
        user.lastName,
        dto.businessName,
        dto.businessType,
        dto.description,
        dto.website
      )
      .catch((error) =>
        console.error('Failed to send admin notification email:', error)
      );

    // Email confirmation client (en arrière-plan)
    this.emailService
      .sendBusinessApplicationConfirmationEmail(
        user.email,
        user.firstName,
        dto.businessName
      )
      .catch((error) =>
        console.error('Failed to send client confirmation email:', error)
      );

    return {
      message:
        'Your business application has been received. Our team will review it and contact you by email.',
    };
  }

  // ─── ADMIN: voir toutes les candidatures ───────────────────────────────

  async findAll(): Promise<BusinessApplicationDocument[]> {
    return this.applicationModel
      .find()
      .populate('userId', 'email firstName lastName username')
      .sort({ createdAt: -1 })
      .lean() as Promise<BusinessApplicationDocument[]>;
  }

  // ─── ADMIN: approuver une candidature ──────────────────────────────────

  async approve(
    applicationId: string
  ): Promise<BusinessApplicationResponseDto> {
    const application = await this.applicationModel.findById(applicationId);
    if (!application) {
      throw new NotFoundException('Application not found');
    }

    if (application.status !== ApplicationStatus.PENDING) {
      throw new BadRequestException('Application is not pending');
    }

    // Changer le rôle de l'utilisateur
    await this.userModel.findByIdAndUpdate(application.userId, {
      role: Role.BUSINESS_OWNER,
      hasApplied: false,
    });

    application.status = ApplicationStatus.APPROVED;
    await application.save();

    return { message: 'Application approved. User is now a Business Owner.' };
  }

  // ─── ADMIN: rejeter une candidature ────────────────────────────────────

  async reject(applicationId: string): Promise<BusinessApplicationResponseDto> {
    const application = await this.applicationModel.findById(applicationId);
    if (!application) {
      throw new NotFoundException('Application not found');
    }

    if (application.status !== ApplicationStatus.PENDING) {
      throw new BadRequestException('Application is not pending');
    }

    // Remettre hasApplied à false pour qu'il puisse re-postuler
    await this.userModel.findByIdAndUpdate(application.userId, {
      hasApplied: false,
    });

    application.status = ApplicationStatus.REJECTED;
    await application.save();

    return { message: 'Application rejected.' };
  }
}
