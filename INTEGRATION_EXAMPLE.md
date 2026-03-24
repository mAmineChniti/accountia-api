/\*\*

- Integration Example: Using Email Service in Business Controller
-
- This file shows how to integrate the new Email module with the Business module
- to send email notifications when approving/rejecting business applications.
  \*/

/\*\*

- Step 1: Update BusinessModule to import EmailModule
-
- File: src/business/business.module.ts
  \*/

/\*
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { BusinessController } from '@/business/business.controller';
import { BusinessService } from '@/business/business.service';
import { AuthModule } from '@/auth/auth.module';
import { EmailModule } from '@/email/email.module'; // <- ADD THIS
import { Business, BusinessSchema } from '@/business/schemas/business.schema';
import {
BusinessApplication,
BusinessApplicationSchema,
} from '@/business/schemas/business-application.schema';
import {
BusinessUser,
BusinessUserSchema,
} from '@/business/schemas/business-user.schema';
import { TenantConnectionService } from '@/common/tenant/tenant-connection.service';
import { TenantContextService } from '@/common/tenant/tenant-context.service';
import { TenantContextGuard } from '@/common/tenant/tenant-context.guard';

@Module({
imports: [
AuthModule,
EmailModule, // <- ADD THIS
MongooseModule.forFeature([
{ name: Business.name, schema: BusinessSchema },
{ name: BusinessApplication.name, schema: BusinessApplicationSchema },
{ name: BusinessUser.name, schema: BusinessUserSchema },
]),
],
controllers: [BusinessController],
providers: [
BusinessService,
TenantConnectionService,
TenantContextService,
TenantContextGuard,
],
exports: [
BusinessService,
TenantConnectionService,
TenantContextService,
TenantContextGuard,
],
})
export class BusinessModule {}
\*/

/\*\*

- Step 2: Update BusinessService to use the Email Service
-
- File: src/business/business.service.ts
  \*/

/\*
import { EmailService } from '@/email/email.service';
import { SendEmailDto } from '@/email/dto/send-email.dto';

@Injectable()
export class BusinessService {
constructor(
@InjectConnection() private readonly connection: Connection,
@InjectModel(Business.name) private businessModel: Model<BusinessDocument>,
@InjectModel(BusinessApplication.name)
private businessApplicationModel: Model<BusinessApplicationDocument>,
@InjectModel(BusinessUser.name)
private businessUserModel: Model<BusinessUserDocument>,
private emailService: EmailService, // <- ADD THIS
private tenantConnectionService: TenantConnectionService
) {}

async reviewBusinessApplication(
applicationId: string,
reviewDto: ReviewBusinessApplicationDto,
reviewerId: string
): Promise<BusinessApplicationResponseDto> {
const application =
await this.businessApplicationModel.findById(applicationId);

    if (!application) {
      throw new NotFoundException('Business application not found');
    }

    if (application.status !== 'pending') {
      throw new BadRequestException('Application has already been reviewed');
    }

    // Update application status
    application.status = reviewDto.status;
    application.reviewedBy = reviewerId;
    application.reviewNotes = reviewDto.reviewNotes;

    if (reviewDto.status === 'approved') {
      // ... [existing business creation logic] ...

      // Send approval email - UPDATED VERSION
      if (application.applicantEmail) {
        await this.emailService.sendEmail({
          to: application.applicantEmail,
          subject: `Your Business Application Has Been Approved - ${application.businessName}`,
          html: this.generateApprovalEmailHtml(
            application.businessName,
            application.applicantName,
            application.description
          ),
          text: this.generateApprovalEmailText(
            application.businessName,
            application.applicantName
          ),
          type: 'business_approval',
          metadata: {
            businessName: application.businessName,
            applicantEmail: application.applicantEmail,
          },
        });
      }
    } else {
      // Send rejection email - UPDATED VERSION
      if (application.applicantEmail) {
        await this.emailService.sendEmail({
          to: application.applicantEmail,
          subject: `Update on Your Business Application - ${application.businessName}`,
          html: this.generateRejectionEmailHtml(
            application.businessName,
            application.applicantName,
            reviewDto.reviewNotes
          ),
          text: this.generateRejectionEmailText(
            application.businessName,
            application.applicantName,
            reviewDto.reviewNotes
          ),
          type: 'business_rejection',
          metadata: {
            businessName: application.businessName,
            applicantEmail: application.applicantEmail,
          },
        });
      }

      await application.save();
    }

    return {
      message:
        reviewDto.status === 'approved'
          ? 'Business application approved successfully'
          : 'Business application has been rejected',
      application: {
        id: application._id.toString(),
        businessName: application.businessName,
        description: application.description,
        website: application.website,
        phone: application.phone,
        applicantId: application.applicantId,
        applicantEmail: application.applicantEmail,  // Include in response
        applicantName: application.applicantName,    // Include in response
        status: application.status,
        createdAt: application.createdAt,
      },
    };

}

// Helper methods to generate email content
private generateApprovalEmailHtml(
businessName: string,
applicantName: string,
description: string
): string {
return `       <!DOCTYPE html>
      <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; }
            .container { max-width: 600px; margin: 0 auto; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }
            .content { padding: 40px; }
            .badge { display: inline-block; background: #d1fae5; color: #065f46; padding: 8px 16px; border-radius: 20px; margin-bottom: 20px; }
            .footer { border-top: 1px solid #e5e7eb; padding: 20px 40px; background: #f9fafb; font-size: 12px; text-align: center; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>✓ Application Approved</h1>
            </div>
            <div class="content">
              <div class="badge">APPROVED</div>
              <p>Hi ${applicantName},</p>
              <p>We're thrilled to inform you that your business application has been <strong>approved</strong>!</p>
              <h3>${businessName}</h3>
              <p>${description}</p>
              <p>Your business is now active on our platform. You can start using all the features available to approved business owners.</p>
            </div>
            <div class="footer">
              <p>© 2026 Accountia. All rights reserved.</p>
            </div>
          </div>
        </body>
      </html>
    `;
}

private generateApprovalEmailText(
businessName: string,
applicantName: string
): string {
return `
Application Approved

Dear ${applicantName},

We're thrilled to inform you that your business application has been approved!

Business: ${businessName}

Your business is now active on our platform. You can start using all the features available to approved business owners.

Best regards,
Accountia Team
`.trim();
}

private generateRejectionEmailHtml(
businessName: string,
applicantName: string,
reason?: string
): string {
return `      <!DOCTYPE html>
      <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; }
            .container { max-width: 600px; margin: 0 auto; }
            .header { background: linear-gradient(135deg, #f87171 0%, #dc2626 100%); color: white; padding: 40px; text-align: center; }
            .content { padding: 40px; }
            .badge { display: inline-block; background: #fee2e2; color: #991b1b; padding: 8px 16px; border-radius: 20px; margin-bottom: 20px; }
            .reason { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; }
            .footer { border-top: 1px solid #e5e7eb; padding: 20px 40px; background: #f9fafb; font-size: 12px; text-align: center; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Application Not Approved</h1>
            </div>
            <div class="content">
              <div class="badge">NOT APPROVED</div>
              <p>Hi ${applicantName},</p>
              <p>Thank you for submitting your business application for ${businessName}.</p>
              <p>After thorough review, we regret to inform you that your application has not been approved at this time.</p>
              ${
                reason
                  ?`<div class="reason">

<h4>Reason for Decision:</h4>
<p>${reason}</p>
</div>`                   : ''
              }
              <p>We encourage you to review the feedback provided and consider reapplying once you've addressed the concerns raised.</p>
            </div>
            <div class="footer">
              <p>© 2026 Accountia. All rights reserved.</p>
            </div>
          </div>
        </body>
      </html>
    `;
}

private generateRejectionEmailText(
businessName: string,
applicantName: string,
reason?: string
): string {
return `
Application Not Approved

Dear ${applicantName},

Thank you for submitting your business application for ${businessName}.

After thorough review, we regret to inform you that your application has not been approved at this time.

${reason ? `Reason for Decision: ${reason}` : ''}

We encourage you to review the feedback provided and consider reapplying once you've addressed the concerns raised.

Best regards,
Accountia Team
`.trim();
}
}
\*/

/\*\*

- Step 3: Ensure applicant information is captured when submitting application
-
- File: src/business/business.controller.ts
  \*/

/\*
import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { BusinessService } from '@/business/business.service';
import { CreateBusinessApplicationDto } from '@/business/dto/business-application.dto';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';
import { type UserPayload } from '@/auth/types/auth.types';

@Controller('business')
export class BusinessController {
constructor(private readonly businessService: BusinessService) {}

@Post('apply')
@UseGuards(JwtAuthGuard)
async applyForBusiness(
@Body() createApplicationDto: CreateBusinessApplicationDto,
@CurrentUser() user: UserPayload
) {
// The service should populate applicantEmail and applicantName from the user object
return this.businessService.submitBusinessApplication(
{
...createApplicationDto,
applicantEmail: user.email, // <- Capturing email
applicantName: `${user.firstName} ${user.lastName}`, // <- Capturing name
},
user.id
);
}
}
\*/

/\*\*

- Step 4: Update submitBusinessApplication in BusinessService
-
- File: src/business/business.service.ts
  \*/

/\*
async submitBusinessApplication(
createApplicationDto: CreateBusinessApplicationDto & {
applicantEmail?: string;
applicantName?: string;
},
userId: string
): Promise<BusinessApplicationResponseDto> {
// Check if user already has a pending application
const existingApplication = await this.businessApplicationModel.findOne({
applicantId: userId,
status: 'pending',
});

if (existingApplication) {
throw new BadRequestException(
'You already have a pending business application'
);
}

const application = new this.businessApplicationModel({
...createApplicationDto,
applicantId: userId,
applicantEmail: createApplicationDto.applicantEmail, // Store email
applicantName: createApplicationDto.applicantName, // Store name
});

const savedApplication = await application.save();

return {
message: 'Business application submitted successfully...',
application: {
id: savedApplication.\_id.toString(),
businessName: savedApplication.businessName,
description: savedApplication.description,
website: savedApplication.website,
phone: savedApplication.phone,
applicantId: savedApplication.applicantId,
applicantEmail: savedApplication.applicantEmail, // Include in response
applicantName: savedApplication.applicantName, // Include in response
status: savedApplication.status,
createdAt: savedApplication.createdAt,
},
};
}
\*/

export default {
// This file is for documentation only
};
