import { Controller, Get, UseGuards, OnModuleInit } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Template, TemplateDocument } from './schemas/template.schema';
import { JwtAuthGuard } from '@/auth/guards/jwt-auth.guard';

@ApiTags('Templates')
@Controller('templates')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class TemplatesController implements OnModuleInit {
  constructor(
    @InjectModel(Template.name) private templateModel: Model<TemplateDocument>
  ) {}

  async onModuleInit() {
    // Seed default templates if they don't exist
    const count = await this.templateModel.countDocuments();
    if (count === 0) {
      await this.templateModel.insertMany([
        {
          name: 'Standard Professional',
          key: 'standard',
          description: 'Clean and widely accepted format',
        },
        {
          name: 'Modern Minimal',
          key: 'modern',
          description: 'Contemporary and minimalist design',
        },
        {
          name: 'Executive Blue',
          key: 'executive',
          description: 'Formal design with deep blue accents',
        },
      ]);
      console.log('Seeded default invoice templates');
    }
  }

  @Get('my')
  @ApiOperation({ summary: 'Get all available invoice templates' })
  @ApiResponse({
    status: 200,
    description: 'List of templates retrieved successfully',
  })
  async findAll() {
    const templates = await this.templateModel.find().exec();
    return { templates };
  }
}
