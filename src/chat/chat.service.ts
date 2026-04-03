import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel, InjectConnection } from '@nestjs/mongoose';
import { Model, Connection } from 'mongoose';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { Business } from '@/business/schemas/business.schema';
import { BusinessUser } from '@/business/schemas/business-user.schema';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { PersonalInvoice } from '@/invoices/schemas/personal-invoice.schema';
import { CompanyInvoice } from '@/invoices/schemas/company-invoice.schema';

export interface AiResponse {
  response: string;
  choices: string[];
  link: { text: string; url: string } | undefined;
  type: 'text' | 'choices' | 'analysis';
}

export interface BusinessContext {
  businessId?: string;
  businessName?: string;
  totalInvoices?: number;
  totalRevenue?: number;
  overdueInvoices?: number;
  overdueAmount?: number;
  paidInvoices?: number;
  pendingInvoices?: number;
  monthlyRevenue?: number;
  revenueGrowth?: number;
  averagePaymentDelay?: number;
  clientCount?: number;
}

@Injectable()
export class ChatService {
  private readonly logger = new Logger(ChatService.name);
  private genAI: GoogleGenerativeAI;
  private model: ReturnType<GoogleGenerativeAI['getGenerativeModel']>;

  constructor(
    @InjectModel(Business.name) private businessModel: Model<Business>,
    @InjectModel(BusinessUser.name)
    private businessUserModel: Model<BusinessUser>,
    @InjectModel(PersonalInvoice.name)
    private personalInvoiceModel: Model<PersonalInvoice>,
    @InjectModel(CompanyInvoice.name)
    private companyInvoiceModel: Model<CompanyInvoice>,
    @InjectConnection() private connection: Connection
  ) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      this.logger.error(
        'GEMINI_API_KEY environment variable is not set. Chat service will not work properly.'
      );
      throw new Error('GEMINI_API_KEY is required');
    }

    this.genAI = new GoogleGenerativeAI(apiKey);
    this.model = this.genAI.getGenerativeModel({
      model: 'gemini-2.0-flash',
    });

    this.logger.log('ChatService initialized with Gemini API');
  }

  /**
   * Verify user has access to a business (must be OWNER or ADMIN)
   */
  private async verifyBusinessAccess(
    businessId: string,
    userId: string
  ): Promise<void> {
    const businessUser = await this.businessUserModel.findOne({
      businessId,
      userId,
    });

    if (!businessUser) {
      throw new ForbiddenException('You do not have access to this business');
    }

    if (
      businessUser.role !== BusinessUserRole.OWNER &&
      businessUser.role !== BusinessUserRole.ADMIN
    ) {
      throw new ForbiddenException(
        'Only business owners and admins can use the chat for this business'
      );
    }
  }

  /**
   * Fetch business statistics from the database
   */
  private async fetchBusinessContext(
    businessId: string
  ): Promise<BusinessContext> {
    // Fetch business details
    const business = await this.businessModel.findById(businessId);
    if (!business) {
      throw new NotFoundException('Business not found');
    }

    // Get tenant connection for this business
    const tenantDb = this.connection.useDb(business.databaseName);

    // Get invoice models for the tenant database
    const tenantPersonalInvoiceModel = tenantDb.model(
      PersonalInvoice.name,
      this.personalInvoiceModel.schema
    );
    const tenantCompanyInvoiceModel = tenantDb.model(
      CompanyInvoice.name,
      this.companyInvoiceModel.schema
    );

    // Fetch all invoices for aggregation - cast to proper invoice types
    const personalInvoices = (await tenantPersonalInvoiceModel
      .find()
      .lean()
      .exec()) as Array<PersonalInvoice & { _id: unknown; __v?: number }>;
    const companyInvoices = (await tenantCompanyInvoiceModel
      .find()
      .lean()
      .exec()) as Array<CompanyInvoice & { _id: unknown; __v?: number }>;

    // Combine all invoices with common properties
    const allInvoices = [...personalInvoices, ...companyInvoices] as Array<
      PersonalInvoice | CompanyInvoice
    >;

    // Calculate statistics
    const totalInvoices = allInvoices.length;
    const paidInvoices = allInvoices.filter((inv) => inv.paid).length;
    const pendingInvoices = allInvoices.filter((inv) => !inv.paid).length;

    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    // Calculate overdue invoices (not paid and issued more than 30 days ago)
    const overdueInvoices = allInvoices.filter(
      (inv) => !inv.paid && new Date(inv.issuedAt) < thirtyDaysAgo
    ).length;

    // Calculate overdue amount
    const overdueAmount = allInvoices
      .filter((inv) => !inv.paid && new Date(inv.issuedAt) < thirtyDaysAgo)
      .reduce((sum, inv) => sum + (inv.amount || 0), 0);

    // Calculate total revenue (paid invoices)
    const totalRevenue = allInvoices
      .filter((inv) => inv.paid)
      .reduce((sum, inv) => sum + (inv.amount || 0), 0);

    // Calculate monthly revenue (paid invoices in last 30 days)
    const monthlyRevenue = allInvoices
      .filter(
        (inv) =>
          inv.paid &&
          (inv.paidAt ? new Date(inv.paidAt) >= thirtyDaysAgo : false)
      )
      .reduce((sum, inv) => sum + (inv.amount || 0), 0);

    // Calculate revenue growth (compare last 30 days with previous 30 days)
    const previousThirtyDaysStart = new Date(
      thirtyDaysAgo.getTime() - 30 * 24 * 60 * 60 * 1000
    );
    const previousMonthRevenue = allInvoices
      .filter(
        (inv) =>
          inv.paid &&
          inv.paidAt &&
          new Date(inv.paidAt) >= previousThirtyDaysStart &&
          new Date(inv.paidAt) < thirtyDaysAgo
      )
      .reduce((sum, inv) => sum + (inv.amount || 0), 0);

    const revenueGrowth =
      previousMonthRevenue > 0
        ? ((monthlyRevenue - previousMonthRevenue) / previousMonthRevenue) * 100
        : 0;

    // Count unique clients
    const uniqueClientUserIds = new Set<string>();
    const uniqueClientBusinessIds = new Set<string>();

    for (const inv of personalInvoices) {
      if (inv.clientUserId) {
        uniqueClientUserIds.add(inv.clientUserId);
      }
    }

    for (const inv of companyInvoices) {
      if (inv.clientBusinessId) {
        uniqueClientBusinessIds.add(inv.clientBusinessId);
      }
    }

    const clientCount = uniqueClientUserIds.size + uniqueClientBusinessIds.size;

    // Calculate average payment delay
    const paidWithDelay = allInvoices
      .filter((inv) => inv.paid && inv.paidAt)
      .map((inv) => {
        const issued = new Date(inv.issuedAt);
        const paid = new Date(inv.paidAt!);
        return (paid.getTime() - issued.getTime()) / (24 * 60 * 60 * 1000);
      });

    const averagePaymentDelay =
      paidWithDelay.length > 0
        ? paidWithDelay.reduce((a, b) => a + b, 0) / paidWithDelay.length
        : 0;

    return {
      businessId,
      businessName: business.name,
      totalInvoices,
      totalRevenue: Number(totalRevenue.toFixed(2)),
      overdueInvoices,
      overdueAmount: Number(overdueAmount.toFixed(2)),
      paidInvoices,
      pendingInvoices,
      monthlyRevenue: Number(monthlyRevenue.toFixed(2)),
      revenueGrowth: Number(revenueGrowth.toFixed(2)),
      averagePaymentDelay: Number(averagePaymentDelay.toFixed(1)),
      clientCount,
    };
  }

  /**
   * Generate system prompt based on user role
   */
  private getSystemPrompt(role: string): string {
    const prompts: Record<string, string> = {
      PLATFORM_OWNER: `You are a strategic advisor and platform administrator for Accountia, a SaaS invoicing platform for Tunisian SMEs.

YOUR EXPERTISE:
- Platform administration and user management
- Overall platform analytics and reporting
- Strategic business decisions
- System health and performance monitoring

RULES:
- Always respond in French
- Be professional and strategic
- Only reference data provided in context
- Provide actionable insights`,

      PLATFORM_ADMIN: `You are a platform support specialist for Accountia.

YOUR ROLE:
- Help businesses with platform features
- Provide technical guidance
- Answer questions about invoice management
- Support onboarding

RULES:
- Always respond in French
- Be helpful and clear
- Guide users through features
- Provide relevant links when helpful`,

      BUSINESS_OWNER: `Tu es un conseiller financier expert (CFO virtuel) pour Accountia Business, spécialisé dans la gestion des PME tunisiennes.

TON EXPERTISE :
- Analyse de données financières en temps réel (revenus, factures en retard)
- Prévision (forecasting) des revenus sur 3 mois
- Détection d'anomalies (chute de CA, ratio impayés élevé)
- Fiscalité tunisienne : TVA (19% standard, 7% réduit, 0% exonéré), IS (25%)
- Stratégie de croissance et optimisation de cash-flow

RÈGLES ABSOLUES :
- Analyse UNIQUEMENT les données de 'context' fournies
- Ne cite JAMAIS un chiffre qui n'est pas présent ou dérivable mathématiquement du contexte
- Si les données manquent, dis-le poliment au lieu d'inventer
- Réponds TOUJOURS en français, de façon professionnelle, claire et structurée
- Utilise Markdown pour une lisibilité maximale

LIENS DISPONIBLES :
- Mon dashboard : /dashboard/business
- Mes clients : /dashboard/business/clients
- Analyser mes finances : /dashboard/business/financials
- Relances automatiques : /dashboard/business/automations`,

      BUSINESS_ADMIN: `Tu es un assistant pour les administrateurs business dans Accountia.

TON RÔLE :
- Aider à gérer les factures et clients
- Expliquer les fonctionnalités de gestion
- Fournir des conseils opérationnels

RÈGLES :
- Réponds TOUJOURS en français
- Sois clair et professionnel
- Guide les utilisateurs à travers les processus
- Fournis des liens pertinents`,

      CLIENT: `Tu es un assistant support simple et bienveillant pour Accountia, une plateforme SaaS de gestion de factures pour PME tunisiennes.

TON RÔLE :
- Aider les clients à naviguer sur la plateforme
- Expliquer comment consulter et payer leurs factures reçues
- Les guider pour créer leur propre business si intéressés
- Répondre de façon claire, simple et rassurante

RÈGLES ABSOLUES :
- Tu ne connais JAMAIS les données réelles de l'utilisateur (montants, noms, numéros de factures)
- Si la liste de factures est vide, explique que les factures apparaîtront automatiquement
- Ne jamais inventer de montants ou de numéros de factures
- Réponds TOUJOURS en français

LIENS DISPONIBLES :
- Mes factures : /invoices
- Créer un business : /invoices`,

      default: `Tu es un assistant helpful pour Accountia.

TON RÔLE :
- Aider les utilisateurs
- Répondre aux questions
- Fournir des conseils

RÈGLES :
- Réponds TOUJOURS en français
- Sois clair et concis
- Ne sois jamais agressif`,
    };

    return prompts[role] || prompts.default;
  }

  /**
   * Format business context as a string for the prompt
   */
  private formatBusinessContext(context?: BusinessContext): string {
    if (!context) return '';

    const parts: string[] = ['CONTEXTE MÉTIER :'];

    if (context.businessName) {
      parts.push(`- Business: ${context.businessName}`);
    }

    if (context.totalRevenue !== undefined) {
      parts.push(`- Chiffre d'affaires total: ${context.totalRevenue} TND`);
    }

    if (context.monthlyRevenue !== undefined) {
      parts.push(`- Revenu mensuel: ${context.monthlyRevenue} TND`);
    }

    if (context.revenueGrowth !== undefined) {
      parts.push(`- Croissance: ${context.revenueGrowth}%`);
    }

    if (context.totalInvoices !== undefined) {
      parts.push(`- Factures totales: ${context.totalInvoices}`);
    }

    if (context.paidInvoices !== undefined) {
      parts.push(`- Factures payées: ${context.paidInvoices}`);
    }

    if (context.pendingInvoices !== undefined) {
      parts.push(`- Factures en attente: ${context.pendingInvoices}`);
    }

    if (context.overdueInvoices !== undefined) {
      parts.push(`- Factures en retard: ${context.overdueInvoices}`);
    }

    if (context.overdueAmount !== undefined) {
      parts.push(`- Montant en retard: ${context.overdueAmount} TND`);
    }

    if (context.clientCount !== undefined) {
      parts.push(`- Nombre de clients: ${context.clientCount}`);
    }

    if (context.averagePaymentDelay !== undefined) {
      parts.push(
        `- Délai de paiement moyen: ${context.averagePaymentDelay} jours`
      );
    }

    return parts.join('\n');
  }

  /**
   * Get AI response from Gemini with business context
   */
  async getAiResponse(
    userId: string,
    role: string,
    query: string,
    businessId: string,
    history: Array<{ role: string; content: string }> = []
  ): Promise<AiResponse> {
    try {
      // Verify user has access to this business
      await this.verifyBusinessAccess(businessId, userId);

      // Fetch business context from database
      const businessContext = await this.fetchBusinessContext(businessId);

      const systemPrompt = this.getSystemPrompt(role);
      const businessContextStr = this.formatBusinessContext(businessContext);

      // Build conversation with system context
      const conversationHistory = history.map((h) => ({
        role: h.role === 'user' ? 'user' : 'model',
        parts: [{ text: h.content }],
      }));

      // Prepare the full message with system prompt and business context
      let fullMessage = `${systemPrompt}`;

      if (businessContextStr) {
        fullMessage += `\n\n${businessContextStr}`;
      }

      fullMessage += `\n\nUtilisateur: ${query}`;

      // Start a chat session
      const chat = this.model.startChat({
        history:
          conversationHistory.length > 0 ? conversationHistory : undefined,
      });

      const result = await chat.sendMessage(fullMessage);
      const response = result.response.text();

      // Parse response - attempt to extract JSON if present
      let parsedResponse: AiResponse;

      try {
        // Try to find JSON in the response
        const jsonMatch = /{[\S\s]*}/.exec(response);
        parsedResponse = jsonMatch
          ? (JSON.parse(jsonMatch[0]) as AiResponse)
          : {
              response,
              choices: [],
              link: undefined,
              type: 'text',
            };
      } catch {
        // If JSON parsing fails, just use the response as text
        parsedResponse = {
          response,
          choices: [],
          link: undefined,
          type: 'text',
        };
      }

      return parsedResponse;
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      const message = err.message || 'Unknown AI service error';
      this.logger.error(`Chat error: ${message}`, err);

      // Re-throw authorization and not found errors
      if (
        err instanceof ForbiddenException ||
        err instanceof NotFoundException
      ) {
        throw err;
      }

      return {
        response:
          'Désolé, je rencontre une petite difficulté technique. Réessayez dans un instant.',
        choices: [],
        link: undefined,
        type: 'text',
      };
    }
  }
}
