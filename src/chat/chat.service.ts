import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel, InjectConnection } from '@nestjs/mongoose';
import { Model, Connection } from 'mongoose';
import { Business } from '@/business/schemas/business.schema';
import { BusinessUser } from '@/business/schemas/business-user.schema';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { Invoice } from '@/invoices/schemas/invoice.schema';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';

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
  private readonly openRouterApiKey?: string;
  private readonly chatEnabled: boolean;
  private readonly openRouterModel: string;
  private readonly openRouterMaxCompletionTokens: number;
  private readonly openRouterTimeoutMs: number;
  private static readonly MAX_HISTORY_MESSAGES = 20;
  private static readonly MAX_MESSAGE_CHARS = 2000;
  private openRouterClientPromise?: Promise<unknown>;

  constructor(
    @InjectModel(Business.name) private businessModel: Model<Business>,
    @InjectModel(BusinessUser.name)
    private businessUserModel: Model<BusinessUser>,
    @InjectModel(Invoice.name)
    private invoiceModel: Model<Invoice>,
    @InjectConnection() private connection: Connection
  ) {
    this.openRouterApiKey = process.env.OPENROUTER_API_KEY;
    this.openRouterModel =
      process.env.OPENROUTER_MODEL ?? 'google/gemini-2.5-flash';
    this.openRouterMaxCompletionTokens = this.resolveMaxCompletionTokens(
      process.env.OPENROUTER_MAX_COMPLETION_TOKENS
    );
    this.openRouterTimeoutMs = this.resolveOpenRouterTimeoutMs(
      process.env.OPENROUTER_TIMEOUT_MS
    );
    this.chatEnabled = Boolean(this.openRouterApiKey);

    if (!this.chatEnabled) {
      this.logger.warn(
        'OPENROUTER_API_KEY environment variable is not set. Chat service is disabled.'
      );
      return;
    }

    this.logger.log(
      `ChatService initialized with OpenRouter model: ${this.openRouterModel} (maxCompletionTokens=${this.openRouterMaxCompletionTokens})`
    );
  }

  private resolveMaxCompletionTokens(rawValue?: string): number {
    const fallback = 1200;
    if (!rawValue) {
      return fallback;
    }

    const parsed = Number(rawValue);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return fallback;
    }

    return Math.max(64, Math.min(Math.floor(parsed), 16_000));
  }

  private resolveOpenRouterTimeoutMs(rawValue?: string): number {
    const fallback = 30_000;
    if (!rawValue) {
      return fallback;
    }

    const parsed = Number(rawValue);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return fallback;
    }

    return Math.max(1000, Math.min(Math.floor(parsed), 120_000));
  }

  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    operationName: string
  ): Promise<T> {
    let timeoutId: ReturnType<typeof setTimeout> | undefined;

    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => {
        reject(new Error(`${operationName} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });

    try {
      return await Promise.race([promise, timeoutPromise]);
    } finally {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    }
  }

  private async getOpenRouterClient(): Promise<{
    chat: {
      send(request: {
        chatRequest: {
          model: string;
          messages: Array<{
            role: 'system' | 'user' | 'assistant';
            content: string;
          }>;
          maxCompletionTokens: number;
          temperature: number;
          stream: false;
        };
      }): Promise<{
        choices?: Array<{ message?: { content?: unknown } }>;
      }>;
    };
  }> {
    this.openRouterClientPromise ??= import('@openrouter/sdk').then(
      ({ OpenRouter }) =>
        new OpenRouter({
          apiKey: this.openRouterApiKey,
          httpReferer: process.env.APP_URL,
          appTitle: process.env.APP_NAME ?? 'accountia-api',
        })
    );

    return this.openRouterClientPromise as Promise<{
      chat: {
        send(request: {
          chatRequest: {
            model: string;
            messages: Array<{
              role: 'system' | 'user' | 'assistant';
              content: string;
            }>;
            maxCompletionTokens: number;
            temperature: number;
            stream: false;
          };
        }): Promise<{
          choices?: Array<{ message?: { content?: unknown } }>;
        }>;
      };
    }>;
  }

  private async generateWithOpenRouter(params: {
    systemPrompt: string;
    businessContext?: string;
    query: string;
    history: Array<{ role: string; content: string }>;
  }): Promise<string> {
    if (!this.chatEnabled || !this.openRouterApiKey) {
      throw new Error('OPENROUTER_API_KEY is not configured');
    }

    const systemContent = params.businessContext
      ? `${params.systemPrompt}\n\n${params.businessContext}`
      : params.systemPrompt;

    const safeQuery = params.query.slice(0, ChatService.MAX_MESSAGE_CHARS);
    const safeHistory = params.history
      .slice(-ChatService.MAX_HISTORY_MESSAGES)
      .map((entry) => ({
        role: entry.role,
        content: entry.content.slice(0, ChatService.MAX_MESSAGE_CHARS),
      }));

    const messages: Array<{
      role: 'system' | 'user' | 'assistant';
      content: string;
    }> = [
      { role: 'system', content: systemContent },
      ...safeHistory.map((entry) => ({
        role:
          entry.role === 'assistant' || entry.role === 'model'
            ? ('assistant' as const)
            : ('user' as const),
        content: entry.content,
      })),
      { role: 'user', content: safeQuery },
    ];

    const openRouterClient = await this.getOpenRouterClient();
    let response: Awaited<ReturnType<(typeof openRouterClient.chat)['send']>>;
    try {
      response = await this.withTimeout(
        openRouterClient.chat.send({
          chatRequest: {
            model: this.openRouterModel,
            messages,
            maxCompletionTokens: this.openRouterMaxCompletionTokens,
            temperature: 0.4,
            stream: false,
          },
        }),
        this.openRouterTimeoutMs,
        'OpenRouter chat request'
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`OpenRouter request failed: ${message}`);
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(message);
    }

    const content = (
      response as {
        choices?: Array<{
          message?: {
            content?: string | Array<{ type?: string; text?: string }>;
          };
        }>;
      }
    )?.choices?.[0]?.message?.content;

    if (typeof content === 'string' && content.trim().length > 0) {
      return content;
    }

    if (Array.isArray(content)) {
      const text = content
        .map((part) => (typeof part.text === 'string' ? part.text : ''))
        .join('')
        .trim();
      if (text.length > 0) {
        return text;
      }
    }

    throw new Error('OpenRouter response did not include message content');
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

    // Get invoice model for the tenant database
    const tenantInvoiceModel = tenantDb.model(
      Invoice.name,
      this.invoiceModel.schema
    );

    // Fetch all invoices issued by this business for analysis
    const invoices = (await tenantInvoiceModel
      .find({ issuerBusinessId: businessId })
      .lean()
      .exec()) as Array<Invoice & { _id: unknown; __v?: number }>;

    // Calculate statistics
    const totalInvoices = invoices.length;
    const paidInvoices = invoices.filter(
      (inv) => inv.status === InvoiceStatus.PAID
    ).length;
    const pendingInvoices = invoices.filter(
      (inv) =>
        inv.status === InvoiceStatus.ISSUED ||
        inv.status === InvoiceStatus.DRAFT ||
        inv.status === InvoiceStatus.PARTIAL
    ).length;

    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    // Calculate overdue invoices (not paid and issued more than 30 days ago)
    const overdueInvoices = invoices.filter(
      (inv) =>
        (inv.status === InvoiceStatus.ISSUED ||
          inv.status === InvoiceStatus.OVERDUE) &&
        new Date(inv.issuedDate) < thirtyDaysAgo
    ).length;

    // Calculate overdue amount
    const overdueAmount = invoices
      .filter(
        (inv) =>
          (inv.status === InvoiceStatus.ISSUED ||
            inv.status === InvoiceStatus.OVERDUE) &&
          new Date(inv.issuedDate) < thirtyDaysAgo
      )
      .reduce((sum, inv) => sum + (inv.totalAmount || 0), 0);

    // Calculate total revenue (fully paid invoices)
    const totalRevenue = invoices
      .filter((inv) => inv.status === InvoiceStatus.PAID)
      .reduce((sum, inv) => sum + (inv.totalAmount || 0), 0);

    // Calculate monthly revenue (invoices paid in last 30 days)
    const monthlyRevenue = invoices
      .filter(
        (inv) =>
          inv.status === InvoiceStatus.PAID &&
          inv.paymentDates?.some((date) => new Date(date) >= thirtyDaysAgo)
      )
      .reduce((sum, inv) => sum + (inv.totalAmount || 0), 0);

    // Calculate revenue growth (compare last 30 days with previous 30 days)
    const previousThirtyDaysStart = new Date(
      thirtyDaysAgo.getTime() - 30 * 24 * 60 * 60 * 1000
    );
    const previousMonthRevenue = invoices
      .filter(
        (inv) =>
          inv.status === InvoiceStatus.PAID &&
          inv.paymentDates?.some(
            (date) =>
              new Date(date) >= previousThirtyDaysStart &&
              new Date(date) < thirtyDaysAgo
          )
      )
      .reduce((sum, inv) => sum + (inv.totalAmount || 0), 0);

    const revenueGrowth =
      previousMonthRevenue > 0
        ? ((monthlyRevenue - previousMonthRevenue) / previousMonthRevenue) * 100
        : 0;

    // Count unique recipients (both platform businesses and external contacts)
    const uniqueRecipientIds = new Set<string>();

    for (const inv of invoices) {
      if (inv.recipient?.platformId) {
        uniqueRecipientIds.add(inv.recipient.platformId);
      } else if (inv.recipient?.email) {
        uniqueRecipientIds.add(inv.recipient.email);
      }
    }

    const clientCount = uniqueRecipientIds.size;

    // Calculate average payment delay
    const paidWithDelay = invoices
      .filter((inv) => inv.status === InvoiceStatus.PAID && inv.paymentDates)
      .flatMap((inv) =>
        (inv.paymentDates ?? []).map((paymentDate) => {
          const issued = new Date(inv.issuedDate);
          const paid = new Date(paymentDate);
          return (paid.getTime() - issued.getTime()) / (24 * 60 * 60 * 1000);
        })
      );

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

      const response = await this.generateWithOpenRouter({
        systemPrompt,
        businessContext: businessContextStr,
        query,
        history,
      });

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

      const sdkError = err as {
        errorDetails?: Array<{ reason?: string; message?: string }>;
        status?: number;
        apiMessage?: string;
        statusCode?: number;
        body?: string;
      };
      const parsedErrorBody = (() => {
        if (!sdkError.body || typeof sdkError.body !== 'string') {
          return;
        }
        try {
          return JSON.parse(sdkError.body) as {
            error?: { message?: string };
          };
        } catch {
          return;
        }
      })();
      const details = sdkError.errorDetails ?? [];
      const hasInvalidApiKeyReason = details.some(
        (detail) => detail.reason === 'API_KEY_INVALID'
      );
      const httpStatus = sdkError.statusCode ?? sdkError.status;
      const hasOpenRouterAuthError = httpStatus === 401;
      const hasOpenRouterCreditError = httpStatus === 402;
      const hasExpiredKeyMessage =
        message.toLowerCase().includes('api key expired') ||
        details.some((detail) =>
          (detail.message ?? '').toLowerCase().includes('api key expired')
        );
      const isApiKeyError =
        hasInvalidApiKeyReason ||
        hasExpiredKeyMessage ||
        hasOpenRouterAuthError ||
        message.toLowerCase().includes('api_key_invalid');

      // Re-throw authorization and not found errors
      if (
        err instanceof ForbiddenException ||
        err instanceof NotFoundException
      ) {
        throw err;
      }

      if (isApiKeyError) {
        this.logger.error(
          'OpenRouter API key is invalid or expired. Renew OPENROUTER_API_KEY in .env and restart the backend.'
        );
        return {
          response:
            'Le service IA est indisponible: la clé API OpenRouter est invalide ou expirée. Mettez à jour OPENROUTER_API_KEY puis redémarrez le serveur.',
          choices: [],
          link: undefined,
          type: 'text',
        };
      }

      if (hasOpenRouterCreditError) {
        this.logger.error(
          `OpenRouter credits or billing issue: ${parsedErrorBody?.error?.message ?? sdkError.apiMessage ?? message}`
        );
        return {
          response:
            'Le service IA est indisponible: crédits OpenRouter insuffisants. Réduisez OPENROUTER_MAX_COMPLETION_TOKENS ou ajoutez des crédits OpenRouter.',
          choices: [],
          link: undefined,
          type: 'text',
        };
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
