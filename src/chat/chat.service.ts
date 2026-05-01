import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel, InjectConnection } from '@nestjs/mongoose';
import { Model, Connection } from 'mongoose';
import OpenAI from 'openai';
import { Business } from '@/business/schemas/business.schema';
import { BusinessUser } from '@/business/schemas/business-user.schema';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { Invoice } from '@/invoices/schemas/invoice.schema';
import { InvoiceReceipt } from '@/invoices/schemas/invoice-receipt.schema';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import { CacheService } from '@/redis/cache.service';

// Groq API configuration - free tier, fast responses
const GROQ_MODEL = 'llama-3.3-70b-versatile';

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
  topDebtors?: Array<{ name: string; overdueAmount: number }>;
}

export interface IndividualContext {
  userId: string;
  totalReceivedInvoices: number;
  pendingInvoices: number;
  paidInvoices: number;
  overdueInvoices: number;
  totalAmountDue: number;
  totalAmountPaid: number;
  upcomingDueAmount: number;
  upcomingDueCount: number;
  recentInvoices: Array<{
    invoiceNumber: string;
    issuerName: string;
    totalAmount: number;
    currency: string;
    status: InvoiceStatus;
    dueDate: Date;
  }>;
  upcomingInvoices: Array<{
    invoiceNumber: string;
    issuerName: string;
    totalAmount: number;
    currency: string;
    dueDate: Date;
    daysUntilDue: number;
  }>;
}

@Injectable()
export class ChatService {
  private readonly logger = new Logger(ChatService.name);
  private readonly client: OpenAI | undefined;
  private readonly chatEnabled: boolean;
  private readonly maxCompletionTokens: number;
  private readonly timeoutMs: number;
  private static readonly MAX_HISTORY_MESSAGES = 20;
  private static readonly MAX_MESSAGE_CHARS = 2000;

  constructor(
    @InjectModel(Business.name) private businessModel: Model<Business>,
    @InjectModel(BusinessUser.name)
    private businessUserModel: Model<BusinessUser>,
    @InjectModel(Invoice.name)
    private invoiceModel: Model<Invoice>,
    @InjectModel(InvoiceReceipt.name)
    private invoiceReceiptModel: Model<InvoiceReceipt>,
    @InjectConnection() private connection: Connection,
    private readonly cacheService: CacheService
  ) {
    const apiKey = process.env.GROQ_API_KEY;
    this.chatEnabled = Boolean(apiKey);
    this.maxCompletionTokens = this.resolveMaxCompletionTokens(
      process.env.GROQ_MAX_COMPLETION_TOKENS
    );
    this.timeoutMs = this.resolveTimeoutMs(process.env.GROQ_TIMEOUT_MS);

    if (!this.chatEnabled) {
      this.logger.warn(
        'GROQ_API_KEY environment variable is not set. Chat service is disabled.'
      );
      this.client = undefined;
      return;
    }

    // Initialize OpenAI client with Groq's base URL
    this.client = new OpenAI({
      apiKey: process.env.GROQ_API_KEY,
      baseURL: 'https://api.groq.com/openai/v1',
    });

    this.logger.log(
      `ChatService initialized with Groq model: ${GROQ_MODEL} (maxCompletionTokens=${this.maxCompletionTokens})`
    );
  }

  private resolveMaxCompletionTokens(rawValue?: string): number {
    const fallback = 1200;
    if (!rawValue) return fallback;
    const parsed = Number(rawValue);
    if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
    return Math.max(64, Math.min(Math.floor(parsed), 16_000));
  }

  private resolveTimeoutMs(rawValue?: string): number {
    const fallback = 30_000;
    if (!rawValue) return fallback;
    const parsed = Number(rawValue);
    if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
    return Math.max(1000, Math.min(Math.floor(parsed), 120_000));
  }

  private async withTimeout<T>(
    promise: Promise<T>,
    operationName: string
  ): Promise<T> {
    let timeoutId: ReturnType<typeof setTimeout> | undefined;

    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => {
        reject(
          new Error(`${operationName} timed out after ${this.timeoutMs}ms`)
        );
      }, this.timeoutMs);
    });

    try {
      return await Promise.race([promise, timeoutPromise]);
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
    }
  }

  private async generateWithGroq(params: {
    systemPrompt: string;
    businessContext?: string;
    query: string;
    history: Array<{ role: string; content: string }>;
  }): Promise<string> {
    if (!this.chatEnabled || !this.client) {
      throw new Error('GROQ_API_KEY is not configured');
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

    try {
      const res = await this.withTimeout(
        this.client.chat.completions.create({
          model: GROQ_MODEL,
          messages,
          max_tokens: this.maxCompletionTokens,
          temperature: 0.7,
          top_p: 0.95,
        }),
        'Groq chat request'
      );

      const content = res.choices[0]?.message?.content;
      if (typeof content === 'string' && content.trim().length > 0) {
        return content;
      }

      throw new Error('Groq response did not include message content');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Groq request failed: ${message}`);
      if (error instanceof Error) throw error;
      throw new Error(message);
    }
  }

  private async streamWithGroq(params: {
    systemPrompt: string;
    businessContext?: string;
    query: string;
    history: Array<{ role: string; content: string }>;
    onChunk: (chunk: string) => void;
  }): Promise<string> {
    if (!this.chatEnabled || !this.client) {
      throw new Error('GROQ_API_KEY is not configured');
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

    // Create AbortController for request-level timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const stream = await this.client.chat.completions.create(
        {
          model: GROQ_MODEL,
          messages,
          max_tokens: this.maxCompletionTokens,
          temperature: 0.7,
          top_p: 0.95,
          stream: true,
        },
        { signal: controller.signal }
      );

      let fullContent = '';

      for await (const chunk of stream) {
        const content = chunk.choices[0]?.delta?.content;
        if (content) {
          fullContent += content;
          params.onChunk(content);
        }
      }

      if (fullContent.trim().length === 0) {
        throw new Error(
          'Groq streaming response did not include message content'
        );
      }

      return fullContent;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Groq streaming request failed: ${message}`);
      if (error instanceof Error) throw error;
      throw new Error(message);
    } finally {
      clearTimeout(timeoutId);
    }
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
   * Cached for 60 seconds to reduce database load
   */
  private async fetchBusinessContext(
    businessId: string
  ): Promise<BusinessContext> {
    const cacheKey = `chat:business_context:${businessId}`;

    // Try to get from cache first
    const cached = await this.cacheService.get<BusinessContext>(cacheKey);
    if (cached) {
      this.logger.debug(`Business context cache hit for ${businessId}`);
      // Return clone to prevent mutation of cached data
      return structuredClone(cached);
    }

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

    // Calculate overdue invoices (past dueDate and not fully paid)
    const overdueInvoices = invoices.filter(
      (inv) =>
        (inv.status === InvoiceStatus.ISSUED ||
          inv.status === InvoiceStatus.PARTIAL ||
          inv.status === InvoiceStatus.OVERDUE) &&
        new Date(inv.dueDate) < now
    ).length;

    // Calculate overdue amount
    const overdueAmount = invoices
      .filter(
        (inv) =>
          (inv.status === InvoiceStatus.ISSUED ||
            inv.status === InvoiceStatus.PARTIAL ||
            inv.status === InvoiceStatus.OVERDUE) &&
          new Date(inv.dueDate) < now
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

    // Get top debtors (clients with highest overdue amounts)
    const debtorMap = new Map<
      string,
      { name: string; overdueAmount: number }
    >();
    for (const inv of invoices) {
      if (
        (inv.status === InvoiceStatus.ISSUED ||
          inv.status === InvoiceStatus.PARTIAL ||
          inv.status === InvoiceStatus.OVERDUE) &&
        new Date(inv.dueDate) < now
      ) {
        const key =
          inv.recipient?.platformId ??
          inv.recipient?.email ??
          inv._id?.toString() ??
          'Unknown';
        const name =
          inv.recipient?.displayName ??
          inv.recipient?.email ??
          `Invoice ${inv._id?.toString() ?? 'Unknown'}`;
        const existing = debtorMap.get(key);
        if (existing) {
          existing.overdueAmount += inv.totalAmount || 0;
        } else {
          debtorMap.set(key, { name, overdueAmount: inv.totalAmount || 0 });
        }
      }
    }
    const topDebtors = [...debtorMap.values()]
      .toSorted((a, b) => b.overdueAmount - a.overdueAmount)
      .slice(0, 5);

    const result: BusinessContext = {
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
      topDebtors,
    };

    // Cache for 60 seconds
    await this.cacheService.set(cacheKey, result, 60);
    return result;
  }

  /**
   * Fetch individual user context from invoice receipts (invoices received by user)
   * Cached for 60 seconds to reduce database load
   */
  private async fetchIndividualContext(
    userId: string,
    email: string
  ): Promise<IndividualContext> {
    const cacheKey = `chat:individual_context:${userId}`;

    // Try to get from cache first
    const cached = await this.cacheService.get<IndividualContext>(cacheKey);
    if (cached) {
      this.logger.debug(`Individual context cache hit for ${userId}`);
      // Return clone to prevent mutation of cached data
      return structuredClone(cached);
    }

    // Normalize email for matching
    const normalizedEmail = email.toLowerCase().trim();

    // Find all receipts where user is recipient (by userId or email)
    const receipts = await this.invoiceReceiptModel
      .find({
        $or: [{ recipientUserId: userId }, { recipientEmail: normalizedEmail }],
      })
      .sort({ issuedDate: -1 })
      .lean()
      .exec();

    const totalReceivedInvoices = receipts.length;

    // Count by status
    const pendingInvoices = receipts.filter(
      (r) =>
        r.invoiceStatus === InvoiceStatus.ISSUED ||
        r.invoiceStatus === InvoiceStatus.PARTIAL
    ).length;

    const paidInvoices = receipts.filter(
      (r) => r.invoiceStatus === InvoiceStatus.PAID
    ).length;

    // Get upcoming due invoices (next 14 days, not paid)
    const now = new Date();
    const fourteenDaysFromNow = new Date(
      now.getTime() + 14 * 24 * 60 * 60 * 1000
    );

    const overdueInvoices = receipts.filter(
      (r) =>
        r.invoiceStatus === InvoiceStatus.OVERDUE ||
        ((r.invoiceStatus === InvoiceStatus.ISSUED ||
          r.invoiceStatus === InvoiceStatus.PARTIAL) &&
          new Date(r.dueDate) < now)
    ).length;

    // Calculate amounts
    const totalAmountDue = receipts
      .filter(
        (r) =>
          r.invoiceStatus === InvoiceStatus.ISSUED ||
          r.invoiceStatus === InvoiceStatus.PARTIAL ||
          r.invoiceStatus === InvoiceStatus.OVERDUE
      )
      .reduce((sum, r) => sum + (r.totalAmount || 0), 0);

    const totalAmountPaid = receipts
      .filter((r) => r.invoiceStatus === InvoiceStatus.PAID)
      .reduce((sum, r) => sum + (r.totalAmount || 0), 0);

    // Get 5 most recent invoices
    const recentInvoices = receipts.slice(0, 5).map((r) => ({
      invoiceNumber: r.invoiceNumber,
      issuerName: r.issuerBusinessName,
      totalAmount: r.totalAmount,
      currency: r.currency,
      status: r.invoiceStatus,
      dueDate: r.dueDate,
    }));

    const upcomingInvoices = receipts
      .filter(
        (r) =>
          (r.invoiceStatus === InvoiceStatus.ISSUED ||
            r.invoiceStatus === InvoiceStatus.PARTIAL) &&
          new Date(r.dueDate) >= now &&
          new Date(r.dueDate) <= fourteenDaysFromNow
      )
      .map((r) => ({
        invoiceNumber: r.invoiceNumber,
        issuerName: r.issuerBusinessName,
        totalAmount: r.totalAmount,
        currency: r.currency,
        dueDate: r.dueDate,
        daysUntilDue: Math.ceil(
          (new Date(r.dueDate).getTime() - now.getTime()) /
            (24 * 60 * 60 * 1000)
        ),
      }))
      .toSorted((a, b) => a.daysUntilDue - b.daysUntilDue)
      .slice(0, 5);

    const upcomingDueAmount = upcomingInvoices.reduce(
      (sum, inv) => sum + (inv.totalAmount || 0),
      0
    );

    const result: IndividualContext = {
      userId,
      totalReceivedInvoices,
      pendingInvoices,
      paidInvoices,
      overdueInvoices,
      totalAmountDue: Number(totalAmountDue.toFixed(2)),
      totalAmountPaid: Number(totalAmountPaid.toFixed(2)),
      upcomingDueAmount: Number(upcomingDueAmount.toFixed(2)),
      upcomingDueCount: upcomingInvoices.length,
      recentInvoices,
      upcomingInvoices,
    };

    // Cache for 60 seconds
    await this.cacheService.set(cacheKey, result, 60);
    return result;
  }

  /**
   * Format individual context as a string for the prompt
   */
  private formatIndividualContext(context?: IndividualContext): string {
    if (!context) return '';

    const parts: string[] = [
      'RECEIVED INVOICES CONTEXT:',
      `- Total Received Invoices: ${context.totalReceivedInvoices}`,
      `- Paid Invoices: ${context.paidInvoices}`,
      `- Pending Invoices: ${context.pendingInvoices}`,
      `- Overdue Invoices: ${context.overdueInvoices}`,
    ];

    // Use overall totals from context (computed from all receipts, not capped sample)
    // Note: Per-currency totals would require additional precomputation in fetchIndividualContext
    if (context.totalAmountDue > 0) {
      parts.push(`- Total Amount Due: ${context.totalAmountDue.toFixed(2)}`);
    }
    if (context.totalAmountPaid > 0) {
      parts.push(`- Total Amount Paid: ${context.totalAmountPaid.toFixed(2)}`);
    }
    if (context.upcomingDueAmount > 0) {
      parts.push(
        `- Due in Next 14 Days: ${context.upcomingDueAmount.toFixed(2)}`
      );
    }

    if (context.recentInvoices.length > 0) {
      parts.push('\nRecent Invoices:');
      for (const inv of context.recentInvoices) {
        parts.push(
          `- ${inv.invoiceNumber} from ${inv.issuerName}: ${inv.totalAmount} ${inv.currency} (${inv.status}, due: ${inv.dueDate.toISOString().split('T')[0]})`
        );
      }
    }

    if (context.upcomingInvoices.length > 0) {
      parts.push('\nUpcoming Due (Next 14 Days):');
      for (const inv of context.upcomingInvoices) {
        parts.push(
          `- ${inv.invoiceNumber} from ${inv.issuerName}: ${inv.totalAmount} ${inv.currency} (in ${inv.daysUntilDue} days)`
        );
      }
    }

    return parts.join('\n');
  }

  /**
   * Generate system prompt based on mode (business or individual)
   * Groq will respond in the same language as the user's query
   */
  private getSystemPrompt(mode: 'business' | 'individual'): string {
    if (mode === 'business') {
      return `You are an expert financial advisor (virtual CFO) for Accountia Business.

YOUR PURPOSE:
Help business owners understand their financial situation and make better decisions to improve cash flow, reduce overdue payments, and grow their business.

HOW TO HELP:
- Analyze the financial context provided and identify key issues or opportunities
- Calculate important metrics (collection rate, overdue ratio, average invoice value)
- Compare current performance to previous periods when data allows
- Identify which clients owe the most and may need follow-up
- Suggest specific actions to improve cash flow
- Answer questions about Tunisian business taxation when relevant: VAT (19% standard, 7% reduced, 0% exempt), Corporate Tax (25%)

RESPONSE STYLE:
- Be direct, practical, and actionable
- Use bullet points and clear headings
- Highlight the most important numbers and what they mean
- Offer 2-3 specific recommendations the user can act on today

ABSOLUTE RULES:
- ONLY use data from the context section - never invent numbers
- If the user asks about something not in the context, say you don't have that information
- Respond in the SAME LANGUAGE as the user's query
- Keep responses focused on finances and business operations`;
    }

    // Individual mode
    return `You are a financial assistant for Accountia helping individuals manage their invoices.

YOUR PURPOSE:
Help users understand their invoice obligations, track what they owe, and stay on top of upcoming payments to avoid late fees.

HOW TO HELP:
- Summarize their current invoice situation (total due, what's overdue, what's coming up)
- Highlight urgent items needing immediate attention
- Calculate upcoming payment obligations in the next 14 days
- Explain invoice statuses and what they mean
- Suggest which invoices to prioritize paying first
- Help them understand payment options

RESPONSE STYLE:
- Be clear, friendly, and non-judgmental about payment situations
- Use bullet points to organize invoice information
- Clearly separate: overdue items (urgent), upcoming due (plan ahead), and already paid
- Offer practical advice on managing payments

ABSOLUTE RULES:
- ONLY use data from the context section - never invent invoice amounts or details
- If asking about a specific invoice not in the context, say you don't see it
- Respond in the SAME LANGUAGE as the user's query
- Keep responses focused on their invoice and payment management`;
  }

  /**
   * Format business context as a string for the prompt
   */
  private formatBusinessContext(context?: BusinessContext): string {
    if (!context) return '';

    const parts: string[] = ['BUSINESS FINANCIAL CONTEXT:'];

    if (context.businessName) {
      parts.push(`- Business: ${context.businessName}`);
    }

    if (context.totalRevenue !== undefined) {
      parts.push(`- Total Revenue: ${context.totalRevenue} TND`);
    }

    if (context.monthlyRevenue !== undefined) {
      parts.push(`- Monthly Revenue: ${context.monthlyRevenue} TND`);
    }

    if (context.revenueGrowth !== undefined) {
      parts.push(`- Revenue Growth: ${context.revenueGrowth}%`);
    }

    if (context.totalInvoices !== undefined) {
      parts.push(`- Total Invoices: ${context.totalInvoices}`);
    }

    if (context.paidInvoices !== undefined) {
      parts.push(`- Paid Invoices: ${context.paidInvoices}`);
    }

    if (context.pendingInvoices !== undefined) {
      parts.push(`- Pending Invoices: ${context.pendingInvoices}`);
    }

    if (context.overdueInvoices !== undefined) {
      parts.push(`- Overdue Invoices: ${context.overdueInvoices}`);
    }

    if (context.overdueAmount !== undefined) {
      parts.push(`- Overdue Amount: ${context.overdueAmount} TND`);
    }

    if (context.clientCount !== undefined) {
      parts.push(`- Client Count: ${context.clientCount}`);
    }

    if (context.averagePaymentDelay !== undefined) {
      parts.push(
        `- Average Payment Delay: ${context.averagePaymentDelay} days`
      );
    }

    if (context.topDebtors && context.topDebtors.length > 0) {
      parts.push('\nTop Debtors (overdue amounts):');
      for (const debtor of context.topDebtors) {
        parts.push(`- ${debtor.name}: ${debtor.overdueAmount.toFixed(2)} TND`);
      }
    }

    return parts.join('\n');
  }

  /**
   * Stream AI response from Groq with business or individual context
   * Used by WebSocket gateway for real-time chat responses
   */
  async streamAiResponse(
    userId: string,
    query: string,
    businessId: string | undefined,
    userEmail: string,
    history: Array<{ role: string; content: string }> = [],
    callbacks: {
      onChunk: (chunk: string) => void;
      onComplete: (fullResponse: string) => void;
      onError: (error: Error) => void;
    }
  ): Promise<void> {
    try {
      let contextStr: string;
      let mode: 'business' | 'individual';

      if (businessId) {
        // Business mode: verify access and fetch business context
        await this.verifyBusinessAccess(businessId, userId);
        const businessContext = await this.fetchBusinessContext(businessId);
        contextStr = this.formatBusinessContext(businessContext);
        mode = 'business';
      } else {
        // Individual mode: fetch user's received invoices
        const individualContext = await this.fetchIndividualContext(
          userId,
          userEmail
        );
        contextStr = this.formatIndividualContext(individualContext);
        mode = 'individual';
      }

      const systemPrompt = this.getSystemPrompt(mode);

      // Stream the response
      const fullResponse = await this.streamWithGroq({
        systemPrompt,
        businessContext: contextStr,
        query,
        history,
        onChunk: callbacks.onChunk,
      });

      callbacks.onComplete(fullResponse);
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      this.logger.error(`Streaming chat error: ${err.message}`, err.stack);

      // Handle specific error types
      const message = err.message || 'Unknown AI service error';

      // Handle HTTP exceptions first (before API key detection)
      if (
        err instanceof ForbiddenException ||
        err instanceof NotFoundException
      ) {
        callbacks.onError(err);
        return;
      }

      const groqError = err as {
        status?: number;
        code?: string;
        message?: string;
        type?: string;
      };
      const httpStatus = groqError.status;
      const isApiKeyError =
        httpStatus === 401 ||
        message.toLowerCase().includes('invalid api key') ||
        message.toLowerCase().includes('authentication') ||
        groqError.code === 'invalid_api_key';

      if (isApiKeyError) {
        callbacks.onError(
          new Error('AI service is not configured. Please check GROQ_API_KEY.')
        );
        return;
      }

      callbacks.onError(new Error(message));
    }
  }

  /**
   * Invalidate business context cache
   * Call this when invoice/payment data changes for a business
   */
  invalidateBusinessContext(businessId: string): void {
    void this.cacheService.del(`chat:business_context:${businessId}`);
    this.logger.debug(`Invalidated business context cache for ${businessId}`);
  }

  /**
   * Invalidate individual context cache
   * Call this when receipt/payment data changes for a user
   */
  invalidateIndividualContext(userId: string): void {
    void this.cacheService.del(`chat:individual_context:${userId}`);
    this.logger.debug(`Invalidated individual context cache for ${userId}`);
  }
}
