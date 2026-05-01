import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { InjectConnection, InjectModel } from '@nestjs/mongoose';
import { Connection, Model } from 'mongoose';
import { Business } from '@/business/schemas/business.schema';
import { BusinessUser } from '@/business/schemas/business-user.schema';
import { BusinessUserRole } from '@/business/enums/business-user-role.enum';
import { Invoice, InvoiceSchema } from '@/invoices/schemas/invoice.schema';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import type {
  InvoiceRiskScoreDto,
  CollectionsDashboardDto,
  GenerateReminderResponseDto,
  RiskLevel,
} from './dto/collections.dto';

/** Statuses that count as "open" / awaiting payment */
const OPEN_STATUSES = new Set<InvoiceStatus>([
  InvoiceStatus.ISSUED,
  InvoiceStatus.VIEWED,
  InvoiceStatus.PARTIAL,
  InvoiceStatus.OVERDUE,
]);

/** Statuses used to compute historical "late payment" rate */
const LATE_STATUSES = new Set<InvoiceStatus>([
  InvoiceStatus.OVERDUE,
  InvoiceStatus.DISPUTED,
]);

@Injectable()
export class CollectionsService {
  private readonly logger = new Logger(CollectionsService.name);

  private readonly openRouterApiKey?: string;
  private readonly openRouterModel: string;
  private readonly openRouterTimeoutMs: number;
  private openRouterClientPromise?: Promise<unknown>;

  constructor(
    @InjectConnection() private readonly connection: Connection,
    @InjectModel(Business.name) private readonly businessModel: Model<Business>,
    @InjectModel(BusinessUser.name)
    private readonly businessUserModel: Model<BusinessUser>
  ) {
    this.openRouterApiKey = process.env.OPENROUTER_API_KEY;
    this.openRouterModel =
      process.env.OPENROUTER_MODEL ?? 'google/gemini-2.5-flash';
    this.openRouterTimeoutMs = this.resolveTimeoutMs(
      process.env.OPENROUTER_TIMEOUT_MS
    );
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  private resolveTimeoutMs(raw?: string): number {
    const fallback = 30_000;
    if (!raw) return fallback;
    const parsed = Number(raw);
    return Number.isFinite(parsed) && parsed > 0
      ? Math.max(1000, Math.min(Math.floor(parsed), 120_000))
      : fallback;
  }

  private async withTimeout<T>(
    promise: Promise<T>,
    ms: number,
    label: string
  ): Promise<T> {
    let id: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      id = setTimeout(
        () => reject(new Error(`${label} timed out after ${ms}ms`)),
        ms
      );
    });
    try {
      return await Promise.race([promise, timeout]);
    } finally {
      if (id) clearTimeout(id);
    }
  }

  /** Lazy-initialise OpenRouter client (same pattern as ChatService) */
  private async getOpenRouterClient() {
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
        send(req: {
          chatRequest: {
            model: string;
            messages: Array<{ role: 'system' | 'user'; content: string }>;
            maxCompletionTokens: number;
            temperature: number;
            stream: false;
          };
        }): Promise<{ choices?: Array<{ message?: { content?: unknown } }> }>;
      };
    }>;
  }

  /** Get invoice model for a specific tenant database */
  private getInvoiceModel(databaseName: string): Model<Invoice> {
    const db = this.connection.useDb(databaseName, { useCache: true });
    try {
      return db.model<Invoice>(Invoice.name);
    } catch {
      return db.model<Invoice>(Invoice.name, InvoiceSchema);
    }
  }

  /** Verify user is OWNER or ADMIN of the given business */
  private async verifyAccess(
    businessId: string,
    userId: string
  ): Promise<void> {
    const bu = await this.businessUserModel
      .findOne({ businessId, userId })
      .lean();
    if (!bu)
      throw new ForbiddenException('You do not have access to this business');
    if (
      bu.role !== BusinessUserRole.OWNER &&
      bu.role !== BusinessUserRole.ADMIN
    ) {
      throw new ForbiddenException(
        'Only owners and admins can access collections'
      );
    }
  }

  /** Build a canonical key for a recipient (used to group history) */
  private recipientKey(invoice: Invoice): string {
    return invoice.recipient?.platformId
      ? `pid:${String(invoice.recipient.platformId)}`
      : (invoice.recipient?.email ?? 'unknown').toLowerCase();
  }

  /** Readable label for frontend display */
  private recipientLabel(invoice: Invoice): string {
    if (invoice.recipient?.displayName) return invoice.recipient.displayName;
    if (invoice.recipient?.email) return invoice.recipient.email;
    return 'Client inconnu';
  }

  // ─── Risk Scoring ─────────────────────────────────────────────────────────

  /**
   * Compute a risk score 0–100 for a single open invoice.
   *
   * Weights:
   *  45% — days overdue (capped at 90 days = full score)
   *  25% — client avg historical payment delay
   *  20% — client late-payment rate (fraction of past invoices that were overdue/disputed)
   *  10% — invoice amount vs client's historical average (large outliers carry extra risk)
   */
  private computeRiskScore(
    invoice: Invoice,
    now: Date,
    paidByRecipient: Invoice[],
    allByRecipient: Invoice[]
  ): Omit<
    InvoiceRiskScoreDto,
    | 'invoiceId'
    | 'invoiceNumber'
    | 'totalAmount'
    | 'outstandingAmount'
    | 'currency'
    | 'dueDate'
    | 'status'
    | 'recipientLabel'
  > {
    const dueDate = new Date(invoice.dueDate);
    const daysOverdue = Math.max(
      0,
      Math.floor((now.getTime() - dueDate.getTime()) / 86_400_000)
    );

    // Component 1: days overdue (45%)
    const overdueComponent = Math.min(daysOverdue / 90, 1) * 45;

    // Component 2: avg historical payment delay (25%)
    let avgHistoricalDelayDays: number | undefined;
    let avgDelayComponent = 0;
    if (paidByRecipient.length > 0) {
      const delays = paidByRecipient
        .filter((inv) => inv.paymentDates && inv.paymentDates.length > 0)
        .map((inv) => {
          const issued = new Date(inv.issuedDate).getTime();
          const paid = Math.min(
            ...inv.paymentDates!.map((d) => new Date(d).getTime())
          );
          return Math.max(0, (paid - issued) / 86_400_000);
        });
      if (delays.length > 0) {
        avgHistoricalDelayDays = Number(
          (delays.reduce((a, b) => a + b, 0) / delays.length).toFixed(1)
        );
        avgDelayComponent = Math.min(avgHistoricalDelayDays / 60, 1) * 25;
      }
    }

    // Component 3: late payment rate (20%)
    let clientLatePaymentRate: number | undefined;
    let lateRateComponent = 0;
    const relevantHistory = allByRecipient.filter(
      (inv) =>
        inv.status !== InvoiceStatus.DRAFT &&
        inv.status !== InvoiceStatus.VOIDED
    );
    if (relevantHistory.length > 0) {
      const lateCount = relevantHistory.filter((inv) =>
        LATE_STATUSES.has(inv.status)
      ).length;
      clientLatePaymentRate = Number(
        (lateCount / relevantHistory.length).toFixed(2)
      );
      lateRateComponent = clientLatePaymentRate * 20;
    }

    // Component 4: amount ratio (10%) — how large is this invoice vs client's average
    let amountRatioComponent = 0;
    if (allByRecipient.length > 0) {
      const avgAmount =
        allByRecipient.reduce((sum, inv) => sum + (inv.totalAmount || 0), 0) /
        allByRecipient.length;
      if (avgAmount > 0) {
        const ratio = invoice.totalAmount / avgAmount;
        // Every 50% above average adds 10 points, capped at 10
        amountRatioComponent = Math.min(Math.max(ratio - 1, 0) * 20, 10);
      }
    }

    const riskScore = Math.min(
      100,
      Math.round(
        overdueComponent +
          avgDelayComponent +
          lateRateComponent +
          amountRatioComponent
      )
    );

    let riskLevel: RiskLevel;
    if (riskScore <= 25) riskLevel = 'LOW';
    else if (riskScore <= 55) riskLevel = 'MEDIUM';
    else if (riskScore <= 80) riskLevel = 'HIGH';
    else riskLevel = 'CRITICAL';

    return {
      riskScore,
      riskLevel,
      daysOverdue,
      historyCount: allByRecipient.length,
      avgHistoricalDelayDays,
      clientLatePaymentRate,
    };
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  /**
   * GET /collections/dashboard
   * Returns risk scores for all open invoices plus aggregate breakdown.
   */
  async getDashboard(
    businessId: string,
    databaseName: string,
    userId: string
  ): Promise<CollectionsDashboardDto> {
    await this.verifyAccess(businessId, userId);

    const invoiceModel = this.getInvoiceModel(databaseName);
    const now = new Date();

    // Fetch all invoices for this business once — we need history for scoring
    const allInvoices = (await invoiceModel
      .find({ issuerBusinessId: businessId })
      .lean()
      .exec()) as Invoice[];

    const openInvoices = allInvoices.filter((inv) =>
      OPEN_STATUSES.has(inv.status)
    );

    // Group all invoices by recipient key for efficient history lookup
    const byRecipient = new Map<string, Invoice[]>();
    for (const inv of allInvoices) {
      const key = this.recipientKey(inv);
      if (!byRecipient.has(key)) byRecipient.set(key, []);
      byRecipient.get(key)!.push(inv);
    }

    const scores: InvoiceRiskScoreDto[] = openInvoices.map((invoice) => {
      const key = this.recipientKey(invoice);
      const allByRecipient = (byRecipient.get(key) ?? []).filter(
        (inv) => String(inv._id) !== String(invoice._id)
      );
      const paidByRecipient = allByRecipient.filter(
        (inv) => inv.status === InvoiceStatus.PAID
      );

      const {
        riskScore,
        riskLevel,
        daysOverdue,
        historyCount,
        avgHistoricalDelayDays,
        clientLatePaymentRate,
      } = this.computeRiskScore(invoice, now, paidByRecipient, allByRecipient);

      const outstanding =
        invoice.status === InvoiceStatus.PARTIAL
          ? Number((invoice.totalAmount - (invoice.amountPaid ?? 0)).toFixed(2))
          : invoice.totalAmount;

      return {
        invoiceId: String(invoice._id),
        invoiceNumber: invoice.invoiceNumber,
        totalAmount: invoice.totalAmount,
        outstandingAmount: outstanding,
        currency: invoice.currency ?? 'TND',
        dueDate: new Date(invoice.dueDate).toISOString(),
        daysOverdue,
        status: invoice.status,
        recipientLabel: this.recipientLabel(invoice),
        riskScore,
        riskLevel,
        historyCount,
        avgHistoricalDelayDays,
        clientLatePaymentRate,
      };
    });

    // Sort by risk score descending so the most critical invoices appear first
    scores.sort((a, b) => b.riskScore - a.riskScore);

    // Aggregate breakdown
    const riskBreakdown = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    const amountByRisk = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    for (const s of scores) {
      riskBreakdown[s.riskLevel]++;
      amountByRisk[s.riskLevel] = Number(
        (amountByRisk[s.riskLevel] + s.outstandingAmount).toFixed(2)
      );
    }

    const totalOutstandingAmount = Number(
      scores.reduce((sum, s) => sum + s.outstandingAmount, 0).toFixed(2)
    );

    // Derive dominant currency from the open invoices (fallback TND)
    const currencyCount = new Map<string, number>();
    for (const inv of openInvoices) {
      const c = inv.currency ?? 'TND';
      currencyCount.set(c, (currencyCount.get(c) ?? 0) + 1);
    }
    let dominantCurrency = 'TND';
    let maxCount = 0;
    for (const [c, count] of currencyCount.entries()) {
      if (count > maxCount) {
        maxCount = count;
        dominantCurrency = c;
      }
    }

    return {
      totalOpenInvoices: openInvoices.length,
      totalOutstandingAmount,
      currency: dominantCurrency,
      riskBreakdown,
      amountByRisk,
      scores,
    };
  }

  /**
   * GET /collections/risk-scores
   * Returns only the scored list (lighter than full dashboard, no aggregate).
   */
  async getRiskScores(
    businessId: string,
    databaseName: string,
    userId: string
  ): Promise<InvoiceRiskScoreDto[]> {
    const dashboard = await this.getDashboard(businessId, databaseName, userId);
    return dashboard.scores;
  }

  /**
   * POST /collections/invoices/:id/generate-reminder
   * Uses OpenRouter/Gemini to generate a personalised French reminder email.
   */
  async generateReminder(
    invoiceId: string,
    businessId: string,
    databaseName: string,
    userId: string
  ): Promise<GenerateReminderResponseDto> {
    await this.verifyAccess(businessId, userId);

    if (!this.openRouterApiKey) {
      throw new ServiceUnavailableException(
        'OPENROUTER_API_KEY is not configured. Cannot generate reminders.'
      );
    }

    const invoiceModel = this.getInvoiceModel(databaseName);
    const now = new Date();

    const invoice = (await invoiceModel
      .findOne({
        _id: invoiceId,
        issuerBusinessId: businessId,
      })
      .lean()) as Invoice | null;

    if (!invoice) {
      throw new NotFoundException(`Invoice ${invoiceId} not found`);
    }

    if (!OPEN_STATUSES.has(invoice.status)) {
      throw new ForbiddenException(
        `Cannot generate a reminder for an invoice with status "${invoice.status}"`
      );
    }

    // Build history for risk scoring
    const allInvoices = (await invoiceModel
      .find({ issuerBusinessId: businessId })
      .lean()
      .exec()) as Invoice[];

    const key = this.recipientKey(invoice);
    const allByRecipient = allInvoices.filter(
      (inv) =>
        this.recipientKey(inv) === key &&
        String(inv._id) !== String(invoice._id)
    );
    const paidByRecipient = allByRecipient.filter(
      (inv) => inv.status === InvoiceStatus.PAID
    );
    const { riskLevel, daysOverdue, avgHistoricalDelayDays } =
      this.computeRiskScore(invoice, now, paidByRecipient, allByRecipient);

    const recipientName = this.recipientLabel(invoice);
    const business = await this.businessModel.findById(businessId).lean();
    const businessName = business?.name ?? 'Notre entreprise';

    // Build the prompt for OpenRouter
    const toneMap: Record<string, string> = {
      LOW: 'courtois et amical, simple rappel',
      MEDIUM: 'professionnel et direct, mention des conséquences possibles',
      HIGH: 'ferme et urgent, demande de paiement immédiat',
      CRITICAL:
        'très ferme, mention de recours légaux possibles si non-paiement dans les 48h',
    };
    const tone = toneMap[riskLevel] ?? 'professionnel';

    const historyNote =
      avgHistoricalDelayDays === undefined
        ? "Pas d'historique de paiement disponible pour ce client."
        : `Ce client paie en moyenne avec ${Math.round(avgHistoricalDelayDays)} jours de retard.`;

    const systemPrompt = `Tu es un assistant spécialisé en relances de factures impayées pour PME tunisiennes.
Tu rédiges des emails de relance professionnels en français.
Ton ton doit être : ${tone}.
Réponds UNIQUEMENT avec un JSON valide contenant ces clés : "subject" (string), "body" (string), "recommendedAction" (string).
Ne rajoute aucun texte hors du JSON.`;

    const userPrompt = `Génère un email de relance pour la facture suivante :

- Numéro de facture : ${invoice.invoiceNumber}
- Montant dû : ${invoice.totalAmount} ${invoice.currency ?? 'TND'}
- Date d'échéance : ${new Date(invoice.dueDate).toLocaleDateString('fr-FR')}
- Jours de retard : ${daysOverdue}
- Destinataire : ${recipientName}
- Notre entreprise : ${businessName}
- Niveau de risque : ${riskLevel}
- ${historyNote}

Génère un email de relance complet avec objet et corps du message.`;

    let rawResponse: string;
    try {
      const client = await this.getOpenRouterClient();
      const result = await this.withTimeout(
        client.chat.send({
          chatRequest: {
            model: this.openRouterModel,
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: userPrompt },
            ],
            maxCompletionTokens: 600,
            temperature: 0.3,
            stream: false,
          },
        }),
        this.openRouterTimeoutMs,
        'Collections reminder generation'
      );

      const content = (
        result as {
          choices?: Array<{
            message?: { content?: string | Array<{ text?: string }> };
          }>;
        }
      )?.choices?.[0]?.message?.content;

      if (typeof content === 'string') {
        rawResponse = content;
      } else if (Array.isArray(content)) {
        rawResponse = content.map((p) => p.text ?? '').join('');
      } else {
        throw new TypeError('Empty response from OpenRouter');
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.error(`Reminder generation failed: ${msg}`);
      throw new ServiceUnavailableException(
        'Le service IA est temporairement indisponible. Réessayez dans un instant.'
      );
    }

    // Parse JSON from response
    let parsed: {
      subject?: string;
      body?: string;
      recommendedAction?: string;
    } = {};
    try {
      const jsonMatch = /{[\S\s]*}/.exec(rawResponse);
      if (jsonMatch) {
        parsed = JSON.parse(jsonMatch[0]) as typeof parsed;
      }
    } catch {
      this.logger.warn(
        'Could not parse JSON from reminder response, using raw text'
      );
    }

    return {
      invoiceId: String(invoice._id),
      riskLevel,
      subject:
        parsed.subject ?? `Relance – Facture ${invoice.invoiceNumber} impayée`,
      reminderMessage: parsed.body ?? rawResponse,
      recommendedAction: parsed.recommendedAction,
    };
  }
}
