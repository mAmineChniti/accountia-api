import {
  Injectable,
  ForbiddenException,
  NotFoundException,
  ServiceUnavailableException,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectConnection, InjectModel } from '@nestjs/mongoose';
import { Connection, Model } from 'mongoose';
import Stripe from 'stripe';
import { InvoiceReceipt } from '@/invoices/schemas/invoice-receipt.schema';

import {
  CreateInvoiceCheckoutSessionDto,
  InvoiceCheckoutSessionResponseDto,
  MockInvoicePaymentDto,
} from '@/invoices/dto/invoice.dto';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import { InvoiceIssuanceService } from '@/invoices/services/invoice-issuance.service';
import type { UserPayload } from '@/auth/types/auth.types';
import { EmailService } from '@/email/email.service';
import { Business } from '@/business/schemas/business.schema';
import { NotificationsService } from '@/notifications/notifications.service';
import { NotificationType } from '@/notifications/schemas/notification.schema';

@Injectable()
export class InvoicePaymentService {
  private readonly logger = new Logger(InvoicePaymentService.name);
  private readonly stripeClient?: InstanceType<typeof Stripe>;
  private readonly stripeWebhookSecret?: string;
  private readonly stripeFallbackCurrency: string;
  private readonly fallbackFxRates: Map<string, number>;
  private readonly mockInvoicePaymentsEnabled: boolean;
  private readonly paymentMethodConfigurationId?: string;

  constructor(
    private readonly configService: ConfigService,
    @InjectModel(InvoiceReceipt.name)
    private readonly invoiceReceiptModel: Model<InvoiceReceipt>,
    private readonly issuanceService: InvoiceIssuanceService,
    private readonly emailService: EmailService,
    private readonly notificationsService: NotificationsService,
    @InjectConnection() private readonly mainConnection: Connection,
    @InjectModel(Business.name) private readonly businessModel: Model<Business>
  ) {
    const stripeSecretKey = (
      this.configService.get<string>('STRIPE_SECRET_KEY') ??
      process.env.STRIPE_SECRET_KEY
    )?.trim();
    this.stripeWebhookSecret = (
      this.configService.get<string>('STRIPE_WEBHOOK_SECRET') ??
      process.env.STRIPE_WEBHOOK_SECRET
    )?.trim();
    this.stripeFallbackCurrency = (
      this.configService.get<string>('STRIPE_FALLBACK_CURRENCY') ??
      process.env.STRIPE_FALLBACK_CURRENCY ??
      'usd'
    )
      .trim()
      .toLowerCase();

    this.fallbackFxRates = this.parseFallbackFxRates(
      this.configService.get<string>('STRIPE_FX_RATES') ??
        process.env.STRIPE_FX_RATES ??
        'TND:0.32'
    );

    this.paymentMethodConfigurationId = (
      this.configService.get<string>('PAYMENT_METHOD_CONFIGURATION') ??
      process.env.PAYMENT_METHOD_CONFIGURATION
    )?.trim();

    const mockFlag =
      this.configService.get<string>('MOCK_INVOICE_PAYMENTS') ??
      process.env.MOCK_INVOICE_PAYMENTS ??
      'false';
    this.mockInvoicePaymentsEnabled =
      String(mockFlag).trim().toLowerCase() === 'true';

    if (stripeSecretKey) {
      this.stripeClient = new Stripe(stripeSecretKey);
      this.logger.log('Stripe payment provider initialized');
    } else {
      this.logger.warn(
        'Stripe payment provider not configured: STRIPE_SECRET_KEY is missing'
      );
    }
  }

  private ensureStripeEnabled(): InstanceType<typeof Stripe> {
    if (!this.stripeClient) {
      throw new ServiceUnavailableException(
        'Online payment is not configured yet. Please contact support.'
      );
    }
    return this.stripeClient;
  }

  private assertRecipientCanPay(
    receipt: InvoiceReceipt,
    user: UserPayload
  ): void {
    const receiptUserId = receipt.recipientUserId?.toString();
    const normalizedReceiptEmail = receipt.recipientEmail?.toLowerCase().trim();
    const normalizedUserEmail = user.email.toLowerCase().trim();

    const allowedByUserId = receiptUserId === user.id;
    const allowedByEmail =
      Boolean(normalizedReceiptEmail) &&
      normalizedReceiptEmail === normalizedUserEmail;

    if (!allowedByUserId && !allowedByEmail) {
      throw new ForbiddenException(
        'You do not have access to pay this invoice'
      );
    }
  }

  private isPayableStatus(status: InvoiceStatus): boolean {
    return [
      InvoiceStatus.ISSUED,
      InvoiceStatus.VIEWED,
      InvoiceStatus.PARTIAL,
      InvoiceStatus.OVERDUE,
      InvoiceStatus.DISPUTED,
    ].includes(status);
  }

  private parseFallbackFxRates(rawValue: string): Map<string, number> {
    const rates = new Map<string, number>();
    for (const part of rawValue.split(',')) {
      const trimmed = part.trim();
      if (!trimmed) {
        continue;
      }
      const [fromCurrencyRaw, rateRaw] = trimmed.split(':');
      if (!fromCurrencyRaw || !rateRaw) {
        continue;
      }
      const fromCurrency = fromCurrencyRaw.trim().toLowerCase();
      const rate = Number(rateRaw.trim());
      if (!fromCurrency || !Number.isFinite(rate) || rate <= 0) {
        continue;
      }
      rates.set(fromCurrency, rate);
    }
    return rates;
  }

  private convertToFallbackCurrency(
    amount: number,
    invoiceCurrency: string
  ): { convertedAmount: number; rate: number } | undefined {
    const fromCurrency = invoiceCurrency.trim().toLowerCase();
    if (fromCurrency === this.stripeFallbackCurrency) {
      return { convertedAmount: amount, rate: 1 };
    }

    const rate = this.fallbackFxRates.get(fromCurrency);
    if (!rate) {
      return undefined;
    }

    const convertedAmount = Number((amount * rate).toFixed(2));
    if (!Number.isFinite(convertedAmount) || convertedAmount <= 0) {
      return undefined;
    }

    return { convertedAmount, rate };
  }

  async createCheckoutSession(
    receiptId: string,
    user: UserPayload,
    _options?: CreateInvoiceCheckoutSessionDto
  ): Promise<InvoiceCheckoutSessionResponseDto> {
    const stripe = this.ensureStripeEnabled();

    const receipt = await this.invoiceReceiptModel.findById(receiptId).exec();
    if (!receipt) {
      throw new NotFoundException('Invoice receipt not found');
    }

    this.assertRecipientCanPay(receipt, user);

    const invoice = await this.issuanceService.getInvoiceById(
      receipt.invoiceId.toString(),
      receipt.issuerTenantDatabaseName
    );

    if (!this.isPayableStatus(invoice.status)) {
      throw new BadRequestException(
        `Invoice cannot be paid in status ${invoice.status}`
      );
    }

    const remainingAmount = Math.max(
      0,
      invoice.totalAmount - invoice.amountPaid
    );
    if (remainingAmount <= 0) {
      throw new BadRequestException('Invoice is already fully paid');
    }

    // Retrieve business from platform DB to get Stripe Connect account ID
    const business = await this.businessModel
      .findById(receipt.issuerBusinessId)
      .exec();
    if (!business) {
      throw new NotFoundException('Business not found');
    }
    const connectedAccountId = business.stripeConnectId?.trim();
    if (!connectedAccountId) {
      this.logger.warn(
        `Business "${receipt.issuerBusinessName}" has no Stripe Connect account. Falling back to platform Stripe account for checkout.`
      );
    }

    const baseMetadata: Record<string, string> = {
      invoiceId: invoice.id,
      receiptId,
      issuerBusinessId: receipt.issuerBusinessId.toString(),
      issuerTenantDatabaseName: receipt.issuerTenantDatabaseName,
      payerUserId: user.id,
      payerEmail: user.email,
      originalInvoiceCurrency: invoice.currency,
      originalInvoiceAmount: remainingAmount.toFixed(2),
    };

    const createPaymentIntent = async (
      currency: string,
      amount: number,
      metadata: Record<string, string>
    ) => {
      const requestOptions = undefined; // Quick override to bypass connect onboarding issues during testing

      return stripe.paymentIntents.create(
        {
          amount: Math.round(amount * 100),
          currency,
          metadata,
          receipt_email: user.email,
          automatic_payment_methods: { enabled: true },
        },
        requestOptions
      );
    };

    const invoiceCurrency = invoice.currency.trim().toLowerCase();
    let paymentIntent: { id: string; client_secret: string | null } | undefined;
    try {
      paymentIntent = await createPaymentIntent(
        invoiceCurrency,
        remainingAmount,
        baseMetadata
      );
    } catch (error) {
      const message =
        error instanceof Error ? error.message.toLowerCase() : String(error);
      const isInvalidCurrency = message.includes('invalid currency');

      if (!isInvalidCurrency) {
        throw error;
      }

      const conversion = this.convertToFallbackCurrency(
        remainingAmount,
        invoiceCurrency
      );
      if (!conversion) {
        throw new BadRequestException(
          `Unsupported invoice currency ${invoice.currency}. Configure STRIPE_FX_RATES for fallback currency ${this.stripeFallbackCurrency}.`
        );
      }

      this.logger.warn(
        `Stripe currency fallback used for invoice ${invoice.invoiceNumber}: ${invoiceCurrency} -> ${this.stripeFallbackCurrency} (rate=${conversion.rate})`
      );

      paymentIntent = await createPaymentIntent(
        this.stripeFallbackCurrency,
        conversion.convertedAmount,
        {
          ...baseMetadata,
          checkoutCurrency: this.stripeFallbackCurrency,
          conversionRate: conversion.rate.toString(),
          convertedAmount: conversion.convertedAmount.toFixed(2),
        }
      );
    }

    if (!paymentIntent) {
      throw new ServiceUnavailableException(
        'Unable to create payment session. Please try again.'
      );
    }

    return {
      clientSecret: paymentIntent.client_secret ?? '',
      sessionId: paymentIntent.id,
      checkoutUrl: undefined,
    };
  }

  async simulateIndividualPayment(
    receiptId: string,
    user: UserPayload,
    _mockPaymentDto?: MockInvoicePaymentDto
  ) {
    if (!this.mockInvoicePaymentsEnabled) {
      throw new ForbiddenException(
        'Mock payments are disabled. Set MOCK_INVOICE_PAYMENTS=true to enable demo payments.'
      );
    }

    const receipt = await this.invoiceReceiptModel.findById(receiptId).exec();
    if (!receipt) {
      throw new NotFoundException('Invoice receipt not found');
    }

    this.assertRecipientCanPay(receipt, user);

    const invoice = await this.issuanceService.getInvoiceById(
      receipt.invoiceId.toString(),
      receipt.issuerTenantDatabaseName
    );

    if (!this.isPayableStatus(invoice.status)) {
      throw new BadRequestException(
        `Invoice cannot be paid in status ${invoice.status}`
      );
    }

    if (invoice.status !== InvoiceStatus.PAID) {
      await this.issuanceService.transitionInvoiceState(
        invoice.id,
        receipt.issuerBusinessId.toString(),
        receipt.issuerTenantDatabaseName,
        {
          newStatus: InvoiceStatus.PAID,
          amountPaid: invoice.totalAmount,
          reason: 'Demo mock payment',
        },
        user.id
      );

      try {
        await this.notificationsService.createNotification({
          type: NotificationType.INVOICE_PAID,
          message: `Invoice ${invoice.invoiceNumber} was paid by ${user.email}`,
          targetBusinessId: receipt.issuerBusinessId.toString(),
          payload: {
            invoiceId: invoice.id,
            invoiceNumber: invoice.invoiceNumber,
            payerEmail: user.email,
            paidAmount: invoice.totalAmount,
            currency: invoice.currency,
          },
        });
      } catch (error) {
        this.logger.warn(
          `Failed to create paid notification for invoice ${invoice.id}: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }

      try {
        await this.emailService.sendInvoicePaymentConfirmation(
          user.email,
          invoice.invoiceNumber,
          invoice.totalAmount,
          invoice.currency,
          receipt.issuerBusinessName
        );
      } catch (error) {
        this.logger.warn(
          `Failed to send payment confirmation for invoice ${invoice.id}: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }

    const updatedInvoice = await this.issuanceService.getInvoiceById(
      invoice.id,
      receipt.issuerTenantDatabaseName
    );

    return updatedInvoice;
  }

  private async completeInvoicePayment(input: {
    invoiceId: string;
    issuerBusinessId: string;
    issuerTenantDatabaseName: string;
    payerUserId?: string;
    payerEmail?: string;
    issuerBusinessName: string;
  }): Promise<boolean> {
    const invoice = await this.issuanceService.getInvoiceById(
      input.invoiceId,
      input.issuerTenantDatabaseName
    );

    if (invoice.status === InvoiceStatus.PAID) {
      return true;
    }

    await this.issuanceService.transitionInvoiceState(
      input.invoiceId,
      input.issuerBusinessId,
      input.issuerTenantDatabaseName,
      {
        newStatus: InvoiceStatus.PAID,
        amountPaid: invoice.totalAmount,
      },
      input.payerUserId ?? ''
    );

    // Keep API response fast: run side effects in background after payment state is persisted.
    void this.notificationsService
      .createNotification({
        type: NotificationType.INVOICE_PAID,
        message: `Invoice ${invoice.invoiceNumber} was paid by ${input.payerEmail ?? 'a client'}`,
        targetBusinessId: input.issuerBusinessId,
        payload: {
          invoiceId: input.invoiceId,
          invoiceNumber: invoice.invoiceNumber,
          payerEmail: input.payerEmail,
          paidAmount: invoice.totalAmount,
          currency: invoice.currency,
        },
      })
      .catch((error: unknown) => {
        this.logger.warn(
          `Failed to create paid notification for invoice ${input.invoiceId}: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      });

    if (input.payerEmail) {
      void this.emailService
        .sendInvoicePaymentConfirmation(
          input.payerEmail,
          invoice.invoiceNumber,
          invoice.totalAmount,
          invoice.currency,
          input.issuerBusinessName
        )
        .catch((error: unknown) => {
          this.logger.warn(
            `Payment confirmation email failed for ${input.payerEmail}: ${
              error instanceof Error ? error.message : String(error)
            }`
          );
        });
    }

    return true;
  }

  async handleStripeWebhook(
    signatureHeader: string | undefined,
    rawBody: Buffer
  ): Promise<void> {
    const stripe = this.ensureStripeEnabled();

    if (!this.stripeWebhookSecret) {
      throw new ServiceUnavailableException(
        'Stripe webhook secret is not configured'
      );
    }

    if (!signatureHeader) {
      throw new BadRequestException('Missing Stripe signature header');
    }

    let event: ReturnType<
      InstanceType<typeof Stripe>['webhooks']['constructEvent']
    >;
    try {
      event = stripe.webhooks.constructEvent(
        rawBody,
        signatureHeader,
        this.stripeWebhookSecret
      );
    } catch (error) {
      throw new BadRequestException(
        `Invalid Stripe webhook signature: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }

    if (
      event.type === 'account.updated' ||
      event.type === 'account.external_account.created'
    ) {
      await this.handleStripeAccountEvent(event);
      return;
    }

    if (
      event.type !== 'checkout.session.completed' &&
      event.type !== 'checkout.session.async_payment_succeeded' &&
      event.type !== 'payment_intent.succeeded'
    ) {
      return;
    }

    const session = event.data.object as {
      id?: string;
      payment_status?: string;
      status?: string;
      metadata?: Record<string, string>;
    };

    // For Payment Intents, success is indicated by status 'succeeded'
    // For Checkout Sessions, it's payment_status 'paid'
    const isPaid =
      session.payment_status === 'paid' || session.status === 'succeeded';

    if (!isPaid) {
      return;
    }

    const metadata = session.metadata ?? {};
    const invoiceId = metadata.invoiceId;
    const receiptId = metadata.receiptId;
    const issuerBusinessId = metadata.issuerBusinessId;
    const issuerTenantDatabaseName = metadata.issuerTenantDatabaseName;
    const payerUserId = metadata.payerUserId;
    const payerEmail = metadata.payerEmail;

    if (
      !invoiceId ||
      !issuerBusinessId ||
      !issuerTenantDatabaseName ||
      !payerUserId
    ) {
      this.logger.warn(
        `Stripe session ${session.id} missing invoice metadata. Skipping state transition.`
      );
      return;
    }

    const receipt = receiptId
      ? await this.invoiceReceiptModel.findById(receiptId).exec()
      : undefined;
    const issuerBusinessName =
      receipt?.issuerBusinessName ?? 'Unknown Business';

    await this.completeInvoicePayment({
      invoiceId,
      issuerBusinessId,
      issuerTenantDatabaseName,
      payerUserId,
      payerEmail,
      issuerBusinessName,
    });
  }

  private async handleStripeAccountEvent(
    event: ReturnType<InstanceType<typeof Stripe>['webhooks']['constructEvent']>
  ): Promise<void> {
    const stripeAccountId = (event.data.object as { id?: string }).id;

    if (!stripeAccountId) {
      this.logger.warn(
        `Stripe account webhook ${event.type} missing account id in payload`
      );
      return;
    }

    const business = await this.businessModel
      .findOne({ stripeConnectId: stripeAccountId })
      .exec();

    if (!business) {
      this.logger.warn(
        `No business found for Stripe account ${stripeAccountId} on event ${event.type}`
      );
      return;
    }

    const setPayload: Record<string, string> = {};
    if (business.stripeConnectId !== stripeAccountId) {
      setPayload.stripeConnectId = stripeAccountId;
    }

    const updateDoc: Record<string, unknown> = {
      $unset: { stripeOnboardingUrl: '' },
    };
    if (Object.keys(setPayload).length > 0) {
      updateDoc.$set = setPayload;
    }

    await this.businessModel.updateOne({ _id: business._id }, updateDoc).exec();

    this.logger.log(
      `Stripe account ${stripeAccountId} synced for business ${String(business._id)} via ${event.type}. Cleared onboarding URL.`
    );
  }
}
