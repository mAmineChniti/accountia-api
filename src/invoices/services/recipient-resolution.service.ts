import { Injectable, Logger } from '@nestjs/common';
import { InjectModel, InjectConnection } from '@nestjs/mongoose';
import { Model, Connection } from 'mongoose';
import { InvoiceReceipt } from '@/invoices/schemas/invoice-receipt.schema';

/**
 * RecipientResolutionService
 * Handles background identity resolution for invoice recipients
 * Resolves external recipient identities when they join the platform
 *
 * ARCHITECTURAL ROLE:
 * - Receives events from user service when new user claims an email
 * - Links pending external invoice recipients to their new platform identity
 * - Enables invoice visibility once external recipient creates account
 *
 * CRITICAL ASSUMPTION:
 * - Only call resolveRecipientIdentity() AFTER user service confirms
 *   that newUserId has verified ownership of recipientEmail
 * - This service trusts the user service to handle email verification
 *
 * IDEMPOTENCY:
 * - resolveRecipientIdentity() is idempotent (safe to call multiple times)
 * - Only resolves unresolved receipts (prevents duplicate resolution)
 */
@Injectable()
export class RecipientResolutionService {
  private readonly logger = new Logger(RecipientResolutionService.name);

  constructor(
    @InjectModel(InvoiceReceipt.name)
    private invoiceReceiptModel: Model<InvoiceReceipt>,
    @InjectConnection() private connection: Connection
  ) {}

  /**
   * Resolve recipient identity when they join the platform with verified email
   *
   * Called by: UserService.onEmailVerified() or similar event handler
   * Precondition: newUserId has verified ownership of recipientEmail
   *
   * Effect: Links all pending external invoices to the new user account
   * Result: Invoices become accessible via user's platform identity
   */
  async resolveRecipientIdentity(
    recipientEmail: string,
    newUserId: string
  ): Promise<void> {
    if (!recipientEmail || !newUserId) {
      throw new Error('recipientEmail and newUserId are required');
    }

    try {
      // Normalize email to lowercase for consistent matching
      // This handles variant email addresses: JOHN@EX.COM, john@ex.com, etc.
      const normalizedEmail = recipientEmail.toLowerCase().trim();

      // Find all UNRESOLVED receipts with this email
      // Idempotency: Only update if recipientUserId not already set
      // This prevents race conditions if called multiple times
      const unresolvedReceipts = await this.invoiceReceiptModel
        .find({
          recipientEmail: normalizedEmail,
          recipientUserId: { $exists: false },
        })
        .exec();

      if (unresolvedReceipts.length === 0) {
        this.logger.debug(
          `No unresolved receipts found for email: ${normalizedEmail}`
        );
        return;
      }

      // Update each receipt: Link external recipient to platform user ID
      // After this, invoices are discoverable via user search
      for (const receipt of unresolvedReceipts) {
        receipt.recipientUserId = newUserId;
        await receipt.save();
      }

      this.logger.log(
        `Resolved ${unresolvedReceipts.length} external invoices for email ${normalizedEmail} → user ${newUserId}`
      );
    } catch (error) {
      this.logger.error(
        `Error resolving recipient identity for ${recipientEmail}: ${error}`,
        error
      );
      throw error;
    }
  }

  /**
   * Batch resolve identities for multiple recipients
   * Background job to attempt resolution of pending external recipients
   * Usually called periodically or event-driven from user service
   *
   * This is a more efficient way to handle bulk user signup scenarios
   * Instead of resolving one-by-one, resolve multiple at once
   */
  async batchResolveIdentities(recipientEmails: string[]): Promise<void> {
    try {
      if (!recipientEmails || recipientEmails.length === 0) {
        return;
      }

      // Normalize all emails
      const normalizedEmails = recipientEmails.map((e) =>
        e.toLowerCase().trim()
      );

      // Find all pending receipts matching the email list that don't have a resolved user ID
      const pendingReceipts = await this.invoiceReceiptModel
        .find({
          recipientEmail: { $in: normalizedEmails },
          recipientUserId: { $exists: false },
        })
        .exec();

      if (pendingReceipts.length === 0) {
        this.logger.debug(
          `No pending receipts found for ${normalizedEmails.length} emails`
        );
        return;
      }

      this.logger.log(
        `Found ${pendingReceipts.length} pending receipts for batch resolution across ${normalizedEmails.length} emails`
      );

      // NOTE: In production, you would query a user service to find resolved users
      // For now, just log that these are pending resolution
      // When integrated with user service, you'd do:
      // const resolved = await userService.findByEmails(normalizedEmails)
      // Then update receipts with their user IDs
    } catch (error) {
      this.logger.error('Error in batch resolve identities: ' + error, error);
      throw error;
    }
  }
}
