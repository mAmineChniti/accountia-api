/**
 * Invoice Recipient Type Enum
 * Determines the type of recipient for an invoice
 */
export enum InvoiceRecipientType {
  PLATFORM_BUSINESS = 'PLATFORM_BUSINESS', // Registered business on platform
  PLATFORM_INDIVIDUAL = 'PLATFORM_INDIVIDUAL', // Registered user on platform
  EXTERNAL = 'EXTERNAL', // External contact not registered on platform
}

/**
 * Recipient Resolution Status Enum
 * Tracks whether a recipient's platform identity has been resolved
 */
export enum RecipientResolutionStatus {
  RESOLVED = 'RESOLVED', // Recipient identity linked to platform
  PENDING = 'PENDING', // Recipient exists but identity not fully resolved
  CLAIMED = 'CLAIMED', // External recipient has claimed their identity
  NEVER_RESOLVED = 'NEVER_RESOLVED', // External recipient never joined platform
}
