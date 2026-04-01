import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface GeneratePaymentResponse {
  link: string;
  payment_id: string;
  developer_tracking_id?: string;
  success: boolean;
}

export interface VerifyPaymentResponse {
  success: boolean;
  result?: {
    payment_id: string;
    amount: number;
    status: 'SUCCESS' | 'FAILURE' | 'PENDING';
    details: Record<string, unknown>;
  };
}

@Injectable()
export class FlouciService {
  private readonly logger = new Logger(FlouciService.name);
  private readonly publicKey: string | undefined;
  private readonly secretKey: string | undefined;
  private readonly baseUrl = 'https://developers.flouci.com/api/v2';
  private readonly isSimulationMode: boolean;

  constructor(private configService: ConfigService) {
    this.publicKey = this.configService.get<string>('FLOUCI_PUBLIC_KEY');
    this.secretKey = this.configService.get<string>('FLOUCI_SECRET_KEY');

    // Si les clés ne sont pas configurées, on passe en mode simulation
    this.isSimulationMode = !this.publicKey || !this.secretKey;

    if (this.isSimulationMode) {
      this.logger.warn(
        '⚠️ FLOUCI_PUBLIC_KEY or FLOUCI_SECRET_KEY is missing in .env'
      );
      this.logger.warn('⚠️ Running FlouciService in SIMULATION MODE.');
    } else {
      this.logger.log('✅ Flouci API configured successfully.');
    }
  }

  /**
   * Génère un lien de paiement Flouci
   */
  async generatePayment(
    amount: number, // en DINARS (ex: 120.50)
    invoiceId: string,
    successLink: string,
    failLink: string
  ): Promise<GeneratePaymentResponse> {
    if (this.isSimulationMode) {
      this.logger.log(
        `[SIMULATION] Generating payment for invoice ${invoiceId} - Amount: ${amount} TND`
      );

      // On redirige vers notre page de simulation ultra-réaliste au lieu de valider direct
      // On extrait la base URL et la langue du successLink (ex: http://localhost:3000/en/...)
      const urlMatch = /^(https?:\/\/[^/]+)\/([a-z]{2})\//.exec(successLink);
      const baseUrl = urlMatch ? urlMatch[1] : 'http://localhost:3000';
      const lang = urlMatch ? urlMatch[2] : 'en';

      const simulationLink = `${baseUrl}/${lang}/managed/payment-simulation?invoiceId=${invoiceId}&amount=${amount}&successLink=${encodeURIComponent(successLink)}`;

      return {
        success: true,
        payment_id: `sim_pending_${Date.now()}`,
        developer_tracking_id: invoiceId,
        link: simulationLink,
      };
    }

    try {
      // Flouci attend le montant en millimes (ex: 120.50 TND => 120500 millimes)
      const amountInMillimes = Math.round(amount * 1000);

      const response = await fetch(`${this.baseUrl}/generate_payment`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.publicKey}:${this.secretKey}`,
        },
        body: JSON.stringify({
          app_public: this.publicKey,
          amount: amountInMillimes,
          developer_tracking_id: invoiceId,
          success_link: successLink,
          fail_link: failLink,
        }),
      });

      const data = (await response.json()) as Record<string, unknown>;

      if (!response.ok || !(data.success === true)) {
        this.logger.error(`Flouci Error: ${JSON.stringify(data)}`);
        throw new Error('Failed to generate Flouci payment link');
      }

      return data as unknown as GeneratePaymentResponse;
    } catch (error) {
      this.logger.error('Error generating flouci payment', error);
      throw error;
    }
  }

  /**
   * Vérifie le statut d'un paiement
   */
  async verifyPayment(paymentId: string): Promise<VerifyPaymentResponse> {
    if (this.isSimulationMode) {
      this.logger.log(
        `[SIMULATION] Verifying payment for paymentId ${paymentId}`
      );
      // Simuler un paiement réussi
      return {
        success: true,
        result: {
          payment_id: paymentId,
          amount: 0, // Mocked
          status: 'SUCCESS',
          details: { simulated: true },
        },
      };
    }

    try {
      const response = await fetch(
        `${this.baseUrl}/verify_payment/${paymentId}`,
        {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            apppublic: this.publicKey ?? '',
            appsecret: this.secretKey ?? '',
            // Note: Selon la doc Flouci, l'authentification est parfois dans les headers custom au lieu de Bearer pour verify
            // mais on peut aussi envoyer Bearer
            Authorization: `Bearer ${this.publicKey}:${this.secretKey}`,
          },
        }
      );

      const data = (await response.json()) as Record<string, unknown>;

      if (!response.ok) {
        this.logger.error(`Flouci Verify Error: ${JSON.stringify(data)}`);
        throw new Error('Failed to verify Flouci payment');
      }

      return data as unknown as VerifyPaymentResponse;
    } catch (error) {
      this.logger.error('Error verifying flouci payment', error);
      throw error;
    }
  }
}
