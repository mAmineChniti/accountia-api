import { type Logger, BadRequestException } from '@nestjs/common';

export interface AiMappingSchema {
  targetKeys: string[];
  description: string;
}

/**
 * Universal synonym dictionary for common accounting terms.
 * Keys will be normalized (lowercase, no _, no spaces) before matching.
 */
const SYNONYMS: Record<string, string> = {
  // Invoices
  facture: 'invoiceNumber',
  numfacture: 'invoiceNumber',
  num: 'invoiceNumber',
  ref: 'invoiceNumber',

  typedestinataire: 'recipientType',
  type: 'recipientType',
  destinataire: 'recipientType',
  nature: 'recipientType',

  email: 'recipientEmail',
  mail: 'recipientEmail',
  courriel: 'recipientEmail',

  nom: 'recipientDisplayName',
  client: 'recipientDisplayName',
  societe: 'recipientDisplayName',

  idplateforme: 'recipientPlatformId',
  platformid: 'recipientPlatformId',

  // Products / Line Items
  idsproduits: 'productIds',
  idproduit: 'productIds',
  refproduit: 'productIds',
  productids: 'productIds',

  nomsproduits: 'productNames',
  productnames: 'productNames',
  designation: 'productNames',
  article: 'productNames',

  quantites: 'quantities',
  quantite: 'quantities',
  qte: 'quantities',
  nb: 'quantities',

  prixunitaires: 'unitPrices',
  prixunitaire: 'unitPrices',
  unitprices: 'unitPrices',
  prix: 'unitPrices',
  tarif: 'unitPrices',
  pu: 'unitPrices',

  dateemission: 'issuedDate',
  dateo: 'issuedDate',
  emission: 'issuedDate',
  date: 'issuedDate',

  dateecheance: 'dueDate',
  echeance: 'dueDate',
  datefin: 'dueDate',

  devise: 'currency',
  monnaie: 'currency',
  currency: 'currency',

  // General Product fields
  cout: 'cost',
  prixvente: 'unitPrice',
};

/**
 * Normalizes values like "EXTERNE" to "EXTERNAL" and handles date formats
 */
function normalizeValue(
  key: string,
  value: any,
  logger: Logger | null = null
): any {
  if (typeof value !== 'string' || !value.trim()) return value;
  const val = value.trim();

  // 1. Recipient Type Normalization
  if (key === 'recipientType') {
    const v = val.toUpperCase();
    if (['EXTERNE', 'EXTERN', 'OUTSIDE', 'EXT'].includes(v)) return 'EXTERNAL';
    if (['INDIVIDU', 'PARTICULIER', 'INDIVIDUAL', 'PERS'].includes(v))
      return 'PLATFORM_INDIVIDUAL';
    if (
      ['BUSINESS', 'ENTREPRISE', 'SOCIETE', 'B2B', 'PROFESSIONAL'].includes(v)
    )
      return 'PLATFORM_BUSINESS';
  }

  // 2. Date Normalization (DD/MM/YYYY -> YYYY-MM-DD)
  if (key === 'issuedDate' || key === 'dueDate') {
    // Match DD/MM/YYYY or DD-MM-YYYY
    const dateMatch = /^(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})$/.exec(val);
    if (dateMatch) {
      const [, day, month, year] = dateMatch;
      const normalizedDate = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
      if (logger)
        logger.debug(`[AI-Fix] Normalized date: ${val} -> ${normalizedDate}`);
      return normalizedDate;
    }
  }

  // 3. Currency Normalization
  if (key === 'currency') {
    const v = val.toUpperCase();
    if (['DT', 'DINAR', 'TND'].includes(v)) return 'TND';
    if (['EUR', 'EURO', '€'].includes(v)) return 'EUR';
    if (['USD', 'DOLLAR', '$'].includes(v)) return 'USD';
  }

  return value;
}

/**
 * Finds the best target key for a given header
 */
function fuzzyMatch(header: string, targetKeys: string[]): string | null {
  const h = header.toLowerCase().replaceAll(/[^\da-z]/g, '');

  // 1. Direct match
  if (targetKeys.includes(header)) return header;

  // 2. Exact normalized match
  for (const [synonym, target] of Object.entries(SYNONYMS)) {
    if (h === synonym && targetKeys.includes(target)) return target;
  }

  // 3. Substring match
  for (const [synonym, target] of Object.entries(SYNONYMS)) {
    if (h.includes(synonym) && targetKeys.includes(target)) return target;
  }

  return null;
}

export async function fixStructureWithAi(
  rawRecords: Record<string, any>[],
  schema: AiMappingSchema,
  logger: Logger
): Promise<Record<string, any>[]> {
  const geminiKey = process.env.GEMINI_API_KEY?.replaceAll('"', '');

  const mapAllRecords = (mapping: Record<string, string>) => {
    return rawRecords.map((record) => {
      const newRecord: any = {};
      // Force all schema keys to exist to avoid "missing field" validation errors
      for (const k of schema.targetKeys) {
        const isNumeric = [
          'quantities',
          'unitPrices',
          'quantity',
          'cost',
          'unitPrice',
        ].includes(k);
        newRecord[k] = isNumeric ? 0 : '';
      }

      // Map columns
      for (const [key, value] of Object.entries(record)) {
        const targetKey = mapping[key] || fuzzyMatch(key, schema.targetKeys);
        if (targetKey && schema.targetKeys.includes(targetKey)) {
          newRecord[targetKey] = normalizeValue(targetKey, value);
        }
      }
      return newRecord;
    });
  };

  if (geminiKey && geminiKey.length > 20) {
    const models = [
      'gemini-2.0-flash-lite',
      'gemini-1.5-flash',
      'gemini-2.0-flash',
    ];
    let mappingText = '';

    for (const model of models) {
      let attempts = 0;
      const maxAttempts = 2;

      while (attempts < maxAttempts) {
        attempts++;
        try {
          const sample = rawRecords.slice(0, 3);
          const prompt = `Map columns [${Object.keys(rawRecords[0] || {}).join(', ')}] to target keys [${schema.targetKeys.join(', ')}]. JSON only: {"source_col": "target_key"}. \nData help: ${JSON.stringify(sample)}`;

          const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: {
                  temperature: 0.1,
                  response_mime_type: 'application/json',
                },
              }),
            }
          );

          if (response.ok) {
            const data = await response.json();
            mappingText = data.candidates?.[0]?.content?.parts?.[0]?.text
              ?.replaceAll(/```json|```/gi, '')
              .trim();
            break; // Success!
          } else {
            const errorData = await response.json().catch(() => ({}));
            const isQuotaError =
              response.status === 429 ||
              JSON.stringify(errorData).includes('quota');

            if (isQuotaError && attempts < maxAttempts) {
              logger.warn(
                `[AI-Mapping] Quota reached for ${model}. Retrying in 2s...`
              );
              await new Promise((resolve) => setTimeout(resolve, 2000));
              continue;
            }
            logger.warn(
              `[AI-Mapping] Model ${model} failed with status ${response.status}`
            );
            break; // Try next model
          }
        } catch (error) {
          logger.warn(`[AI-Mapping] Error with ${model}: ${error.message}`);
          break; // Try next model
        }
      }

      if (mappingText) {
        try {
          const mapping = JSON.parse(mappingText);
          logger.log(
            `[AI-Mapping] Success with ${model}: ${JSON.stringify(mapping)}`
          );
          return mapAllRecords(mapping);
        } catch {
          logger.error(
            `[AI-Mapping] Failed to parse mapping from ${model}: ${mappingText}`
          );
          // Continue to next model if parsing fails
          mappingText = '';
        }
      }
    }
  }

  logger.log('[AI-Mapping] Using robust fuzzy mapping logic...');
  return mapAllRecords({});
}
