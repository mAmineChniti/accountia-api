import { Logger } from '@nestjs/common';
import OpenAI from 'openai';

const logger = new Logger('AiMapper');
const GROQ_MODEL = 'llama-3.3-70b-versatile';

// Initialize OpenAI client with Groq's base URL
function getGroqClient(): OpenAI | undefined {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return undefined;

  return new OpenAI({
    apiKey,
    baseURL: 'https://api.groq.com/openai/v1',
  });
}

export async function mapColumnsUsingAi(
  records: Record<string, unknown>[],
  expectedColumns: string[]
): Promise<Record<string, unknown>[]> {
  if (!records || records.length === 0) return records;

  const actualColumns = Object.keys(records[0]);

  // Find actual columns that don't match any expected column
  const expectedColsLower = new Set(
    expectedColumns.map((exp) => exp.toLowerCase())
  );
  const unknownColumns = actualColumns.filter(
    (actual) => !expectedColsLower.has(actual.toLowerCase())
  );

  // If there are no incorrectly named columns, do not trigger AI
  if (unknownColumns.length === 0) {
    return records;
  }

  const client = getGroqClient();
  if (!client) {
    logger.warn('GROQ_API_KEY is not set. Skipping AI column mapping.');
    return records;
  }

  try {
    const prompt = `
You are an expert data mapping assistant.
I have a list of columns extracted from an uploaded CSV/Excel file.
Provided actual columns: [${actualColumns.join(', ')}]
Expected columns: [${expectedColumns.join(', ')}]

Your task is to map the 'actual columns' to the 'expected columns' based on their meaning. They might be in French, Arabic, misspelled, etc. Example: 'prix' maps to 'unitPrice'.
Respond strictly with ONLY a valid JSON object. Every key should be an actual column, and its value should be the matching expected column. If an actual column does not logically map to any expected column, do not include it in the output. If multiple actual columns map to the same expected column, choose the best one.
Return exclusively the JSON map without markdown formatting or other text.
    `;

    // Create AbortController for timeout (30 seconds)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30_000);

    try {
      const res = await client.chat.completions.create(
        {
          model: GROQ_MODEL,
          messages: [{ role: 'user', content: prompt }],
          temperature: 0.1,
          response_format: { type: 'json_object' },
        },
        { signal: controller.signal }
      );

      clearTimeout(timeoutId);

      const content = res.choices[0]?.message?.content;

      let mapping: Record<string, string> = {};
      if (typeof content === 'string') {
        const match = /{[\S\s]*}/.exec(content);
        if (match) {
          mapping = JSON.parse(match[0]) as Record<string, string>;
        }
      }

      if (Object.keys(mapping).length > 0) {
        logger.log(
          `Successfully mapped columns using AI: ${JSON.stringify(mapping)}`
        );

        // Remap records
        return records.map((record) => {
          const newRecord: Record<string, unknown> = {};
          for (const [key, value] of Object.entries(record)) {
            const mappedKey = mapping[key];
            if (mappedKey && expectedColumns.includes(mappedKey)) {
              newRecord[mappedKey] = value;
            } else {
              // Retain original if not mapped to a known expected column
              newRecord[key] = value;
            }
          }
          return newRecord;
        });
      }
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        logger.error('AI column mapping timed out after 30 seconds');
      } else {
        logger.error('Failed to map columns using AI', error);
      }
    } finally {
      clearTimeout(timeoutId);
    }

    return records;
  } catch (error) {
    logger.error('Unexpected error in AI column mapping', error);
    return records;
  }
}
