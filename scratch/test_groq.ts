import OpenAI from 'openai';
import * as dotenv from 'dotenv';
import * as path from 'path';

dotenv.config({ path: path.join(__dirname, '..', '.env') });
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

async function testGroq() {
  const apiKey = process.env.GROQ_API_KEY;
  console.log(
    'Using API Key:',
    apiKey ? apiKey.substring(0, 10) + '...' : 'MISSING'
  );

  const client = new OpenAI({
    apiKey: apiKey,
    baseURL: 'https://api.groq.com/openai/v1',
  });

  try {
    console.log('Starting stream...');
    const stream = await client.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [{ role: 'user', content: 'Hello, are you there?' }],
      stream: true,
    });

    for await (const chunk of stream) {
      process.stdout.write(chunk.choices[0]?.delta?.content || '');
    }
    console.log('\nStream finished successfully.');
  } catch (err: any) {
    console.error('\nError during Groq test:');
    console.error(err);
    if (err.response) {
      console.error('Response status:', err.response.status);
      console.error('Response body:', await err.response.text());
    }
  }
}

testGroq();
