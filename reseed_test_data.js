/**
 * Script to re-seed financial data for test clients directly in MongoDB.
 * Ensures the new "varied" logic is applied to Hiba and Ella.
 */
const { MongoClient, ObjectId } = require('mongodb');

const MONGO_URI = 'mongodb://localhost:27017/accountia-db';

async function run() {
  const client = await MongoClient.connect(MONGO_URI);
  const db = client.db();
  
  const businessId = '69c2d2cf3548f2b395eaf7a4'; // Hiba Owner's first business
  const testClients = [
    { id: '69c43e743548f2b395eb3fec', name: 'Hiba Client' }, // hibakhadraoui011@gmail.com
    { id: '69c445ca3548f2b395eb4884', name: 'Ella Client' }  // ellallkj90@gmail.com
  ];

  for (const tClient of testClients) {
    console.log(`\n--- Reseeding ${tClient.name} (${tClient.id}) ---`);
    
    // 1. Delete old data
    await db.collection('transactions').deleteMany({ clientId: tClient.id });
    await db.collection('invoices').deleteMany({ clientId: tClient.id });

    // 2. Varied logic (Same as in business.service.ts)
    const seed = parseInt(tClient.id.slice(-1), 16) || 0;
    const baseAmount = 500 + (seed * 100); 
    const volatility = 0.2 + (seed % 5) * 0.1;

    const transactions = [];
    const now = new Date();
    for (let i = 0; i < 30; i++) {
        const date = new Date();
        date.setDate(now.getDate() - i);
        const isExpense = i % 3 === 0;
        const amount = baseAmount + Math.random() * baseAmount * volatility;
        
        transactions.push({
            transactionId: `TXN-${tClient.id.substring(0, 5)}-${i}-${Date.now()}`,
            date,
            accountType: isExpense ? 'Accounts Payable' : 'Accounts Receivable',
            amount: parseFloat(amount.toFixed(2)),
            cashFlow: isExpense ? -parseFloat(amount.toFixed(2)) : parseFloat(amount.toFixed(2)),
            netIncome: isExpense ? -parseFloat(amount.toFixed(2)) : parseFloat((amount * 0.4).toFixed(2)),
            revenue: isExpense ? 0 : parseFloat(amount.toFixed(2)),
            expenditure: isExpense ? parseFloat(amount.toFixed(2)) : 0,
            profitMargin: isExpense ? 0 : 40,
            operatingExpenses: isExpense ? parseFloat((amount * 0.1).toFixed(2)) : 0,
            grossProfit: isExpense ? 0 : parseFloat((amount * 0.9).toFixed(2)),
            accuracyScore: 98,
            hasMissingData: false,
            businessId,
            clientId: tClient.id,
            __v: 0
        });
    }

    await db.collection('transactions').insertMany(transactions);

    const desc1 = seed % 2 === 0 ? 'Consulting Services' : 'Software Subscription';
    const desc2 = seed % 3 === 0 ? 'Maintenance Fee' : 'Hardware Supply';

    const invoices = [
        {
          invoiceNumber: `INV-${tClient.id.substring(0, 5)}-1`,
          description: desc1,
          amount: parseFloat((baseAmount * 2).toFixed(2)),
          currency: 'EUR',
          status: 'PAID',
          dueDate: new Date(),
          paidAt: new Date(),
          businessId,
          clientId: tClient.id,
          __v: 0
        },
        {
          invoiceNumber: `INV-${tClient.id.substring(0, 5)}-2`,
          description: desc2,
          amount: parseFloat((baseAmount * 0.5).toFixed(2)),
          currency: 'EUR',
          status: 'PENDING',
          dueDate: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000),
          businessId,
          clientId: tClient.id,
          __v: 0
        }
    ];

    await db.collection('invoices').insertMany(invoices);
    console.log(`Successfully reseeded ${tClient.name}`);
  }

  await client.close();
}

run().catch(console.dir);
