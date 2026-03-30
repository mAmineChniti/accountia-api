const mongoose = require('mongoose');

const TransactionSchema = new mongoose.Schema({
  'Date': Date,
  'Account Type': String,
  'Transaction Amount': Number,
  'Transaction ID': String,
  'Revenue': Number,
  'Expenditure': Number,
  'originalCurrency': String,
  'convertedCurrency': String,
  'exchangeRate': Number,
  'convertedAmount': Number,
  'createdAt': Date,
  'updatedAt': Date
}, { collection: 'transactions', strict: false });

const Transaction = mongoose.model('Transaction', TransactionSchema);

async function run() {
  const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
  
  try {
    await mongoose.connect(uri);
    console.log('Connected to MongoDB');

    // Delete existing transactions
    console.log('Deleting existing transactions...');
    await Transaction.deleteMany({});

    const transactions = [];
    for (let i = 0; i < 25; i++) {
        const year = Math.random() > 0.5 ? 2025 : 2026;
        const month = Math.floor(Math.random() * 12);
        const day = Math.floor(Math.random() * 28) + 1;
        const date = new Date(year, month, day);
        
        const isIncome = Math.random() > 0.4;
        const amount = Math.floor(Math.random() * 5000) + 100;
        
        transactions.push({
            'Date': date,
            'Transaction Amount': amount,
            'Account Type': isIncome ? 'Revenue' : 'Expense',
            'Revenue': isIncome ? amount : 0,
            'Expenditure': !isIncome ? amount : 0,
            'Transaction ID': `TX-${1000 + i}`,
            'originalAmount': amount,
            'originalCurrency': 'USD',
            'convertedAmount': amount,
            'convertedCurrency': 'USD',
            'exchangeRate': 1,
            'description': `Real Transaction ${i + 1}`,
            'createdAt': new Date(),
            'updatedAt': new Date()
        });
    }

    console.log(`Inserting ${transactions.length} new transactions...`);
    await Transaction.insertMany(transactions);
    console.log('Seeding completed successfully with 25 transactions (2025-2026).');

  } catch (err) {
    console.error('Error during seeding:', err);
  } finally {
    await mongoose.connection.close();
  }
}

run();
