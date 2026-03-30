import mongoose from 'mongoose';
import fs from 'fs';

const TransactionSchema = new mongoose.Schema({
  Date: Date,
  'Account Type': String,
  'Transaction Amount': Number,
  Revenue: Number,
  Expenditure: Number,
  'Transaction Outcome': Number,
}, { collection: 'transactions' });

const Transaction = mongoose.model('Transaction', TransactionSchema);

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    await mongoose.connect(uri);

    const log: any = {};

    try {
        log.zeroAmount = await Transaction.find({ "Transaction Amount": 0 }).limit(5).lean();
        log.futureDated = await Transaction.find({ "Date": { $gt: new Date() } }).limit(5).lean();

        const start = new Date('2027-09-27T00:00:00Z');
        const end = new Date('2027-09-27T23:59:59Z');
        log.exactMatch = await Transaction.find({ "Date": { $gte: start, $lte: end } }).lean();

        fs.writeFileSync('db_search_results.json', JSON.stringify(log, null, 2));
        console.log('Results written to db_search_results.json');

    } finally {
        await mongoose.connection.close();
    }
}

main().catch(console.error);
