const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        console.log('Checking recurring_invoices...');
        const recurring = await db.collection('recurring_invoices').find({}).limit(10).toArray();
        console.log('Recurring Invoices count:', await db.collection('recurring_invoices').countDocuments());
        
        const businessIds = new Set();
        const clientNames = new Set();
        
        recurring.forEach(r => {
            if (r.businessId) businessIds.add(r.businessId.toString());
            if (r.clientId) businessIds.add(r.clientId.toString()); // Sometimes clientId might be used as businessId
            if (r.clientName) clientNames.add(r.clientName);
        });
        
        console.log('Unique IDs in recurring:', Array.from(businessIds));
        console.log('Unique Client Names in recurring:', Array.from(clientNames));

        console.log('\nChecking transactions for ANY hint of business...');
        const transactions = await db.collection('transactions').find({}).limit(20).toArray();
        const transFields = new Set();
        transactions.forEach(t => Object.keys(t).forEach(k => transFields.add(k)));
        console.log('All fields ever seen in transactions:', Array.from(transFields));

        // Search for transactions that have an extra field like 'clientId' or 'businessId'
        const transWithId = await db.collection('transactions').findOne({ 
            $or: [
                { businessId: { $exists: true } },
                { clientId: { $exists: true } },
                { business: { $exists: true } },
                { tenant: { $exists: true } }
            ] 
        });
        console.log('Transaction with any ID field:', JSON.stringify(transWithId, null, 2));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

main().catch(console.error);
