const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        console.log('Connected to Accountia DB via Mongoose');
        
        const db = mongoose.connection.db;
        
        // Peek at transactions
        const transactions = await db.collection('transactions').find({}).limit(5).toArray();
        if (transactions.length > 0) {
            console.log('Transactions Sample keys:', Object.keys(transactions[0]));
            // Check for potential business identifying fields
            const possibleFields = ['businessId', 'businessName', 'clientId', 'clientName', 'business', 'tenantId', 'databaseName'];
            const foundFields = possibleFields.filter(f => transactions[0].hasOwnProperty(f));
            console.log('Found identifying fields:', foundFields);
            console.log('Transactions Sample:', JSON.stringify(transactions[0], null, 2));
        } else {
            console.log('No transactions found in Accountia.transactions');
        }
        
        // Peek at businesses
        const businesses = await db.collection('businesses').find({}).toArray();
        console.log('Businesses Count:', businesses.length);
        if (businesses.length > 0) {
            console.log('Example Business:', JSON.stringify(businesses[0], null, 2));
        }

        // List all collections
        const collections = await db.listCollections().toArray();
        console.log('Collections in Accountia:', collections.map(c => c.name));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

main().catch(console.error);
