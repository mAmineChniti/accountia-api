const { MongoClient } = require('mongodb');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    const client = new MongoClient(uri);

    try {
        await client.connect();
        const database = client.db('Accountia');
        
        console.log('Connected to Accountia DB');
        
        // Peek at transactions
        const transactions = await database.collection('transactions').find({}).limit(5).toArray();
        console.log('Transactions Sample keys:', Object.keys(transactions[0] || {}));
        console.log('Transactions Sample sample:', JSON.stringify(transactions[0] || {}, null, 2));
        
        // Peek at businesses
        const businesses = await database.collection('businesses').find({}).toArray();
        console.log('Businesses Count:', businesses.length);
        console.log('Businesses Names:', businesses.map(b => b.name));

        // Let's see if there are any other collections that look like businesses
        const collections = await database.listCollections().toArray();
        console.log('Collections:', collections.map(c => c.name));

    } finally {
        await client.close();
    }
}

main().catch(console.error);
