const { MongoClient } = require('mongodb');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    const client = new MongoClient(uri);

    try {
        await client.connect();
        const database = client.db('Accountia');
        const collection = database.collection('transactions');

        console.log('Searching for transactions with amount 0 or future dates...');
        
        const zeroAmount = await collection.find({ "Transaction Amount": 0 }).limit(5).toArray();
        console.log('Zero Amount Transactions:', JSON.stringify(zeroAmount, null, 2));

        const futureDated = await collection.find({ "Date": { $gt: new Date() } }).limit(5).toArray();
        console.log('Future Dated Transactions:', JSON.stringify(futureDated, null, 2));

        const exactMatch = await collection.find({ "Date": { $regex: /2027-09-27/ } }).toArray();
        console.log('Exact Match (2027-09-27):', JSON.stringify(exactMatch, null, 2));

    } finally {
        await client.close();
    }
}

main().catch(console.error);
