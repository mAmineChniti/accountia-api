const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        console.log('Peeking at invoices collection...');
        const invoices = await db.collection('invoices').find({}).limit(5).toArray();
        console.log('Invoices count:', await db.collection('invoices').countDocuments());
        console.log('Invoices Sample:', JSON.stringify(invoices, null, 2));
        
        // Let's also check if there's any field linking to a business
        // Look for businessId, databaseName, or similar
        const allFields = new Set();
        invoices.forEach(inv => Object.keys(inv).forEach(k => allFields.add(k)));
        console.log('All fields in invoices:', Array.from(allFields));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

main().catch(console.error);
