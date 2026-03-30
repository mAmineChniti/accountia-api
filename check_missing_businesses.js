const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        console.log('Fetching unique businessIds from invoices...');
        const uniqueBusinessIdsFromInvoices = await db.collection('invoices').distinct('businessId');
        console.log('BusinessIds in invoices:', uniqueBusinessIdsFromInvoices);
        
        console.log('\nFetching current businesses...');
        const currentBusinesses = await db.collection('businesses').find({}).toArray();
        const currentBusinessIds = currentBusinesses.map(b => b._id.toString());
        console.log('Current Business IDs:', currentBusinessIds);
        
        const missingBusinessIds = uniqueBusinessIdsFromInvoices.filter(id => !currentBusinessIds.includes(id?.toString()));
        console.log('\nMissing Business IDs:', missingBusinessIds);
        
        if (missingBusinessIds.length > 0) {
            console.log('\nDetails for invoices with missing businesses:');
            for (const id of missingBusinessIds) {
                const sampleInvoice = await db.collection('invoices').findOne({ businessId: id });
                console.log(`\nBusinessId: ${id}`);
                console.log(`Sample Invoice:`, JSON.stringify(sampleInvoice, null, 2));
            }
        }

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

main().catch(console.error);
