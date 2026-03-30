const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        console.log('Fetching businesses...');
        const businesses = await db.collection('businesses').find({}).toArray();
        const businessIds = new Set(businesses.map(b => b._id.toString()));
        console.log(`Found ${businesses.length} businesses.`);

        console.log('\nFetching invoices...');
        const invoices = await db.collection('invoices').find({}).toArray();
        console.log(`Analyzing ${invoices.length} invoices...`);

        const missingByBusinessId = new Set();
        const missingByClientId = new Set();
        const clientData = {};

        for (const inv of invoices) {
            const bId = inv.businessId ? inv.businessId.toString() : null;
            const cId = inv.clientId ? inv.clientId.toString() : null;
            const name = inv.businessName || inv.clientName || 'Unknown';
            
            if (bId && !businessIds.has(bId)) {
                missingByBusinessId.add(bId);
                clientData[bId] = { name, type: 'businessId' };
            }
            
            if (cId && !businessIds.has(cId)) {
                missingByClientId.add(cId);
                clientData[cId] = { name, type: 'clientId' };
            }
        }

        console.log('\nMissing Business IDs found in invoices.businessId:');
        console.log(Array.from(missingByBusinessId));
        
        console.log('\nMissing Client IDs found in invoices.clientId (Potential businesses):');
        console.log(Array.from(missingByClientId).map(id => ({ id, name: clientData[id].name })));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

main().catch(console.error);
