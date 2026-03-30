const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        console.log('Checking invoices for potential business links...');
        const invoices = await db.collection('invoices').find({}).toArray();
        const businesses = await db.collection('businesses').find({}).toArray();
        const businessIds = new Set(businesses.map(b => b._id.toString()));
        const businessNames = new Set(businesses.map(b => b.name.toLowerCase()));
        
        console.log(`Analyzing ${invoices.length} invoices...`);
        
        const missingFromBusinessId = [];
        const missingFromClientId = [];
        
        for (const inv of invoices) {
            const bId = inv.businessId?.toString();
            const cId = inv.clientId?.toString();
            const bName = inv.businessName || inv.clientName; // Is it possible clientName is used as businessName?
            
            if (bId && !businessIds.has(bId)) {
                missingFromBusinessId.push({ id: bId, name: bName });
            }
            
            // What if clientId is actually a business ID that was erroneously labeled?
            if (cId && !businessIds.has(cId)) {
                // Check if this cId appears multiple times or has business-like properties
                missingFromClientId.push({ id: cId, name: bName });
            }
        }
        
        console.log('\nMissing by BusinessId:', missingFromBusinessId.length);
        console.log('\nMissing by ClientId (Potential Businesses):');
        const uniqueMissingCIds = [...new Map(missingFromClientId.map(m => [m.id, m])).values()];
        console.log(JSON.stringify(uniqueMissingCIds, null, 2));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

main().catch(console.error);
