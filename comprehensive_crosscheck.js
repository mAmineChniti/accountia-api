const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        // 1. Get all registered businesses and applications
        const registeredBusinesses = await db.collection('businesses').find({}).toArray();
        const regBusIds = new Set(registeredBusinesses.map(b => b._id.toString()));
        
        const appsWith = await db.collection('business_applications').find({}).toArray();
        const regAppWithIds = new Set(appsWith.map(a => a._id.toString()));
        
        const appsWithout = await db.collection('businessapplications').find({}).toArray();
        const regAppWithoutIds = new Set(appsWithout.map(a => a._id.toString()));

        console.log(`Summary: ${registeredBusinesses.length} businesses, ${appsWith.length} applications (with), ${appsWithout.length} applications (no)`);

        // 2. Scan invoices for all business/client IDs
        const invoices = await db.collection('invoices').find({}).toArray();
        const invBusinessIds = new Set(invoices.map(i => i.businessId?.toString()).filter(Boolean));
        const invClientIds = new Set(invoices.map(i => i.clientId?.toString()).filter(Boolean));
        
        // 3. Scan transactions for all client IDs
        const transactions = await db.collection('transactions').find({}).toArray();
        const transClientIds = new Set(transactions.map(t => t.clientId?.toString()).filter(Boolean));
        
        const allPotentialBusinessIds = new Set([...invBusinessIds, ...invClientIds, ...transClientIds]);
        
        console.log(`Total potential business/client IDs found in invoices/transactions: ${allPotentialBusinessIds.size}`);
        
        const missingFromRegistry = [];
        
        for (const id of allPotentialBusinessIds) {
            const isRegistered = regBusIds.has(id) || regAppWithIds.has(id) || regAppWithoutIds.has(id);
            if (!isRegistered) {
                // Find more info about this ID
                const inv = invoices.find(i => i.businessId?.toString() === id || i.clientId?.toString() === id);
                const trans = transactions.find(t => t.clientId?.toString() === id);
                
                missingFromRegistry.push({
                    id,
                    name: (inv ? (inv.businessName || inv.clientName) : (trans ? trans.clientName : 'Unknown')),
                    foundIn: (inv ? 'invoices' : '') + (trans ? ' transactions' : '')
                });
            }
        }
        
        console.log('\n--- MISSING BUSINESSES TO SYNC ---');
        if (missingFromRegistry.length === 0) {
            console.log('No missing businesses found. Everything in invoices is already in businesses or applications.');
        } else {
            console.log(JSON.stringify(missingFromRegistry, null, 2));
        }

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

main();
