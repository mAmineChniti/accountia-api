const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const admin = mongoose.connection.db.admin();
        const dbs = await admin.listDatabases();
        
        console.log('List of ALL databases on server:');
        const dbNamesOnServer = dbs.databases.map(db => db.name);
        console.log(dbNamesOnServer);
        
        const mainDb = mongoose.connection.db;
        const businesses = await mainDb.collection('businesses').find({}).toArray();
        const registeredDbNames = businesses.map(b => b.databaseName).filter(Boolean);
        
        console.log('\nRegistered Database Names in Accountia.businesses:');
        console.log(registeredDbNames);
        
        const ghostDbs = dbNamesOnServer.filter(name => {
            // Filter out system and main DBs
            if (['admin', 'local', 'config', 'Accountia', 'test'].includes(name)) return false;
            // Check if it's already registered
            return !registeredDbNames.includes(name);
        });
        
        console.log('\nGhost Databases (Existence confirmed but NOT in registry):');
        console.log(ghostDbs);
        
        // Let's create a list of objects describing these ghosts
        const ghosts = [];
        for (const name of ghostDbs) {
            const ghostDb = mongoose.connection.useDb(name).db;
            const metadata = await ghostDb.collection('tenant_metadata').findOne({ key: 'tenant_info' });
            
            if (metadata) {
                ghosts.push({
                    databaseName: name,
                    businessName: metadata.businessName,
                    ownerUserId: metadata.ownerUserId,
                    source: 'metadata'
                });
            } else {
                // Peek at invoices to get a name if possible
                const sampleInvoice = await ghostDb.collection('invoices').findOne({});
                ghosts.push({
                    databaseName: name,
                    businessName: sampleInvoice ? (sampleInvoice.businessName || sampleInvoice.clientName) : 'Unnamed Ghost',
                    source: 'invoice'
                });
            }
        }
        
        console.log('\nGhost Report:');
        console.log(JSON.stringify(ghosts, null, 2));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

main().catch(console.error);
