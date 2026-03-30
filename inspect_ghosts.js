const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const admin = mongoose.connection.db.admin();
        const dbs = (await admin.listDatabases()).databases.map(d => d.name);
        
        const mainDb = mongoose.connection.db;
        const registeredDbNames = (await mainDb.collection('businesses').find({}).toArray()).map(b => b.databaseName);
        
        const systemDbs = ['admin', 'local', 'config', 'Accountia', 'test'];
        const ghostDbs = dbs.filter(name => !systemDbs.includes(name) && !registeredDbNames.includes(name));
        
        console.log(`Found ${ghostDbs.length} ghost databases.`);
        
        for (const dbName of ghostDbs) {
            console.log(`\n--- DB: ${dbName} ---`);
            const db = mongoose.connection.useDb(dbName).db;
            
            // Check metadata
            const metadata = await db.collection('tenant_metadata').findOne({ key: 'tenant_info' });
            if (metadata) {
                console.log(`Metadata Found: Name="${metadata.businessName}", Owner="${metadata.ownerUserId}"`);
            } else {
                console.log('No metadata. Checking users and invoices...');
                const user = await db.collection('tenant_users').findOne({ role: 'OWNER' });
                const invoice = await db.collection('invoices').findOne({});
                console.log(`User: ${user ? user.userId : 'None'}, Invoice: ${invoice ? (invoice.businessName || invoice.clientName) : 'None'}`);
            }
        }

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

main();
