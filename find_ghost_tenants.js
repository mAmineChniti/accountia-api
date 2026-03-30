const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const admin = mongoose.connection.db.admin();
        const dbs = await admin.listDatabases();
        
        console.log('Listing all databases:');
        const dbNames = dbs.databases.map(db => db.name);
        console.log(JSON.stringify(dbNames, null, 2));
        
        const mainDb = mongoose.connection.db;
        const registeredBusinesses = await mainDb.collection('businesses').find({}).toArray();
        const registeredDbNames = new Set(registeredBusinesses.map(b => b.databaseName));
        
        console.log('\nRegistered Database Names:', Array.from(registeredDbNames));
        
        // Find DBs that look like tenants but aren't registered
        // Naming pattern: anything with an underscore and a suffix or non-standard DBs
        const potentialTenants = dbNames.filter(name => {
            if (['admin', 'local', 'config', 'Accountia', 'test'].includes(name)) return false;
            return !registeredDbNames.has(name);
        });
        
        console.log('\nPotential Ghost Tenants (Unregistered DBs):');
        console.log(JSON.stringify(potentialTenants, null, 2));
        
        for (const ghost of potentialTenants) {
            console.log(`\nInspecting ghost DB: ${ghost}`);
            const ghostDb = mongoose.connection.useDb(ghost).db;
            const metadata = await ghostDb.collection('tenant_metadata').findOne({ key: 'tenant_info' });
            if (metadata) {
                console.log(`Found Metadata:`, JSON.stringify(metadata, null, 2));
            } else {
                console.log(`No tenant_metadata found in ${ghost}. Checking for invoices...`);
                const invoicesCount = await ghostDb.collection('invoices').countDocuments();
                const transCount = await ghostDb.collection('transactions').countDocuments();
                console.log(`Invoices: ${invoicesCount}, Transactions: ${transCount}`);
            }
        }

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

main().catch(console.error);
