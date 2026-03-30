const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        // Find a legacy business application
        const app = await db.collection('business_applications').findOne({ applicantId: 'system', status: 'pending' });
        if (!app) {
            console.log('No pending legacy applications found.');
            return;
        }
        
        console.log(`Testing approval for: ${app.businessName} (ID: ${app._id})`);
        
        // We can't easily call the service method without NestJS context, 
        // but we can try to simulate the provisioning part which is the most likely failure point.
        
        const databaseName = `test_sync_${Date.now().toString(36)}`;
        console.log(`Simulating provisioning for DB: ${databaseName}`);
        
        try {
            const tenantDb = mongoose.connection.useDb(databaseName);
            await tenantDb.createCollection('tenant_metadata');
            console.log('Successfully created tenant_metadata collection.');
            await tenantDb.dropDatabase();
            console.log('Cleanup: Dropped test DB.');
        } catch (e) {
            console.error('PROVISIONING FAILED:', e);
        }

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

main();
