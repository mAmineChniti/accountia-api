const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    const realUserId = "69c5db4d1bfde0e54e6f5177";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        console.log(`Updating applicantId in business_applications for system applications...`);
        const appResult = await db.collection('business_applications').updateMany(
            { applicantId: 'system' },
            { $set: { applicantId: realUserId } }
        );
        console.log(`Updated ${appResult.modifiedCount} applications.`);
        
        console.log(`Updating userId in business_users for 'system' owner...`);
        const userResult = await db.collection('business_users').updateMany(
            { userId: 'system' },
            { $set: { userId: realUserId } }
        );
        console.log(`Updated ${userResult.modifiedCount} business_user links.`);

        // Find businesses that were already approved for system
        const syncedBusinesses = await db.collection('businesses').find({ status: 'approved' }).toArray();
        // Since I don't know which ones were approved for 'system' specifically, I'll filter by those that have a link to the user in business_users now.
        
        for (const b of syncedBusinesses) {
            console.log(`Checking tenant DB for business: ${b.name} (${b.databaseName})`);
            try {
                const tenantDb = mongoose.connection.useDb(b.databaseName);
                
                // Update metadata
                await tenantDb.collection('tenant_metadata').updateOne(
                    { key: 'tenant_info', ownerUserId: 'system' },
                    { $set: { ownerUserId: realUserId } }
                );
                
                // Update tenant_users
                await tenantDb.collection('tenant_users').updateOne(
                    { userId: 'system' },
                    { $set: { userId: realUserId } }
                );
                console.log(`Updated tenant DB: ${b.databaseName}`);
            } catch (e) {
                console.log(`Skipping tenant DB ${b.databaseName} (maybe not provisioned yet)`);
            }
        }

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

main();
