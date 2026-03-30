const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        const syncData = [
          { "id": "69c2c7e924c3c424ad1cf017", "businessName": "Legacy Business 017", "description": "Consultation Services", "applicantId": "system" },
          { "id": "69c47768bd18b33930b1d329", "businessName": "Legacy Business 329", "description": "Imported from transactions", "applicantId": "system" },
          { "id": "69c47bb7939b3b65cf2e5203", "businessName": "Legacy Business 203", "description": "Imported from transactions", "applicantId": "system" },
          { "id": "69c480d5939b3b65cf2e52ed", "businessName": "Legacy Business 2ed", "description": "Imported from transactions", "applicantId": "system" },
          { "id": "69c4898776f80335491ee61d", "businessName": "Legacy Business 61d", "description": "Imported from transactions", "applicantId": "system" },
          { "id": "69c48a0d76f80335491ee640", "businessName": "Legacy Business 640", "description": "Imported from transactions", "applicantId": "system" },
          { "id": "69c4909734d333052463d04e", "businessName": "Legacy Business 04e", "description": "Imported from transactions", "applicantId": "system" },
          { "id": "69c5c25f46f78e24a0431d28", "businessName": "Legacy Business d28", "description": "Imported from transactions", "applicantId": "system" },
          { "id": "69c5c2d446f78e24a0431d73", "businessName": "Legacy Business d73", "description": "Imported from transactions", "applicantId": "system" }
        ];

        console.log(`Starting sync for ${syncData.length} businesses...`);
        
        for (const item of syncData) {
            const appId = new mongoose.Types.ObjectId(item.id);
            
            // Check if application already exists (to be safe)
            const existing = await db.collection('business_applications').findOne({ _id: appId });
            if (existing) {
                console.log(`ID ${item.id} already exists in business_applications. Skipping.`);
                continue;
            }
            
            const newApp = {
                _id: appId,
                businessName: item.businessName,
                description: item.description,
                phone: "00000000",
                applicantId: item.applicantId,
                status: 'pending',
                reviewHistory: [],
                createdAt: new Date(),
                updatedAt: new Date(),
                __v: 0
            };
            
            await db.collection('business_applications').insertOne(newApp);
            console.log(`Synced: ${item.businessName} (ID: ${item.id})`);
        }

        console.log('\nSync completed successfully.');
        await mongoose.disconnect();
    } catch (err) {
        console.error('Error during sync:', err);
    }
}

main();
