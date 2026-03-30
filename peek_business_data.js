const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        const businesses = await db.collection('businesses').find({}).limit(1).toArray();
        console.log('Business Sample:', JSON.stringify(businesses[0], null, 2));

        const applications = await db.collection('business_applications').find({}).limit(1).toArray();
        console.log('Application Sample:', JSON.stringify(applications[0], null, 2));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

main().catch(console.error);
