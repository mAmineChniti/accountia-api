const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        const business = await db.collection('businesses').findOne({});
        console.log('Business keys:', Object.keys(business));
        console.log('Business values:', JSON.stringify(business, null, 2));

        const app = await db.collection('business_applications').findOne({});
        console.log('\nApplication keys:', Object.keys(app || {}));
        console.log('Application values:', JSON.stringify(app || {}, null, 2));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

main().catch(console.error);
