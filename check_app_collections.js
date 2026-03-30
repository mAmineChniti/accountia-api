const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        const count = await db.collection('businessapplications').countDocuments();
        console.log(`businessapplications (no underscore) count: ${count}`);
        
        if (count > 0) {
            const apps = await db.collection('businessapplications').find({}).limit(5).toArray();
            console.log('Sample from businessapplications:', JSON.stringify(apps, null, 2));
        }

        const countWith = await db.collection('business_applications').countDocuments();
        console.log(`business_applications (with underscore) count: ${countWith}`);

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

main();
