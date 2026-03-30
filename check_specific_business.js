const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        const b = await db.collection('businesses').findOne({ name: /Legacy Business d73/ });
        console.log('Business Details:', JSON.stringify(b, null, 2));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

main();
