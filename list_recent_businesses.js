const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        console.log('Listing all businesses in Accountia.businesses...');
        const businesses = await db.collection('businesses').find({}).sort({ createdAt: -1 }).toArray();
        console.log(`Total businesses: ${businesses.length}`);
        
        // Print the last 5
        console.log('Recently added/updated businesses:');
        console.log(JSON.stringify(businesses.slice(0, 5), null, 2));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

main();
