const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        const idsToCheck = ['69c2c7e924c3c424ad1cf017', '69c5c2d446f78e24a0431d73'];
        
        console.log('Checking business_applications (with underscore)...');
        const appsWithUnderscore = await db.collection('business_applications').find({ _id: { $in: idsToCheck.map(id => new mongoose.Types.ObjectId(id)) } }).toArray();
        console.log(`Found ${appsWithUnderscore.length} in business_applications`);
        console.log(JSON.stringify(appsWithUnderscore, null, 2));

        console.log('\nChecking businessapplications (without underscore)...');
        const appsWithoutUnderscore = await db.collection('businessapplications').find({ _id: { $in: idsToCheck.map(id => new mongoose.Types.ObjectId(id)) } }).toArray();
        console.log(`Found ${appsWithoutUnderscore.length} in businessapplications`);
        console.log(JSON.stringify(appsWithoutUnderscore, null, 2));

        console.log('\nChecking businesses for these IDs (just in case they are IDs and not ObjectIds)...');
        const businesses = await db.collection('businesses').find({ _id: { $in: idsToCheck.map(id => new mongoose.Types.ObjectId(id)) } }).toArray();
        console.log(`Found ${businesses.length} in businesses`);

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

main();
