const mongoose = require('mongoose');
const fs = require('fs');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const mainDb = mongoose.connection.db;
        
        const businesses = await mainDb.collection('businesses').find({}).toArray();
        const dbInfo = businesses.map(b => ({
            id: b._id.toString(),
            name: b.name,
            databaseName: b.databaseName
        }));
        
        fs.writeFileSync('registered_dbs.json', JSON.stringify(dbInfo, null, 2));
        console.log(`Saved ${dbInfo.length} businesses to registered_dbs.json`);

        const admin = mongoose.connection.db.admin();
        const dbs = await admin.listDatabases();
        fs.writeFileSync('all_server_dbs.json', JSON.stringify(dbs.databases.map(d => d.name), null, 2));
        console.log(`Saved ${dbs.databases.length} database names to all_server_dbs.json`);

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

main().catch(console.error);
