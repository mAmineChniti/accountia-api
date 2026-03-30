const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        console.log('Searching for business reservations...');
        const reservations = await db.collection('businesses').find({ _isReservation: true }).toArray();
        console.log(`Found ${reservations.length} reservations.`);
        console.log(JSON.stringify(reservations, null, 2));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

main();
