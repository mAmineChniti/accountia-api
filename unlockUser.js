const { MongoClient } = require('mongodb');

async function unlockUser() {
    const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/accountia';
    const client = new MongoClient(uri);

    try {
        await client.connect();
        const db = client.db();
        const users = db.collection('users');

        const result = await users.updateOne(
            { email: 'hkh304171@gmail.com' },
            { $set: { failedLoginAttempts: 0 }, $unset: { lockUntil: "" } }
        );

        console.log(`Matched ${result.matchedCount} document(s) and modified ${result.modifiedCount} document(s).`);
    } catch (err) {
        console.error('Error:', err);
    } finally {
        await client.close();
    }
}

unlockUser();
