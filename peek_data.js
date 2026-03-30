const mongoose = require('mongoose');

async function run() {
  try {
    await mongoose.connect('mongodb://127.0.0.1:27017/accountia');
    const db = mongoose.connection;
    
    console.log('Connected to main DB');
    
    // Check transactions collection
    const transactions = await db.collection('transactions').find({}).limit(5).toArray();
    console.log('Transactions sample:');
    console.log(JSON.stringify(transactions, null, 2));
    
    // Check businesses collection
    const businesses = await db.collection('businesses').find({}).toArray();
    console.log('Businesses count:', businesses.length);
    console.log('Businesses sample:');
    console.log(JSON.stringify(businesses.slice(0, 5), null, 2));

    await mongoose.disconnect();
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

run();
