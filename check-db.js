const { MongoClient } = require('mongodb');

async function check() {
  const client = new MongoClient('mongodb://localhost:27017');
  try {
    await client.connect();
    const db = client.db('accountia'); // Check the env config for the DB name later if wrong
    const invoices = await db.collection('invoices').find({}).toArray();
    console.log(`Found ${invoices.length} invoices`);
    if(invoices.length > 0) {
      console.log('Sample invoice:', invoices[0]);
    }
  } catch (err) {
    console.error(err);
  } finally {
    await client.close();
  }
}
check();
