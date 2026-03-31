const mongoose = require('mongoose');
const fs = require('fs');

async function run() {
  const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
  await mongoose.connect(uri);

  const db = mongoose.connection.db;
  const collection = db.collection('transactions');
  const doc = await collection.findOne();
  fs.writeFileSync('output2.json', JSON.stringify(doc, null, 2), 'utf8');
  await mongoose.disconnect();
}

run().catch(console.dir);
