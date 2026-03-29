const mongoose = require('mongoose');

async function main() {
  await mongoose.connect('mongodb://localhost:27017/accountia');
  const collection = mongoose.connection.collection('notifications');
  const docs = await collection.find({}).sort({createdAt: -1}).limit(5).toArray();
  console.log(JSON.stringify(docs, null, 2));
  process.exit(0);
}
main().catch(console.error);
