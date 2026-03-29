const { MongoClient } = require('mongodb');

async function main() {
  const uri = "mongodb://localhost:27017";
  const client = new MongoClient(uri);

  try {
    await client.connect();
    const database = client.db('accountia');
    const notifications = database.collection('notifications');

    const result = await notifications.find({}).sort({createdAt: -1}).limit(5).toArray();
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await client.close();
  }
}
main().catch(console.error);
