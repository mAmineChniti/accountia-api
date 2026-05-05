import mongoose from 'mongoose';

async function checkIds() {
  const uri =
    'mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.ygmz3nl.mongodb.net/Accountia?appName=Cluster0';
  try {
    await mongoose.connect(uri);
    const db = mongoose.connection.db;
    const businesses = await db.collection('businesses').find({}).toArray();
    console.log('Businesses:');
    businesses.forEach((b) => {
      console.log(
        `- Name: ${b.name}, ID: ${b._id}, databaseName: ${b.databaseName}, Type: ${typeof b._id}`
      );
    });
    await mongoose.disconnect();
  } catch (err) {
    console.error(err);
  }
}

checkIds();
