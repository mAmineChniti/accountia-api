const mongoose = require('mongoose');

const BusinessAppSchema = new mongoose.Schema({}, { strict: false });
const BusinessApp = mongoose.model('business_applications', BusinessAppSchema);

async function run() {
  const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
  try {
    await mongoose.connect(uri);
    console.log('Connected to MongoDB');

    // Update all pending to approved or delete them
    const result = await BusinessApp.deleteMany({ status: 'pending' });
    console.log(`Deleted ${result.deletedCount} pending applications.`);

  } catch (err) {
    console.error(err);
  } finally {
    await mongoose.connection.close();
  }
}

run();
