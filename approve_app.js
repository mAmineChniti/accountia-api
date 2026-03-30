const mongoose = require('mongoose');
const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";

async function approve() {
  try {
    await mongoose.connect(uri);
    const db = mongoose.connection.db;
    
    const appId = "69c2dcdedc8cb3dd83a805fb";
    const result = await db.collection('business_applications').updateOne(
      { _id: new mongoose.Types.ObjectId(appId) },
      { $set: { status: 'approved' } }
    );
    
    if (result.modifiedCount > 0) {
      console.log('Application approved successfully');
    } else {
      console.log('Application not found or already approved');
    }
    
    process.exit(0);
  } catch (err) {
    console.error('Error:', err);
    process.exit(1);
  }
}

approve();
