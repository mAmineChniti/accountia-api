const mongoose = require('mongoose');

async function fixIndex() {
  try {
    console.log('?? Connecting...');
    await mongoose.connect(
      'mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0'
    );
    const db = mongoose.connection;
    try {
      await db.collection('business_applications').dropIndex('userId_1');
      console.log('? Dropped userId_1 directly!');
    } catch (e) {
      console.log('Failed to drop directly:', e.message);
    }
    await mongoose.disconnect();
  } catch (error) {
    console.error('? Error:', error.message);
    process.exit(1);
  }
}
fixIndex();
