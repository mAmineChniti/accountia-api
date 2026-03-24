const mongoose = require('mongoose');

async function fixIndex() {
  try {
    console.log('🔗 Connecting to MongoDB Atlas...');
    await mongoose.connect(
      'mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0'
    );
    const db = mongoose.connection;
    const collection = db.collection('business_applications');

    console.log('📋 Getting all indexes...');
    const indexes = await collection.getIndexes();
    console.log('📋 All indexes found:', Object.keys(indexes));

    if (indexes.userId_1) {
      console.log('❌ Found bad index userId_1, dropping...');
      await collection.dropIndex('userId_1');
      console.log('✅ Bad index dropped!');
    } else {
      console.log('✅ No bad index found!');
    }

    await mongoose.disconnect();
    console.log('✅ All done!');
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}
fixIndex();
