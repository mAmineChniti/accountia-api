const mongoose = require('mongoose');

async function fixIndex() {
  try {
    console.log('🔗 Connecting to MongoDB...');
    await mongoose.connect('mongodb://localhost:27017/accountia');

    const db = mongoose.connection;

    // Create a dummy document to ensure collection exists
    console.log('📝 Creating dummy document...');
    await db.collection('business_applications').insertOne({
      businessName: 'dummy',
      description: 'dummy',
      applicantId: 'dummy',
      status: 'dummy',
      createdAt: new Date(),
    });
    console.log('✅ Dummy document created');

    const collection = db.collection('business_applications');

    // Get all indexes
    console.log('📋 Getting all indexes...');
    const indexes = await collection.getIndexes();
    console.log('📋 All indexes found:', Object.keys(indexes));

    // Drop the bad index
    if (indexes.userId_1) {
      console.log('❌ Found bad index userId_1, dropping...');
      await collection.dropIndex('userId_1');
      console.log('✅ Bad index dropped!');
    }

    // Get indexes again
    const newIndexes = await collection.getIndexes();
    console.log('📋 Indexes after fix:', Object.keys(newIndexes));

    // Delete the dummy document
    await collection.deleteOne({ businessName: 'dummy' });
    console.log('🗑️  Dummy document deleted');

    await mongoose.disconnect();
    console.log('✅ All done!');
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

fixIndex();
