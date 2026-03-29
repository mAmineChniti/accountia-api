const mongoose = require('mongoose');

const MONGO_URI = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";

async function migrate() {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB');

    const db = mongoose.connection.db;
    
    // 0. Check application for target user
    const targetUserId = '69c5db4d1bfde0e54e6f5177';
    const app = await db.collection('business_applications').findOne({ applicantId: targetUserId });
    console.log('Application for user:', JSON.stringify(app, null, 2));

    let bu = await db.collection('business_users').findOne({ userId: targetUserId });
    console.log('Business User for user:', JSON.stringify(bu, null, 2));

    if (!bu && app && app.status === 'approved' && app.businessId) {
        console.log(`Creating missing BusinessUser link for user ${targetUserId} and business ${app.businessId}`);
        await db.collection('business_users').insertOne({
            businessId: app.businessId,
            userId: targetUserId,
            role: 'owner',
            assignedBy: targetUserId,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        });
        console.log('✅ BusinessUser link created');
    }

    // Check collections
    const collections = await db.listCollections().toArray();
    console.log('Collections in DB:', collections.map(c => c.name));

    // 1. Get business owners
    const businessUsers = await db.collection('business_users').find({ role: 'owner' }).toArray();
    console.log(`Found ${businessUsers.length} business owners`);

    for (const bu of businessUsers) {
      const userId = bu.userId;
      const businessId = bu.businessId;

      if (!userId || !businessId) continue;

      console.log(`Checking userId: ${userId} for businessId: ${businessId}`);

      // Try migrating both String and ObjectId versions to ObjectId
      const resultObj = await db.collection('invoices').updateMany(
        { 
          $or: [
            { businessOwnerId: userId },
            { businessOwnerId: new mongoose.Types.ObjectId(userId) }
          ]
        },
        { $set: { businessOwnerId: new mongoose.Types.ObjectId(businessId) } }
      );

      if (resultObj.modifiedCount > 0) {
          console.log(`✅ Migrated ${resultObj.modifiedCount} invoices for Business ${businessId}`);
      }
    }

    console.log('Migration complete');
  } catch (err) {
    console.error('Migration failed:', err);
  } finally {
    await mongoose.disconnect();
  }
}

migrate();
