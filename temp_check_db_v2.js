const mongoose = require('mongoose');
const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";

async function check() {
  try {
    await mongoose.connect(uri);
    console.log('Connected to MongoDB Atlas');
    const db = mongoose.connection.db;
    
    // Check users
    const user = await db.collection('users').findOne({ email: 'wiemgraja64@gmail.com' });
    if (user) {
      console.log('User ID:', user._id.toString());
      
      // Check applications
      const apps = await db.collection('business_applications').find({ applicantId: user._id.toString() }).toArray();
      console.log('Applications:', JSON.stringify(apps, null, 2));
      
      // Check businesses for this user?
      const businessUsers = await db.collection('business_users').find({ userId: user._id.toString() }).toArray();
      console.log('Business Roles:', JSON.stringify(businessUsers, null, 2));
    } else {
      console.log('User wiemgraja64@gmail.com NOT found');
    }
    
    process.exit(0);
  } catch (err) {
    console.error('Error:', err);
    process.exit(1);
  }
}

check();
