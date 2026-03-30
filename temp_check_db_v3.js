const mongoose = require('mongoose');
const fs = require('fs');
const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";

async function check() {
  const log = [];
  try {
    await mongoose.connect(uri);
    log.push('Connected to MongoDB Atlas');
    const db = mongoose.connection.db;
    
    const user = await db.collection('users').findOne({ email: 'wiemgraja64@gmail.com' });
    if (user) {
      log.push('User ID: ' + user._id.toString());
      const apps = await db.collection('business_applications').find({ applicantId: user._id.toString() }).toArray();
      log.push('Applications: ' + JSON.stringify(apps, null, 2));
    } else {
      log.push('User wiemgraja64@gmail.com NOT found');
    }
    
    fs.writeFileSync('db_check_results.txt', log.join('\n'));
    process.exit(0);
  } catch (err) {
    fs.writeFileSync('db_check_results.txt', 'Error: ' + err.stack);
    process.exit(1);
  }
}

check();
