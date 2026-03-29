const mongoose = require('mongoose');

const MONGO_URI = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";

async function check() {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB');

    const db = mongoose.connection.db;
    
    const email = 'hibakhadraoui011@gmail.com';
    const invs = await db.collection('invoices').find({ clientEmail: email }).toArray();
    
    console.log(`Found ${invs.length} invoices for ${email}`);
    
    invs.forEach(inv => {
      console.log(`- Invoice ${inv.invoiceNumber}: Status=${inv.status}, deletedAt=${inv.deletedAt}`);
    });

    if (invs.length === 0) {
        console.log('Checking for ANY invoices to see the email format...');
        const anyInv = await db.collection('invoices').findOne({});
        console.log('Sample invoice:', JSON.stringify(anyInv, null, 2));
    }

  } catch (err) {
    console.error('Check failed:', err);
  } finally {
    await mongoose.disconnect();
  }
}

check();
