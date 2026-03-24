#!/usr/bin/env node
/**
 * Reset business_applications collection
 */

const mongoose = require('mongoose');

async function cleanup() {
  try {
    await mongoose.connect('mongodb://localhost:27017/Accountia');
    console.log('✅ Connected to MongoDB');

    const db = mongoose.connection.db;

    // Check if collection exists
    const collections = await db.listCollections().toArray();
    const exists = collections.some((c) => c.name === 'business_applications');

    if (exists) {
      await db.dropCollection('business_applications');
      console.log('✅ Dropped business_applications collection');
    } else {
      console.log('ℹ️  Collection business_applications does not exist');
    }

    console.log(
      '✅ Cleanup complete! Collection will be recreated on next insert'
    );
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

cleanup();
