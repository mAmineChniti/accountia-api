#!/usr/bin/env node
/**
 * MongoDB Data Cleanup Script
 * Fixes the business_applications collection by removing conflicting indices
 * Run with: node cleanup-db.js
 */

const mongoose = require('mongoose');

async function cleanupDatabase() {
  try {
    // Connect to MongoDB
    await mongoose.connect('mongodb://localhost:27017/Accountia');

    console.log('✅ Connected to MongoDB');

    const db = mongoose.connection.db;

    // Check existing indices
    console.log('\n📊 Current indices on business_applications:');
    const indices = await db
      .collection('business_applications')
      .listIndexes()
      .toArray();
    console.log(JSON.stringify(indices, null, 2));

    // Drop the conflicting userId_1 index if it exists
    try {
      await db.collection('business_applications').dropIndex('userId_1');
      console.log('✅ Dropped conflicting userId_1 index');
    } catch (error) {
      console.log('ℹ️  userId_1 index does not exist (already removed)');
    }

    // Create the correct index on applicantId
    try {
      await db
        .collection('business_applications')
        .createIndex({ applicantId: 1 }, { sparse: true, unique: false });
      console.log('✅ Created correct applicantId index');
    } catch (error) {
      console.log('ℹ️  applicantId index already exists');
    }

    // List final indices
    console.log('\n📊 Final indices on business_applications:');
    const finalIndices = await db
      .collection('business_applications')
      .listIndexes()
      .toArray();
    console.log(JSON.stringify(finalIndices, null, 2));

    console.log('\n✅ Cleanup complete!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during cleanup:', error);
    process.exit(1);
  }
}

cleanupDatabase();
