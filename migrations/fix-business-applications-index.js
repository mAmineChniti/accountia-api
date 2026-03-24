// Migration: Fix business_applications collection
// Run this in MongoDB to fix the duplicate key error

// 1. Drop the conflicting index
db.business_applications.dropIndex('userId_1');

// 2. Create the correct index on applicantId (non-unique, allows multiple reviewing states)
db.business_applications.createIndex({ applicantId: 1, status: 1 });

console.log(
  'Migration complete: userId_1 index removed, applicantId index created'
);
