const mongoose = require('mongoose');

async function main() {
    const uri = "mongodb+srv://eminchniti_db_user:XyGRnmNUb8ezw4MS@cluster0.d9vi2zp.mongodb.net/Accountia?appName=Cluster0";
    
    try {
        await mongoose.connect(uri);
        const db = mongoose.connection.db;
        
        const ids = [
            "69c2c7e924c3c424ad1cf017", "69c47768bd18b33930b1d329",
            "69c47bb7939b3b65cf2e5203", "69c480d5939b3b65cf2e52ed",
            "69c4898776f80335491ee61d", "69c48a0d76f80335491ee640",
            "69c4909734d333052463d04e", "69c5c25f46f78e24a0431d28",
            "69c5c2d446f78e24a0431d73"
        ];
        
        const report = [];
        
        for (const id of ids) {
            const inv = await db.collection('invoices').findOne({ $or: [{ businessId: id }, { businessId: new mongoose.Types.ObjectId(id) }, { clientId: id }, { clientId: new mongoose.Types.ObjectId(id) }] });
            const trans = await db.collection('transactions').findOne({ $or: [{ clientId: id }, { clientId: new mongoose.Types.ObjectId(id) }] });
            
            report.push({
                id,
                businessName: inv ? (inv.businessName || inv.clientName || 'Unknown') : (trans ? (trans.clientName || 'Unknown') : 'Unknown'),
                phone: inv ? inv.phone : (trans ? trans.phone : '00000000'),
                description: inv ? inv.description : 'Imported from legacy invoices',
                applicantId: trans ? trans.userId : 'system'
            });
        }
        
        console.log('FINAL SYNC REPORT:');
        console.log(JSON.stringify(report, null, 2));

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

main();
