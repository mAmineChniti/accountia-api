async function run() {
  try {
    // 1. Log in to get token
    console.log('Logging in...');
    const loginRes = await fetch('http://localhost:4789/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'wiemgraja64@gmail.com', password: '000000000000' })
    });
    
    const loginData = await loginRes.json();
    if (!loginRes.ok) throw new Error(JSON.stringify(loginData));
    const token = loginData.accessToken;
    console.log('Got token:', token.slice(0, 20) + '...');

    // 2. Get applications to find ID
    const appsRes = await fetch('http://localhost:4789/api/business/applications', {
      headers: { Authorization: `Bearer ${token}` }
    });
    const appsData = await appsRes.json();
    if (!appsRes.ok) throw new Error(JSON.stringify(appsData));
    
    const pendingApp = appsData.applications.find(a => a.status === 'pending');
    if (!pendingApp) {
      console.log('No pending applications found to approve.');
      return;
    }
    
    console.log(`Found pending app: ${pendingApp.businessName} (ID: ${pendingApp.id})`);

    // 3. Try to approve it
    console.log('Approving application...');
    const approveRes = await fetch(`http://localhost:4789/api/business/applications/${pendingApp.id}/review`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}` 
      },
      body: JSON.stringify({
        status: 'approved',
        reviewNotes: 'Looks good'
      })
    });
    
    const approveData = await approveRes.json();
    if (!approveRes.ok) throw new Error(JSON.stringify(approveData, null, 2));
    
    console.log('Success!', approveData);

  } catch (err) {
    console.error('ERROR OCCURRED:');
    console.error(err.message);
  }
}

run();
