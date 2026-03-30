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

    // 2. Create recurring invoice
    console.log('Creating recurring invoice...');
    const body = {
      clientId: "client_abcd123",
      clientName: "Test Automation Client",
      clientEmail: "testclient@example.com",
      items: [
        {
          description: "Monthly SEO Services",
          quantity: 1,
          price: 500
        }
      ],
      totalAmount: 500,
      frequency: "monthly",
      templateId: "template_standard",
      startDate: new Date().toISOString(),
      autoSend: true,
      generateFirstImmediately: true
    };

    const createRes = await fetch('http://localhost:4789/api/recurring-invoices', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}` 
      },
      body: JSON.stringify(body)
    });
    
    const createData = await createRes.json();
    if (!createRes.ok) throw new Error(JSON.stringify(createData, null, 2));
    
    console.log('Successfully created recurring invoice:', createData._id);

    // 3. Get stats
    console.log('Fetching stats...');
    const statsRes = await fetch('http://localhost:4789/api/recurring-invoices/stats', {
      headers: { Authorization: `Bearer ${token}` }
    });
    const statsData = await statsRes.json();
    console.log('Recurring Stats:', statsData);

  } catch (err) {
    console.error('ERROR OCCURRED:');
    console.error(err.message);
  }
}

run();
