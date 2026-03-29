const fs = require('fs');
const http = require('http');

async function testImport() {
  try {
    // 1. Get Token
    const loginData = JSON.stringify({ email: 'hkh304171@gmail.com', password: 'hiba123456789' });
    const loginReq = http.request('http://localhost:4789/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': loginData.length
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const token = JSON.parse(data).accessToken;
        // 2. Call Import API
        const importReq = http.request('http://localhost:4789/api/business/69c2d2cf3548f2b395eaf7a4/import-financials', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
          }
        }, (res2) => {
          let errData = '';
          res2.on('data', chunk => errData += chunk);
          res2.on('end', () => console.log('ERROR JSON:', errData));
        });
        importReq.on('error', e => console.log(e));
        importReq.write('{}');
        importReq.end();
      });
    });
    loginReq.on('error', e => console.log(e));
    loginReq.write(loginData);
    loginReq.end();
  } catch(e) { console.log(e); }
}
testImport();
