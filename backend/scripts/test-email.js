require('dotenv').config({ path: './.env' });
const { sendCriticalAlert } = require('../middleware/emailNotifier');

const testAlert = {
  alertId:   'test-123',
  timestamp: new Date().toISOString(),
  type:      'IAM_MISUSE',
  severity:  'CRITICAL',
  resource:  'suspicious-user',
  detail:    'AdministratorAccess policy attached from unknown IP 185.220.101.45',
  status:    'OPEN'
};

sendCriticalAlert(testAlert)
  .then(() => console.log('✅ Test email sent — check your inbox'))
  .catch(console.error);
