// backend/middleware/emailNotifier.js
try {
  require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
} catch (e) {
  // Silent catch: dotenv might not be present or needed in Lambda environment
}
const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

const SEVERITY_EMOJI = {
  CRITICAL: '🔴',
  HIGH:     '🟠',
  MEDIUM:   '🟡',
  LOW:      '🟢'
};

const SEVERITY_COLOR = {
  CRITICAL: '#dc2626',
  HIGH:     '#ea580c',
  MEDIUM:   '#ca8a04',
  LOW:      '#16a34a'
};

exports.sendCriticalAlert = async (alert) => {
  if (alert.severity !== 'CRITICAL') return;

  const emoji = SEVERITY_EMOJI[alert.severity] || '🔴';
  const color = SEVERITY_COLOR[alert.severity] || '#dc2626';

  try {
    const fromEmail = process.env.ALERT_EMAIL_FROM;
    const toEmail = process.env.ALERT_EMAIL_TO;
    
    if (!process.env.RESEND_API_KEY || process.env.RESEND_API_KEY === 're_your_api_key_here') {
      console.warn('⚠️ [Notifier] Resend API key is not configured. Skipping email send.');
      return;
    }
    
    if (!fromEmail || !toEmail) {
      console.warn('⚠️ [Notifier] ALERT_EMAIL_FROM or ALERT_EMAIL_TO is not configured. Skipping email send.');
      return;
    }

    const { data, error } = await resend.emails.send({
      from: fromEmail,
      to:   toEmail,
      subject: `${emoji} CRITICAL ALERT — ${alert.type} | CloudSentinel`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">

          <!-- Header -->
          <div style="background: ${color}; color: white; padding: 24px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 22px;">🔴 CRITICAL SECURITY ALERT</h1>
            <p style="margin: 6px 0 0 0; opacity: 0.9;">CloudSentinel requires your immediate attention</p>
          </div>

          <!-- Alert Details -->
          <div style="background: #ffffff; padding: 24px; border: 1px solid #e5e7eb;">
            <table style="width: 100%; border-collapse: collapse;">
              <tr style="border-bottom: 1px solid #f3f4f6;">
                <td style="padding: 12px 8px; color: #6b7280; font-weight: bold; width: 35%;">Alert Type</td>
                <td style="padding: 12px 8px; color: #111827; font-weight: bold;">${(alert.type || 'UNKNOWN').replace(/_/g, ' ')}</td>
              </tr>
              <tr style="border-bottom: 1px solid #f3f4f6; background: #fef2f2;">
                <td style="padding: 12px 8px; color: #6b7280; font-weight: bold;">Severity</td>
                <td style="padding: 12px 8px; color: ${color}; font-weight: bold;">${emoji} ${alert.severity}</td>
              </tr>
              <tr style="border-bottom: 1px solid #f3f4f6;">
                <td style="padding: 12px 8px; color: #6b7280; font-weight: bold;">Resource</td>
                <td style="padding: 12px 8px; color: #111827; font-family: monospace;">${alert.resource || 'N/A'}</td>
              </tr>
              <tr style="border-bottom: 1px solid #f3f4f6; background: #f9fafb;">
                <td style="padding: 12px 8px; color: #6b7280; font-weight: bold;">Detail</td>
                <td style="padding: 12px 8px; color: #111827;">${alert.detail || 'No details provided.'}</td>
              </tr>
              <tr style="border-bottom: 1px solid #f3f4f6;">
                <td style="padding: 12px 8px; color: #6b7280; font-weight: bold;">Detected At</td>
                <td style="padding: 12px 8px; color: #111827;">${new Date(alert.timestamp || Date.now()).toUTCString()}</td>
              </tr>
              <tr style="background: #f9fafb;">
                <td style="padding: 12px 8px; color: #6b7280; font-weight: bold;">Alert ID</td>
                <td style="padding: 12px 8px; color: #9ca3af; font-size: 12px; font-family: monospace;">${alert.alertId || 'N/A'}</td>
              </tr>
            </table>
          </div>

          <!-- Action Required -->
          <div style="background: #fef2f2; border: 1px solid #fecaca; padding: 16px; margin-top: 0;">
            <p style="margin: 0; color: #dc2626; font-weight: bold;">
              ⚠️ Immediate action required — log into CloudSentinel dashboard to investigate and resolve this alert.
            </p>
          </div>

          <!-- Footer -->
          <div style="background: #1f2937; color: #9ca3af; padding: 16px; border-radius: 0 0 8px 8px; text-align: center;">
            <p style="margin: 0; font-size: 12px;">CloudSentinel — Cloud Security Monitoring System</p>
            <p style="margin: 4px 0 0 0; font-size: 11px;">This is an automated alert. Do not reply to this email.</p>
          </div>

        </div>
      `
    });

    if (error) {
      console.error('Resend error:', error);
      return;
    }

    console.log(`📧 Critical alert email sent — ID: ${data.id}`);
    return data;

  } catch (err) {
    console.error('Email notification failed:', err.message);
  }
};
