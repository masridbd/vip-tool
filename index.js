const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

// Load Service Account from Environment Variables
const serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: 'https://vip-tool-b85d9-default-rtdb.firebaseio.com'
});

const db = admin.database();
const app = express();
app.use(cors());
app.use(express.json());

// Rate limiting (per IP, 5 requests per 10 seconds)
const rateLimit = new Map();
function isRateLimited(ip) {
  const now = Date.now();
  const requests = rateLimit.get(ip) || [];
  const recent = requests.filter(t => now - t < 10000);
  if (recent.length >= 5) return true;
  recent.push(now);
  rateLimit.set(ip, recent);
  return false;
}

// ==================== AUTH ENDPOINT ====================
app.post('/auth', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (isRateLimited(ip)) {
    return res.status(429).json({ error: 'Too many attempts' });
  }

  const { username, deviceId, uid, model, buildNumber, fingerprint } = req.body;
  
  if (!username || !deviceId || !uid) {
    return res.status(400).json({ error: 'Missing security identifiers' });
  }

  try {
    const userRef = db.ref(`users/${username.trim()}`);
    const snapshot = await userRef.once('value');
    const userData = snapshot.val();

    if (!userData) return res.status(401).json({ success: 0, error: 'Invalid key' });
    if (userData.account_status === 1) return res.json({ success: 0, banned: 1, error: 'Account banned.' });

    const now = Date.now();
    const isFirstLogin = !userData.device_id || userData.device_id === 'default';

    if (isFirstLogin) {
      const subDays = userData.subscription_days || 30;
      const expiryTime = now + subDays * 24 * 60 * 60 * 1000;

      await userRef.update({
        device_id: deviceId.trim(),
        uid: uid.trim(),
        model: model || 'Unknown',
        build_number: buildNumber || 'Unknown',
        fingerprint: fingerprint || 'Unknown',
        activation_time: now,
        expiry_time: expiryTime,
        login_count: 1,
        last_login: now,
        account_status: 0
      });

      return res.json({
        success: 1,
        message: 'Activated',
        is_first_activation: true,
        activation_time: now,
        expiry_time: expiryTime,
        subscription_days: subDays,
        remaining_days: subDays,
        nickname: userData.nickname || ''
      });
    }

    const isHardwareMatch = (userData.device_id === deviceId.trim()) && (!userData.uid || userData.uid === uid.trim());
    if (!isHardwareMatch) return res.json({ success: 0, device_mismatch: 1, error: 'Hardware mismatch.' });

    if (userData.expiry_time && now > userData.expiry_time) {
      if (userData.account_status !== 2) await userRef.update({ account_status: 2 });
      return res.json({ success: 0, expired: 1, error: 'Subscription expired.' });
    }

    await userRef.update({ login_count: (userData.login_count || 0) + 1, last_login: now });

    const remainingDays = Math.ceil((userData.expiry_time - now) / (24 * 60 * 60 * 1000));
    return res.json({
      success: 1,
      is_first_activation: false,
      activation_time: userData.activation_time,
      expiry_time: userData.expiry_time,
      remaining_days: remainingDays,
      nickname: userData.nickname || ''
    });

  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== UPDATE NICKNAME ENDPOINT ====================
app.post('/update-nickname', async (req, res) => {
  const { username, deviceId, nickname } = req.body;
  if (!username || !deviceId || !nickname) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const userRef = db.ref(`users/${username}`);
    const snapshot = await userRef.once('value');
    const userData = snapshot.val();

    if (!userData) return res.status(404).json({ error: 'User not found' });
    if (userData.device_id !== deviceId) return res.status(403).json({ error: 'Device mismatch' });

    await userRef.update({ nickname: nickname.trim() });
    return res.json({ success: 1, message: 'Nickname updated' });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== ADMIN DIALOG ENDPOINT (DYNAMIC) ====================
app.get('/admin-dialog', async (req, res) => {
  try {
    const snap = await db.ref('admin_dialog').once('value');
    const dialogs = snap.val();

    if (!dialogs) return res.json({ show: 0 });

    // Logic: Force Update takes priority over Normal Announcement
    if (dialogs.force_update && dialogs.force_update.on === 1) {
      return res.json({
        show: 1,
        type: "force_update",
        title: dialogs.force_update.title,
        message: dialogs.force_update.message,
        latest_version: dialogs.force_update.latest_version,
        whats_new: dialogs.force_update.whats_new,
        update_url: dialogs.force_update.update_url,
        buttons: dialogs.force_update.buttons
      });
    }

    if (dialogs.normal_dialog && dialogs.normal_dialog.on === 1) {
      return res.json({
        show: 1,
        type: "normal_dialog",
        title: dialogs.normal_dialog.title,
        message: dialogs.normal_dialog.message,
        url: dialogs.normal_dialog.url,
        buttons: dialogs.normal_dialog.buttons
      });
    }

    res.json({ show: 0 });
  } catch (err) {
    res.json({ show: 0 });
  }
});

// ==================== HEALTH CHECK ====================
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Gatekeeper backend running on port ${PORT}`));