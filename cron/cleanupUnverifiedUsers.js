const cron = require('node-cron');
const User = require('../models/User');

// ⏰ Runs daily at midnight (00:00)
cron.schedule('0 0 * * *', async () => {
  try {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago

    const result = await User.deleteMany({
      isVerified: false,
      createdAt: { $lt: cutoff }
    });

    console.log(`[CRON] Deleted ${result.deletedCount} unverified users older than 24 hours`);
  } catch (err) {
    console.error('[CRON] Error while cleaning unverified users:', err.message);
  }
});
