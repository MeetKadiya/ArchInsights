// tests/sample_codebase/pkg_js/notification.js
import { formatTimestamp } from './utils';

class NotificationService {
    constructor() {
        this.queue = [];
    }

    sendAlert(message, level) {
        if (!message) {
            return false;
        }
        if (level === 'ERROR' || level === 'CRITICAL') {
            console.error(formatTimestamp(), message);
            return true;
        }
        return false;
    }
}

export default NotificationService;
