class KeyManagement:
    def __init__(self):
        self._key_lock = threading.Lock()
        self._session_keys = {}
        self._key_pairs = {}
        self._signing_keys = {}
        
    def cleanup_session_keys(self):
        """Clean up stored session keys."""
        try:
            with self._key_lock:
                self._session_keys.clear()
        except Exception as e:
            log_error(ErrorCode.KEY_MANAGEMENT_ERROR, f"Key cleanup error: {e}") 