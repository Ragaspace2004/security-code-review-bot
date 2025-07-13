import time
from functools import wraps

class RateLimiter:
    def __init__(self, max_calls_per_hour=5000):
        self.max_calls_per_hour = max_calls_per_hour
        self.calls = []
    
    def is_allowed(self):
        now = time.time()
        # Remove calls older than 1 hour
        self.calls = [call_time for call_time in self.calls if now - call_time < 3600]
        
        if len(self.calls) >= self.max_calls_per_hour:
            print(f"⚠️ Rate limit reached: {len(self.calls)} calls in the last hour")
            return False
        
        self.calls.append(now)
        return True
    
    def get_remaining_calls(self):
        now = time.time()
        self.calls = [call_time for call_time in self.calls if now - call_time < 3600]
        return self.max_calls_per_hour - len(self.calls)

# Global rate limiter
rate_limiter = RateLimiter()

def rate_limited(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not rate_limiter.is_allowed():
            print(f"🚫 Rate limit exceeded. Remaining: {rate_limiter.get_remaining_calls()}")
            return None
        return func(*args, **kwargs)
    return wrapper
