"""Mobile IP command and scheduling helpers.

This module contains utility classes for command scheduling and execution:
- _BindingChecker: Monitors binding expiration in background threads
- _Timer: Executes delayed functions with error handling
"""

import threading
import time
import logging


class BindingChecker(threading.Thread):
    """Binding checker class.
    
    Monitors binding table entries and calls a handler when they expire.
    """

    _SLEEP_TIME = 1

    def __init__(self, lock, binding_table, lifetime_expired_handler):
        """Initialize the binding checker.
        
        Parameters:
        lock                   -- Lock for binding table synchronization
        binding_table          -- Dictionary of active bindings to monitor
        lifetime_expired_handler -- Function to call when bindings expire
        """
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.binding_table = binding_table
        self.lifetime_expired_handler = lifetime_expired_handler
        self.active = False
        self.lock = lock

    def start(self):
        """Start the binding checker thread."""
        self.active = True
        threading.Thread.start(self)

    def stop(self):
        """Stop the binding checker thread if running."""
        if self.is_alive():
            self.active = False

    def run(self):
        """Main binding checker loop.
        
        Periodically checks all bindings for expiration and calls
        the handler for expired entries.
        """
        while self.active:
            keys_to_handle = []
            self.lock.acquire()
            t = time.time()
            for key, packet in self.binding_table.items():
                if 0 <= packet.expiration_date <= t:
                    keys_to_handle.append(key)
            self.lock.release()
            for key in keys_to_handle:
                self.lifetime_expired_handler(packet)
            time.sleep(self._SLEEP_TIME)


class Timer(threading.Thread):
    """Call a function after a specified number of seconds.
    
    Provides delayed execution with error handling capabilities.
    """

    def __init__(self, interval, function, exception_handler=None,
                 args=None, kwargs=None):
        """Initialize the timer.
        
        Parameters:
        interval          -- Time in seconds to wait before executing the function
        function          -- Function to execute
        exception_handler -- Function to call if the main function raises an exception
        args              -- Positional arguments for the function
        kwargs            -- Keyword arguments for the function
        """
        threading.Thread.__init__(self)
        self.interval = interval
        self.function = function
        self.exception_handler = exception_handler
        self.args = args if args is not None else []
        self.kwargs = kwargs if kwargs is not None else {}
        self.finished = threading.Event()

    def cancel(self):
        """Stop the timer if it hasn't finished yet."""
        self.finished.set()

    def run(self):
        """Wait for the specified interval and then execute the function."""
        self.finished.wait(self.interval)

        if not self.finished.is_set():
            try:
                self.function(*self.args, **self.kwargs)
            except Exception as e:
                logging.error("Exception has been thrown in the Timer thread.")
                logging.exception(e)
                if self.exception_handler is not None:
                    self.exception_handler(e)

        self.finished.set()
