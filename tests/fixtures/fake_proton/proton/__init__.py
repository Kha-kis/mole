"""Offline SDK double imported only by synthetic subprocess fixtures."""
import json
import time
from pathlib import Path


class Session:
    def __init__(self, **kwargs):
        self.data = dict(kwargs, session_data={'AccessToken': 'synthetic'}, cookies={'a': 'b'})

    @classmethod
    def load(cls, data, **kwargs):
        session = cls(**kwargs)
        session.data = data.copy()
        return session

    def refresh(self):
        if self.data.get('reject'):
            error = RuntimeError('synthetic-secret-token')
            error.code = 5003
            raise error
        self.data['refreshed'] = True

    def authenticate(self, username, password):
        self.data['login'] = True
        return ['vpn']

    def dump(self):
        return self.data

    def api_request(self, endpoint, jsondata=None, method='GET'):
        marker = self.data.get('marker')
        if marker:
            Path(marker).write_text('started')
        time.sleep(self.data.get('delay', 0))
        if self.data.get('error'):
            print('synthetic-secret-token')
            raise RuntimeError('synthetic-secret-token')
        self.data['calls'] = self.data.get('calls', 0) + 1
        return {'Code': 1000, 'LogicalServers': [], 'calls': self.data['calls']}
