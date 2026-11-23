"""Private, short-lived SDK transaction; only the parent publishes its session."""
import contextlib
import json
import logging
import os
import sys
from pathlib import Path

from .proton import ProtonSessionWrapper, SDK_API_OPERATIONS
from ..utils import secure_write_file


def execute(request):
    operation = request['operation']
    endpoint, method = request.get('endpoint', ''), request.get('method', 'GET')
    if not ((operation == 'authenticate' and not endpoint and method == 'GET') or
            (operation == 'api' and (endpoint, method) in SDK_API_OPERATIONS)):
        return {'error': 'unsupported'}
    wrapper = ProtonSessionWrapper(Path(request['session_file']), request['client_version'])
    if operation == 'authenticate':
        ok = wrapper.load() and wrapper.refresh()
        if not ok and not wrapper.compatibility_rejected:
            username, password = request.get('username'), request.get('password')
            ok = bool(username and password) and wrapper.authenticate(username, password)
        if not ok:
            return {'error': 'compatibility' if wrapper.compatibility_rejected else 'authentication'}
        result = {'authenticated': True}
    else:
        if not wrapper.load():
            return {'error': 'session'}
        wrapper.save()
        result = wrapper.api_request(endpoint, method, request.get('data'))
        if not isinstance(result, dict):
            return {'error': 'response'}
    # Persistence errors must fail the transaction, rather than silently adopting
    # an older staged file after the wrapper's best-effort save.
    dump = wrapper._session.dump()
    if isinstance(dump, str):
        dump = json.loads(dump)
    if not isinstance(dump, dict):
        return {'error': 'session'}
    secure_write_file(wrapper.session_file, json.dumps(dump))
    return {'result': result}


def main():
    logging.disable(logging.CRITICAL)
    try:
        request = json.load(sys.stdin)
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            reply = execute(request)
    except Exception:
        reply = {'error': 'operation'}
    print(json.dumps(reply))


if __name__ == '__main__':
    main()
