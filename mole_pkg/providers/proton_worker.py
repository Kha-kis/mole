"""Private, short-lived SDK transaction; only the parent publishes its session."""
import contextlib
import json
import logging
import os
import sys
from pathlib import Path

from .proton import ProtonSessionWrapper, SDK_API_OPERATIONS
from ..utils import secure_write_file


def classify_error(error):
    code = getattr(error, 'code', None)
    if code in (5003, '5003'):
        return 'compatibility'
    if code in (401, 403, '401', '403'):
        return 'credentials_rejected'
    if code in (429, '429') or (type(code) is int and 500 <= code <= 599):
        return 'transient'
    if isinstance(error, (TimeoutError, ConnectionError)):
        return 'transient'
    try:
        from proton.exceptions import NewConnectionError, ConnectionTimeOutError
    except ImportError:
        pass
    else:
        if isinstance(error, (NewConnectionError, ConnectionTimeOutError)):
            return 'transient'
    if code is not None or isinstance(error, (ValueError, TypeError, KeyError)):
        return 'invalid_response'
    return 'local_state'


def execute(request):
    operation = request['operation']
    endpoint, method = request.get('endpoint', ''), request.get('method', 'GET')
    if not ((operation in ('authenticate', 'load', 'refresh') and not endpoint and method == 'GET') or
            (operation == 'api' and (endpoint, method) in SDK_API_OPERATIONS)):
        return {'error': 'unsupported'}
    wrapper = ProtonSessionWrapper(Path(request['session_file']), request['client_version'])
    if operation in ('authenticate', 'refresh'):
        ok = wrapper.load() and wrapper.refresh()
        if operation == 'authenticate' and not ok and not wrapper.compatibility_rejected:
            username, password = request.get('username'), request.get('password')
            ok = bool(username and password) and wrapper.authenticate(username, password)
        if not ok:
            return {'error': 'compatibility' if wrapper.compatibility_rejected else
                    classify_error(wrapper.last_failure)}
        result = {'authenticated': True}
    elif operation == 'load':
        if not wrapper.load() or wrapper._session is None:
            return {'error': 'local_state'}
        result = {'uid': wrapper._session.dump().get('session_data', {}).get('UID')}
    else:
        if not wrapper.load():
            return {'error': 'local_state'}
        wrapper.save()
        result = wrapper.api_request(endpoint, method, request.get('data'))
        if not isinstance(result, dict):
            return {'error': 'invalid_response'}
    # Persistence errors must fail the transaction, rather than silently adopting
    # an older staged file after the wrapper's best-effort save.
    dump = wrapper._session.dump()
    if isinstance(dump, str):
        dump = json.loads(dump)
    if not isinstance(dump, dict):
        return {'error': 'local_state'}
    secure_write_file(wrapper.session_file, json.dumps(dump))
    return {'result': result}


def main():
    logging.disable(logging.CRITICAL)
    try:
        request = json.load(sys.stdin)
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            reply = execute(request)
    except Exception as error:
        reply = {'error': classify_error(error)}
    print(json.dumps(reply))


if __name__ == '__main__':
    main()
