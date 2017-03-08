# Copyright (C) 2017, CERN

# This software is distributed under the terms of the GNU General Public
# Licence version 3 (GPL Version 3), copied verbatim in the file "LICENSE".

# In applying this license, CERN does not waive the privileges and immunities
# granted to it by virtue of its status as Intergovernmental Organization
# or submit itself to any jurisdiction.

from flask import request
from functools import wraps
import jwt


def jwt_authorize(auth_func = None, auth_cls = None, **kwauth_args):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            token = _token_extractor()
            login = _login_decode(token)
            callback = _get_authorization_callback(auth_func, auth_cls, args)
            # Flask_restful params take preference to jwt_authorize params in case of name collision. or is it better to do the opposite?
            kwauth_args.update(kwargs)
            _check_authorization(login, callback, **kwauth_args)
            return fn(*args, **kwargs)
        return decorator
    return wrapper


def _token_extractor():
    auth_header_value = request.headers.get('Authorization', None)
    auth_header_prefix = "JWT"

    if not auth_header_value:
        return

    parts = auth_header_value.split()

    if parts[0].lower() != auth_header_prefix.lower():
        raise JWTAuthorizationError('Invalid JWT header', 'Unsupported authorization type')
    elif len(parts) == 1:
        raise JWTAuthorizationError('Invalid JWT header', 'Token missing')
    elif len(parts) > 2:
        raise JWTAuthorizationError('Invalid JWT header', 'Token contains spaces')

    if parts[0] is None:
        raise JWTAuthorizationError('Authorization required', 'Request does not contain an access token')

    return parts[1]


def _login_decode(token):
    try:
        login = jwt.decode(token, 'secret')['login']
    except jwt.InvalidTokenError as e:
        raise JWTAuthorizationError('Invalid JWT', str(e))
    except KeyError:
        raise JWTAuthorizationError('Invalid JWT', 'login parameter does not exist')

    return login


def _get_authorization_callback(auth_func, auth_cls, args):
    if auth_func != None:
        if callable(auth_func):
            raise JWTAuthorizationError('JWT Authorization', 'No valid authorization callback function provided')
        return auth_func
    else:
        method = 'auth_{0}'.format(request.method.lower())
        if auth_cls != None:
            instance = auth_cls()
        else:
            # If no method/class has been passed, maybe first argument is the instance of the same class
            try:
                instance = args[0]
            except IndexError:
                raise JWTAuthorizationError('JWT Authorization', 'No valid authorization callback function provided')
        try:
            callback = getattr(instance, method)
            return callback
        except AttributeError:
            raise JWTAuthorizationError('JWT Authorization', 'No valid authorization callback function provided')


def _check_authorization(login, auth_func, **kwargs):
    auth_list = auth_func(**kwargs)
    if login in auth_list:
        return
    raise JWTAuthorizationError('JWT Authorization', 'User is not authorized to access this endpoint')



class JWTAuthorizationError(Exception):
    def __init__(self, error, description, status_code=403, headers=None):
        self.error = error
        self.description = description
        self.status_code = status_code
        self.headers = headers


    def __repr__(self):
        return 'JWT Authorization Error: %s' % self.error


    def __str__(self):
        return '%s. %s' % (self.error, self.description)
