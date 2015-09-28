'''
Django authentication plugins for Python WebSocket library.
Copyright 2015 Luca Capacci
Licensed under LGPL version 3

- SessionIdAuth grants access to the target only to the users authenticated in a django web app.
 
- SessionIdAuthAndHostPort determines the target based on the authenticated user. Edit get_host_port(current_user) to determine a target and a host for each user.

'''


from auth_plugins import AuthenticationError


class SessionIdAuth(object):
    def __init__(self, src=None):
        init_django()

    def authenticate(self, headers, target_host, target_port):
        try:
            cookies = headers.get('Cookie').split("; ")
            for cookie in cookies:
                if cookie.startswith("sessionid"):
                    session_token = cookie.split("=")[1]
            current_user = user_from_session_key(session_token)
            from django.contrib.auth.models import AnonymousUser
            if type(current_user) is AnonymousUser:
                raise AuthenticationError(response_code=403)
        except:
            raise AuthenticationError(response_code=403)


class SessionIdAuthAndHostPort(object):
    def __init__(self, src=None):
        init_django()

    def authenticate(self, headers, target_host, target_port):
        try:
            cookies = headers.get('Cookie').split("; ")
            for cookie in cookies:
                if cookie.startswith("sessionid"):
                    session_token = cookie.split("=")[1]
            current_user = user_from_session_key(session_token)
            from django.contrib.auth.models import AnonymousUser
            if type(current_user) is AnonymousUser:
                raise AuthenticationError(response_code=403)
            return get_host_port(current_user)
        except:
            raise AuthenticationError(response_code=403)


def get_host_port(current_user):
    host_port_dict = {'john': ('localhost', 5900),
                      'bob': ('localhost', 5901)}

    if current_user.username in host_port_dict:
        return host_port_dict[current_user.username]
    else:
        raise AuthenticationError(response_code=403)


def user_from_session_key(session_key):
    from django.conf import settings
    from django.contrib.auth import SESSION_KEY, BACKEND_SESSION_KEY, load_backend
    from django.contrib.auth.models import AnonymousUser

    session_engine = __import__(settings.SESSION_ENGINE, {}, {}, [''])
    session_wrapper = session_engine.SessionStore(session_key)
    session = session_wrapper.load()
    user_id = session.get(SESSION_KEY)
    backend_id = session.get(BACKEND_SESSION_KEY)
    if user_id and backend_id:
        auth_backend = load_backend(backend_id)
        user = auth_backend.get_user(user_id)
        if user:
            return user
    return AnonymousUser()


def init_django():
    import sys
    import os
    current_path = os.path.dirname(os.path.abspath(__file__))
    django_app_path = os.path.abspath(os.path.join(current_path, os.pardir, os.pardir))
    sys.path.insert(0, django_app_path)
    os.environ['DJANGO_SETTINGS_MODULE'] = u'{0}.settings'.format(os.path.split(django_app_path)[1])
    import django
    django.setup()
