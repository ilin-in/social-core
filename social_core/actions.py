from six.moves.urllib_parse import quote

from .utils import sanitize_redirect, user_is_authenticated, \
                   user_is_active, partial_pipeline_data, setting_url
from rest_framework_jwt.serializers import jwt_payload_handler, jwt_encode_handler
from rest_framework import status
from django.http import HttpResponse
import datetime


def do_auth(backend, redirect_name='next'):
    # Save any defined next value into session
    data = backend.strategy.request_data(merge=False)

    # Save extra data into session.
    for field_name in backend.setting('FIELDS_STORED_IN_SESSION', []):
        if field_name in data:
            backend.strategy.session_set(field_name, data[field_name])

    if redirect_name in data:
        # Check and sanitize a user-defined GET/POST next field value
        redirect_uri = data[redirect_name]
        if backend.setting('SANITIZE_REDIRECTS', True):
            allowed_hosts = backend.setting('ALLOWED_REDIRECT_HOSTS', []) + \
                            [backend.strategy.request_host()]
            redirect_uri = sanitize_redirect(allowed_hosts, redirect_uri)
        backend.strategy.session_set(
            redirect_name,
            redirect_uri or backend.setting('LOGIN_REDIRECT_URL')
        )
    return backend.start()


def do_complete(backend, login, user=None, redirect_name='next',
                *args, **kwargs):
    data = backend.strategy.request_data()

    is_authenticated = user_is_authenticated(user)
    user = is_authenticated and user or None

    partial = partial_pipeline_data(backend, user, *args, **kwargs)
    if partial:
        user = backend.continue_pipeline(partial)
    else:
        user = backend.complete(user=user, *args, **kwargs)

    # pop redirect value before the session is trashed on login(), but after
    # the pipeline so that the pipeline can change the redirect if needed
    redirect_value = backend.strategy.session_get(redirect_name, '') or \
                     data.get(redirect_name, '')
    payload = "None"
    # check if the output value is something else than a user and just
    # return it to the client
    user_model = backend.strategy.storage.user.user_model()
    if user and not isinstance(user, user_model):
        return user

    APP_URL_SCHEME_PREFIX = 'pickerUrl://?'
    response = HttpResponse("", status=302)
    if is_authenticated:
        if not user:
            information = 'st=-1&m=User%20error'
        else:
            payload = jwt_payload_handler(user)
            sex = user.sex if user.sex else ''
            bdate = ''
            if user.birthday:
                today = date.today()
                if (today.year - user.birthday.year - ((today.month, today.day) < (user.birthday.month, user.birthday.day))) > 17:
                    bdate = user.birthday.strftime('%d.%m.%Y')
            req_info = '&b=' + bdate + '&s=' + str(sex)
            information = 'st=1' + req_info
    elif user:
        payload = jwt_payload_handler(user)
        if user_is_active(user):
            # catch is_new/social_user in case login() resets the instance
            is_new = getattr(user, 'is_new', False)
            social_user = user.social_user
            # login(backend, user, social_user)


            sex = user.sex if user.sex else ''
            bdate = ''
            if user.birthday:
                today = date.today()
                if (today.year - user.birthday.year - ((today.month, today.day) < (user.birthday.month, user.birthday.day))) > 17:
                    bdate = user.birthday.strftime('%d.%m.%Y')
            req_info = '&b=' + bdate + '&s=' + str(sex)

            # store last login backend name in session
            backend.strategy.session_set('social_auth_last_login_backend', social_user.provider)

            if is_new:
                response['Location'] = APP_URL_SCHEME_PREFIX + 't=' + jwt_encode_handler(payload) + '&n=1&st=1' + req_info
                return response
            else:
                response['Location'] = APP_URL_SCHEME_PREFIX + 't=' + jwt_encode_handler(payload) + '&n=-1&st=1' + req_info
                return response
        else:
            response['Location'] = APP_URL_SCHEME_PREFIX + 'st=-1&m=The%20user%20account%20is%20disabled'
            return response
    else:
        information = 'st=-1&m=Not%20found'

    try:
        response['Location'] = APP_URL_SCHEME_PREFIX + information + '&t=' + jwt_encode_handler(payload)
    except TypeError:
        response['Location'] = APP_URL_SCHEME_PREFIX + information
    return response


def do_disconnect(backend, user, association_id=None, redirect_name='next',
                  *args, **kwargs):
    partial = partial_pipeline_data(backend, user, *args, **kwargs)
    if partial:
        if association_id and not partial.kwargs.get('association_id'):
            partial.extend_kwargs({
                'association_id': association_id
            })
        response = backend.disconnect(*partial.args, **partial.kwargs)
    else:
        response = backend.disconnect(user=user, association_id=association_id,
                                      *args, **kwargs)

    if isinstance(response, dict):
        url = backend.strategy.absolute_uri(
            backend.strategy.request_data().get(redirect_name, '') or
            backend.setting('DISCONNECT_REDIRECT_URL') or
            backend.setting('LOGIN_REDIRECT_URL')
        )
        if backend.setting('SANITIZE_REDIRECTS', True):
            allowed_hosts = backend.setting('ALLOWED_REDIRECT_HOSTS', []) + \
                            [backend.strategy.request_host()]
            url = sanitize_redirect(allowed_hosts, url) or \
                backend.setting('DISCONNECT_REDIRECT_URL') or \
                backend.setting('LOGIN_REDIRECT_URL')
        response = backend.strategy.redirect(url)
    return response
