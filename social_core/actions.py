from six.moves.urllib_parse import quote

from .utils import sanitize_redirect, user_is_authenticated, \
    user_is_active, partial_pipeline_data, setting_url
from rest_framework_jwt.serializers import jwt_payload_handler, jwt_encode_handler
from rest_framework import status
from django.http import HttpResponse
import datetime
import urllib


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

    res = {'st': 1}
    if user:
        if user.social_user:
            if user.social_user.provider == 'vk-oauth2':
                res.update({'hp': bool(user.social_user.extra_data['has_photo']) or user.main_photo,
                            'pu': user.social_user.extra_data['photo_max_orig']})
            elif user.social_user.provider == 'facebook':
                pic_is_silhouette = backend.strategy.session_get('pic_is_silhouette')
                if pic_is_silhouette is not None:
                    res['hp'] = not pic_is_silhouette or user.main_photo

                pic_url = backend.strategy.session_get('pic_url')
                if pic_url is not None:
                    res['pu'] = pic_url
        sex = user.sex if user.sex else ''
        bdate = ''
        if user.birthday:
            today = datetime.date.today()
            if (today.year - user.birthday.year - ((today.month, today.day) < (user.birthday.month, user.birthday.day))) > 17:
                bdate = user.birthday.strftime('%d.%m.%Y')
        res.update({'b': bdate, 's': str(sex)})

    app_url_scheme_prefix = 'pickerUrl://?'
    response = HttpResponse("", status=302)
    if is_authenticated:
        if not user:
            res.update({'st': -1, 'm': 'User error'})
        else:
            payload = jwt_payload_handler(user)
    elif user:
        payload = jwt_payload_handler(user)
        if user_is_active(user):
            # catch is_new/social_user in case login() resets the instance
            is_new = getattr(user, 'is_new', False)
            social_user = user.social_user
            # login(backend, user, social_user)

            # store last login backend name in session
            backend.strategy.session_set('social_auth_last_login_backend', social_user.provider)

            if is_new:
                res.update({'t': jwt_encode_handler(payload), 'n': 1})
            else:
                res.update({'t': jwt_encode_handler(payload), 'n': -1})
        else:
            res.update({'st': -1, 'm': 'The user account is disabled'})
        response['Location'] = app_url_scheme_prefix + urllib.parse.urlencode(res)
        return response
    else:
        res.update({'st': -1, 'm': 'Not found'})

    try:
        res.update({'t': jwt_encode_handler(payload)})
        response['Location'] = app_url_scheme_prefix + urllib.parse.urlencode(res)
    except TypeError:
        response['Location'] = app_url_scheme_prefix + urllib.parse.urlencode(res)
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
