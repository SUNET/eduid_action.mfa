#
# Copyright (c) 2017 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
import json
import pkg_resources
from jinja2 import Environment, PackageLoader
from eduid_actions.action_abc import ActionPlugin
from eduid_userdb import UserDB
from eduid_userdb.credentials import U2F

from u2flib_server.u2f import begin_authentication, complete_authentication

from pyramid.exceptions import ConfigurationError


import logging
logger = logging.getLogger(__name__)


__author__ = 'ft'
PACKAGE_NAME = 'eduid_action.mfa'

env = Environment(loader=PackageLoader(PACKAGE_NAME, 'templates'))


class MFAPlugin(ActionPlugin):

    steps = 1
    translations = {}

    @classmethod
    def get_translations(cls):
        return cls.translations

    @classmethod
    def includeme(cls, config):
        settings = config.registry.settings

        for item in ('u2f_app_id',
                     'u2f_valid_facets'):
            if settings.get(item) is None:
                logger.error('The "{}" configuration option is required'.format(item))

        settings.setdefault('mfa_testing', False)

        userdb = UserDB(settings['mongo_uri'], 'eduid_am')
        config.registry.settings['userdb'] = userdb
        config.set_request_property(lambda x: x.registry.settings['userdb'], 'userdb', reify=True)
        templatesdir = pkg_resources.resource_filename(__name__, 'templates')
        config.add_jinja2_search_path(templatesdir)

    def get_number_of_steps(self):
        return self.steps

    def get_action_body_for_step(self, step_number, action, request, errors=None):
        settings = request.registry.settings
        lang = self.get_language(request)
        params = {'_': self.translations[lang].ugettext}
        userid = action.user_id
        user = request.userdb.get_user_by_id(userid, raise_on_missing=False)
        logger.debug('Loaded User {} from db'.format(user))
        if not user:
            raise self.ActionError('User not found')

        u2f_tokens = []
        for this in user.credentials.filter(U2F).to_list():
            data = {'version': this.version,
                    'keyHandle': this.keyhandle,
                    'publicKey': this.public_key,
                    #'appId': APP_ID,
                    }
            u2f_tokens.append(data)

        logger.debug('U2F tokens for user {}: {}'.format(user, u2f_tokens))

        challenge = begin_authentication(settings['u2f_app_id'], u2f_tokens)

        # Save the challenge to be used when validating the signature in perform_action() below
        request.session[PACKAGE_NAME + '.u2f.challenge'] = challenge.json

        logger.debug('U2F challenge for user {}: {}'.format(user, challenge.data_for_client))

        # XXX add CSRF token to this form
        params['u2fdata'] = json.dumps(challenge.data_for_client)
        if settings.get('mfa_testing', 'false') == 'true':
            logger.info('MFA test mode is enabled')
            params['testing'] = True
        else:
            params['testing'] = False
        return 'u2f.jinja2', params

    def perform_action(self, action, request):
        settings = request.registry.settings
        _ = self.get_ugettext(request)
        if settings.get('mfa_testing', 'false') == 'true':
            logger.debug('TEST MODE IS ON, FAKING AUTHENTICATION')
            action.result = {'success': True,
                             'testing': True,
                             }
            return action
        token_response = request.POST.get('tokenResponse', '')
        if not token_response:
            msg = _(u'No response from token, please retry login')
            raise self.ActionError(msg)
        logger.debug('U2F token response: {}'.format(token_response))

        logger.debug("Challenge: {!r}".format(request.session.get(PACKAGE_NAME + '.u2f.challenge')))
        challenge = request.session.get(PACKAGE_NAME + '.u2f.challenge')
        device, counter, touch = complete_authentication(challenge, token_response, settings['u2f_valid_facets'])
        logger.debug('U2F authentication data: {}'.format({
            'keyHandle': device['keyHandle'],
            'touch': touch,
            'counter': counter,
        }))

        userid = action.user_id
        user = request.userdb.get_user_by_id(userid, raise_on_missing=False)
        logger.debug('Loaded User {} from db (in perform_action)'.format(user))

        for this in user.credentials.filter(U2F).to_list():
            if this.keyhandle == device['keyHandle']:
                logger.info('User {} logged in using U2F token {} (touch: {}, counter {})'.format(
                    user, this, touch, counter))
                action.result = {'success': True,
                                 'touch': touch,
                                 'counter': counter,
                                 'key_handle': this.keyhandle,
                                 }
                return action

        msg = _(u'Unknown token used, please retry login')
        raise self.ActionError(msg)
