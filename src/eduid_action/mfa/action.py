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
import os.path
import pkg_resources
from bson import ObjectId
from datetime import datetime
from pkg_resources import resource_filename
from jinja2 import Environment, PackageLoader
from pyramid.httpexceptions import HTTPInternalServerError
from eduid_actions.action_abc import ActionPlugin
from eduid_userdb import UserDB
from eduid_userdb.credentials import U2F

from u2flib_server.u2f import begin_authentication, complete_authentication


import logging
logger = logging.getLogger(__name__)


__author__ = 'ft'
PACKAGE_NAME = 'eduid_action.mfa'

APP_ID = 'https://dev.eduid.se/u2f-app-id.json'


env = Environment(loader=PackageLoader(PACKAGE_NAME, 'templates'))


class MFAPlugin(ActionPlugin):

    steps = 1
    translations = {}

    @classmethod
    def get_translations(cls):
        return cls.translations

    @classmethod
    def includeme(self, config):
        settings = config.registry.settings

        userdb = UserDB(settings['mongo_uri'], 'eduid_am')
        config.registry.settings['userdb'] = userdb
        config.set_request_property(lambda x: x.registry.settings['userdb'], 'userdb', reify=True)
        templatesdir = pkg_resources.resource_filename(__name__, 'templates')
        config.add_jinja2_search_path(templatesdir)

    def get_number_of_steps(self):
        return self.steps

    def get_action_body_for_step(self, step_number, action, request, errors=None):
        lang = self.get_language(request)
        _ = self.translations[lang].ugettext
        userid = action.user_id
        user = request.userdb.get_user_by_id(userid, raise_on_missing=False)
        logger.debug('Loaded User {} from db'.format(user))

        u2f_tokens = []
        for this in user.credentials.filter(U2F).to_list():
            data = {'version': this.version,
                    'keyHandle': "K26Td2lzlV-Me-y_Q2dRbcWQpL-evWA7pHLVIeCa-Gh4330UBGmbriSf4QgNs59vGjMpSrQkEAHh9UMdb97elw", #this.keyhandle,
                    #'appId': APP_ID,
                    }
            u2f_tokens.append(data)

        logger.debug('U2F tokens for user {}: {}'.format(user, u2f_tokens))

        u2fdata = begin_authentication(APP_ID, u2f_tokens)
        logger.debug('U2F challenge for user {}: {}'.format(user, u2fdata.data_for_client))

        u2fdata = json.dumps(u2fdata.data_for_client)

        u2fdata = '{"challenge": "dWxv6M8r-N8bBE5aMm1fg7bankESIv2vuEveyQntAxg", "version": "U2F_V2", "keyHandle": "K26Td2lzlV-Me-y_Q2dRbcWQpL-evWA7pHLVIeCa-Gh4330UBGmbriSf4QgNs59vGjMpSrQkEAHh9UMdb97elw", "appId": "https://dev.eduid.se/u2f-app-id.json"}'
        logger.debug('U2F data: {!r}'.format(u2fdata))

        return 'u2f.jinja2', {'u2fdata': u2fdata}

    def perform_action(self, action, request):
        _ = self.get_ugettext(request)
        userid = action.user_id
        user = request.userdb.get_user_by_id(userid, raise_on_missing=False)
        logger.debug('Loaded User {} from db'.format(user))
