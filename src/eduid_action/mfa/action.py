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
import os.path
from bson import ObjectId
from datetime import datetime
from pkg_resources import resource_filename
from jinja2 import Environment, PackageLoader
from pyramid.httpexceptions import HTTPInternalServerError
from eduid_actions.action_abc import ActionPlugin
from eduid_userdb import UserDB

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
    def includeme(self, config):
        settings = config.registry.settings

        userdb = UserDB(settings['mongo_uri'], 'eduid_am')
        config.registry.settings['userdb'] = userdb
        config.set_request_property(lambda x: x.registry.settings['userdb'], 'userdb', reify=True)

    def get_number_of_steps(self):
        return self.steps

    def get_action_body_for_step(self, step_number, action, request, errors=None):
        lang = self.get_language(request)
        _ = self.translations[lang].ugettext
        template = env.get_template('main.jinja2')
        return template.render(mfa_text='This is MFA text', _=_)

    def perform_action(self, action, request):
        _ = self.get_ugettext(request)
        if not request.POST.get('accept', ''):
            msg = _(u'You must press the button on your Security Key to continue logging in')
            raise self.ActionError(msg)
        userid = action.user_id
        user = request.userdb.get_user_by_id(userid, raise_on_missing=False)
        logger.debug('Loaded User {} from db'.format(user))
