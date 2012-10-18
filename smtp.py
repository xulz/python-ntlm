# This library is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see <http://www.gnu.org/licenses/> or <http://www.gnu.org/licenses/lgpl.txt>.

from HTTPNtlmAuthHandler import asbase64
import ntlm
from smtplib import SMTPException, SMTPAuthenticationError

from base64 import decodestring

def ntlm_authenticate(smtp, username, password):
    """Example:
    >>> import smtplib
    >>> smtp = smtplib.SMTP("my.smtp.server")
    >>> smtp.ehlo()
    >>> ntlm_authenticate(smtp, r"DOMAIN\username", "password")
    """
    code, response = smtp.docmd("AUTH", "NTLM " + asbase64(ntlm.create_NTLM_NEGOTIATE_MESSAGE(username)))
    if code != 334:
        raise SMTPException("Server did not respond as expected to NTLM negotiate message")
    challenge, flags = ntlm.parse_NTLM_CHALLENGE_MESSAGE(decodestring(response))
    user_parts = username.split("\\", 1)
    code, response = smtp.docmd("", asbase64(ntlm.create_NTLM_AUTHENTICATE_MESSAGE(challenge, user_parts[1], user_parts[0], password, flags)))
    if code != 235:
        raise SMTPAuthenticationError(code, response)
