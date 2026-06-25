
"""
        InsecureWebApp - an insecure Python/Flask Web application

        Copyright (C) 2024-2025  Kevin A. Lee (kadraman)

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import functools
import logging

from flask import current_app, g, make_response, redirect, render_template, session, url_for
from itsdangerous import URLSafeSerializer


logger = logging.getLogger(__name__)


def login_required(view):
    """View decorator that redirects anonymous users to the login page."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        email = session.get("email")
        if email is None:
            return redirect(url_for("auth.login"))

        return view(**kwargs)

    return wrapped_view


def gen_login_cookie(cookie_name, template):
    email = session["email"]
    logger.debug(f"Creating signed {cookie_name} cookie for {email}")
    serializer = URLSafeSerializer(current_app.config["SECRET_KEY"], salt=cookie_name)
    token = serializer.dumps({"email": email})
    # Redirect instead of rendering the target template directly so request
    # handlers can load request context such as g.user normally.
    res = make_response(redirect(url_for("users.home")))
    res.set_cookie(
        cookie_name,
        token,
        max_age=60 * 60 * 24 * 15,
        secure=True,
        httponly=True,
        samesite="Strict",
    )
    return res