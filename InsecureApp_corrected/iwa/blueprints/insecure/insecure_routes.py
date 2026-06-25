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

import logging
import os
import shutil
from pathlib import Path

from flask import Response, abort, jsonify, make_response, render_template_string
from flask import render_template
from flask import request

from markdown import markdown
from openai import OpenAI

from iwa.blueprints.assistant import assistant_service
from iwa.blueprints.assistant.assistant_service import AssistantService
from iwa.blueprints.insecure import insecure_bp


logger = logging.getLogger(__name__)

INITCMD = "setup.bat"


"""
This file contains examples of insecure coding practices for educational purposes only.
Do not use these practices in production code.
"""


"""
Cross-Site Scripting: Reflected (via URL query parameter)
"""
@insecure_bp.route("/xss1", methods = ["GET"])
def xss1():   
    user_input = request.args.get('input')
    return render_template("insecure/xss1.html", input=user_input)


"""
Server-Side Template Injection (via URL query parameter)
"""
@insecure_bp.route("/xss2", methods = ["GET"])
def xss2():   
    user_input = request.args.get('input')
    return render_template("insecure/xss2.html", input=user_input)


"""
Path Manipulation (via URL query parameter)
"""
@insecure_bp.route("/load_file", methods = ["GET"])
def load_file(): 
    filename = request.args.get('filename', '')
    contents = source(filename)
    return Response(contents, mimetype="text/plain")


"""
Command Injection (via URL query parameter)
"""
@insecure_bp.route("/command_injection", methods = ["GET"])
def command_injection():
    action = request.args.get("action", "status")
    if action == "status":
        load_1, load_5, load_15 = os.getloadavg()
        output = f"load average: {load_1:.2f}, {load_5:.2f}, {load_15:.2f}\n"
    elif action == "disk":
        usage = shutil.disk_usage("/")
        output = (
            f"total={usage.total} used={usage.used} "
            f"free={usage.free}\n"
        )
    else:
        abort(400, "Unsupported action")

    return Response(output, mimetype="text/plain")
    

"""
Cross-Site Scripting: Reflected (via POST form parameter)
Path Manipulation (via POST form parameter)
Server-Side Template Injection (via POST form parameter)
"""
@insecure_bp.route("/template_injection", methods=['POST'])
def template_injection():
    filename = request.form.get('filename', '')
    rendered_output = source(filename)
    return render_template(
        "insecure/template_injection.html",
        rendered_output=rendered_output,
    )


@insecure_bp.route("/insecure_headers", methods=['POST'])
def insecure_headers():
    header_name = request.form.get('header_name')
    header_value = request.form.get('header_value')
    response = make_response('Header set')
    response.headers[header_name] = header_value
    return response


@insecure_bp.route("/insecure_cookies", methods=['POST'])
def insecure_cookies():
    session_id = request.form.get('session_id', '12345')
    response = make_response('Insecure cookie set')
    response.set_cookie(
        'sessionid',
        session_id,
        secure=True,
        httponly=True,
        samesite='Strict',
    )
    return response


"""
Cross-Site Scripting: AI (via URL query parameter)
Prompt Injection (via URL query parameter)
"""
@insecure_bp.route("/prompt_injection", methods=["GET"])
def prompt_injection():
    user_input = request.args.get('input')
    api_key = os.getenv("OPENAI_API_KEY")
    client = OpenAI(api_key=api_key)
    if not api_key or not client:
        return render_template("insecure/prompt_injection.html", response=None, error="OpenAI is not available.")
    instructions = f"You are a helpful medical assistant. {user_input}"
    symptoms = f"a headache, a sore throat, {user_input}"
    messages = [
        {"role": "system", "content": instructions},
        {"role": "user", "content": "I have " + symptoms}
    ]
    completion = client.chat.completions.create(
        model="gpt-4",
        messages=messages
    )
    response = {
        "role": completion.choices[0].message.role,
        "content": completion.choices[0].message.content
    }
    return render_template("insecure/prompt_injection.html", response=response, error=None)


SAFE_FILES_DIR = (Path(__file__).resolve().parents[3] / "safe_files").resolve()


def source(script_path):
    requested = (SAFE_FILES_DIR / script_path).resolve()
    if not str(requested).startswith(str(SAFE_FILES_DIR)):
        abort(400, "Invalid path")
    if not requested.is_file():
        abort(404, "File not found")
    return requested.read_text(encoding="utf-8", errors="replace")
