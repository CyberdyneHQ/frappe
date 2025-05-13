# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE
import base64
import binascii
import json
from urllib.parse import urlencode, urlparse

import frappe
import frappe.client
import frappe.handler
from frappe import _
from frappe.utils.response import build_response
from frappe.utils.data import sbool


def api_method_handler(doctype):
		frappe.local.form_dict.cmd = doctype
		return frappe.handler.handle()


def api_resource_handler(doctype, name):
		if "run_method" in frappe.local.form_dict:
						frappe.local.form_dict.limit or frappe.local.form_dict.limit_page_length or 20,
					)

					# convert strings to native types - only as_dict and debug accept bool
					for param in ["as_dict", "debug"]:
						param_val = frappe.local.form_dict.get(param)
						if param_val is not None:
							frappe.local.form_dict[param] = sbool(param_val)

					# evaluate frappe.get_list
					data = frappe.call(frappe.client.get_list, doctype, **frappe.local.form_dict)

					# set frappe.get_list result to response
					frappe.local.response.update({"data": data})

				if frappe.local.request.method == "POST":
					# fetch data from from dict
					data = get_request_form_data()
					data.update({"doctype": doctype})

					# insert document from request data
					doc = frappe.get_doc(data).insert()

					# set response data
					frappe.local.response.update({"data": doc.as_dict()})

					# commit for POST requests
					frappe.db.commit()
			else:
				raise frappe.DoesNotExistError

	else:
		raise frappe.DoesNotExistError

	return build_response("json")


def get_request_form_data():
	if frappe.local.form_dict.data is None:
		data = frappe.safe_decode(frappe.local.request.get_data())
	else:
		data = frappe.local.form_dict.data

	return frappe.parse_json(data)


def validate_auth():
	"""
	Authenticate and sets user for the request.
	"""
	authorization_header = frappe.get_request_header("Authorization", str()).split(" ")

	if len(authorization_header) == 2:
		validate_oauth(authorization_header)
		validate_auth_via_api_keys(authorization_header)

	validate_auth_via_hooks()


def validate_oauth(authorization_header):
	"""
	Authenticate request using OAuth and set session user

	Args:
		authorization_header (list of str): The 'Authorization' header containing the prefix and token
	"""

	from frappe.integrations.oauth2 import get_oauth_server
	from frappe.oauth import get_url_delimiter

	form_dict = frappe.local.form_dict
	token = authorization_header[1]
	req = frappe.request
	parsed_url = urlparse(req.url)
	access_token = {"access_token": token}
	uri = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path + "?" + urlencode(access_token)
	http_method = req.method
	headers = req.headers
	body = req.get_data()
	if req.content_type and "multipart/form-data" in req.content_type:
		body = None

	try:
		required_scopes = frappe.db.get_value("OAuth Bearer Token", token, "scopes").split(get_url_delimiter())
		valid, oauthlib_request = get_oauth_server().verify_request(uri, http_method, body, headers, required_scopes)
		if valid:
			frappe.set_user(frappe.db.get_value("OAuth Bearer Token", token, "user"))
			frappe.local.form_dict = form_dict
	except AttributeError:
		pass



def validate_auth_via_api_keys(authorization_header):
	"""
	Authenticate request using API keys and set session user

	Args:
		authorization_header (list of str): The 'Authorization' header containing the prefix and token
	"""

	try:
		auth_type, auth_token = authorization_header
		authorization_source = frappe.get_request_header("Frappe-Authorization-Source")
		if auth_type.lower() == 'basic':
			api_key, api_secret = frappe.safe_decode(base64.b64decode(auth_token)).split(":")
			validate_api_key_secret(api_key, api_secret, authorization_source)
		elif auth_type.lower() == 'token':
			api_key, api_secret = auth_token.split(":")
			validate_api_key_secret(api_key, api_secret, authorization_source)
	except binascii.Error:
		frappe.throw(_("Failed to decode token, please provide a valid base64-encoded token."), frappe.InvalidAuthorizationToken)
	except (AttributeError, TypeError, ValueError):
		pass


def validate_api_key_secret(api_key, api_secret, frappe_authorization_source=None):
	"""frappe_authorization_source to provide api key and secret for a doctype apart from User"""
	doctype = frappe_authorization_source or 'User'
	doc = frappe.db.get_value(
		doctype=doctype,
		filters={"api_key": api_key},
		fieldname=["name"]
	)
	form_dict = frappe.local.form_dict
	doc_secret = frappe.utils.password.get_decrypted_password(doctype, doc, fieldname='api_secret')
	if api_secret == doc_secret:
		if doctype == 'User':
			user = frappe.db.get_value(
				doctype="User",
				filters={"api_key": api_key},
				fieldname=["name"]
			)
		else:
			user = frappe.db.get_value(doctype, doc, 'user')
		if frappe.local.login_manager.user in ('', 'Guest'):
			frappe.set_user(user)
		frappe.local.form_dict = form_dict


def validate_auth_via_hooks():
	for auth_hook in frappe.get_hooks('auth_hooks', []):
		frappe.get_attr(auth_hook)()
