# -*- coding: utf-8 -*-

"""
gspread.client
~~~~~~~~~~~~~~

This module contains Client class responsible for communicating with
Google API.

"""

try:
	from google.auth.transport.requests import AuthorizedSession
except Exception:
	pass

from .exceptions import APIError, SpreadsheetNotFound
from .models import Spreadsheet
from .utils import convert_credentials, extract_id_from_url, finditem

from .urls import (
	DRIVE_FILES_API_V2_URL,
	DRIVE_FILES_API_V3_URL,
	DRIVE_FILES_UPLOAD_API_V2_URL
)

import urllib, urllib2
from google.appengine.api import urlfetch
import logging
import json


class ConvertResponse():
	response = None
	
	def __init__(self, response):
		if response:
			self.response = json.loads(response)
	
	def json(self):
		# if self.response and 'code' in self.response:
		# 	if self.response['code'] == 401 or self.response['code'] == 403:
		# 		raise self.response['message']
		
		return self.response


class Client(object):
	"""An instance of this class communicates with Google API.

	:param auth: An OAuth2 credential object. Credential objects
							 are those created by the google-auth library.
							 https://github.com/googleapis/google-auth-library-python
	:param session: (optional) A session object capable of making HTTP requests
									while persisting some parameters across requests.
									Defaults to `requests.Session <http://docs.python-requests.org/en/master/api/#request-sessions>`_.

	>>> c = gspread.Client(auth=OAuthCredentialObject)

	"""
	# def __init__(self, auth, session=None):
	#     self.auth = convert_credentials(auth)
	#     self.session = session or AuthorizedSession(self.auth)
	#
	# def login(self):
	#     from google.auth.transport.requests import Request
	#
	#     self.auth.refresh(Request(self.session))
	#
	#     self.session.headers.update({
	#         'Authorization': 'Bearer %s' % self.auth.token
	#     })
	
	access_token = None
	headers = None
	
	def __init__(self, auth=None, session=None, access_token=None):
		if access_token is not None:
			self.access_token = access_token
			self.headers = {"Authorization": "Bearer %s" % access_token}
		else:
			self.auth = convert_credentials(auth)
			self.session = session or AuthorizedSession(self.auth)
	
	def login(self):
		if self.access_token is not None:
			pass
		else:
			from google.auth.transport.requests import Request
			
			self.auth.refresh(Request(self.session))
			
			self.session.headers.update({
				'Authorization': 'Bearer %s' % self.auth.token
			})
	
	def encode(self, json_data):
		return json.JSONEncoder().encode(json_data)
	
	def decode(self, json_str):
		return json.JSONDecoder().decode(json_str)
	
	def dumps(self, data):
		return json.dumps(data)
	
	def request(
		self,
		method,
		endpoint,
		params=None,
		data=None,
		json=None,
		files=None,
		headers=None):
		
		if self.access_token is not None:
			
			# logging.info(method)
			# logging.info(endpoint)
			# logging.info(params)
			# logging.info(data)
			# logging.info(json)
			# logging.info(files)
			
			if method == 'get':
				headers = {
					"Content-Type": "application/x-www-form-urlencoded",
					"Authorization": "Bearer %s" % self.access_token
				}
				payload = urllib.urlencode({})
				if params is not None:
					payload = urllib.urlencode(params)
				if data is not None:
					payload = urllib.urlencode(data)
				if json is not None:
					payload = urllib.urlencode(json)
			
			elif method == 'post' or method == 'put':
				headers = {
					"Content-Type": "application/json",
					"Authorization": "Bearer %s" % self.access_token
				}
				payload = {}
				if params is not None:
					endpoint += '?' + urllib.urlencode(params)
				if data is not None:
					payload = self.dumps(data)
				if json is not None:
					payload = self.dumps(json)
			
			# req = urllib2.Request(endpoint, data, headers=self.headers)
			# try:
			# 	response = urllib2.urlopen(req)
			# 	jsondata = response.read().decode("utf-8")
			# 	return jsondata
			#
			# except urllib2.URLError as e:
			# 	logging.error(e.reason)
			# 	return e.reason
			
			urlfetch_method = urlfetch.GET
			if method == 'post':
				urlfetch_method = urlfetch.POST
			if method == 'put':
				urlfetch_method = urlfetch.PUT
			if method == 'delete':
				urlfetch_method = urlfetch.DELETE
			if method == 'head':
				urlfetch_method = urlfetch.HEAD
			if method == 'patch':
				urlfetch_method = urlfetch.PATCH
			try:
				result = urlfetch.fetch(
					url=endpoint,
					payload=payload,
					method=urlfetch_method,
					dealine=30,
					headers=headers)
				# logging.warn(result)
				# logging.warn(result.status_code)
				# logging.warn(result.content)
				if result.status_code == 200:
					return ConvertResponse(result.content)
				else:
					raise APIError(ConvertResponse(result.content))
			# elif result.status_code == 401 or result.status_code == 403:
			# 	error = self.decode(result.content)
			# 	raise APIError(ConvertResponse(self.encode({
			# 		'code': error['error']['code'],
			# 		'message': error['error']['message'],
			# 		'status': error['error']['status'],
			# 		'error_message': 'unauthorize'
			# 	})))
			# else:
			# 	error = self.decode(result.content)
			# 	raise APIError(ConvertResponse(self.encode({
			# 		'code': error['error']['code'],
			# 		'message': error['error']['message'],
			# 		'status': error['error']['status'],
			# 		'error_message': 'Caught exception fetching url'
			# 	})))
			except urlfetch.Error:
				logging.exception('Caught exception fetching url')
				# return 'Caught exception fetching url'
				raise APIError(ConvertResponse(self.encode({
					'status_code': 500,
					'error_message': 'Caught exception fetching url'
				})))
		# except DeadlineExceededError as e:
		# 	logging.exception(e)
		# 	return None
		
		else:
			response = getattr(self.session, method)(
				endpoint,
				json=json,
				params=params,
				data=data,
				files=files,
				headers=headers
			)
			
			if response.ok:
				return response
			else:
				raise APIError(response)
	
	def list_spreadsheet_files(self, title=None):
		files = []
		page_token = ''
		url = DRIVE_FILES_API_V3_URL
		
		q = 'mimeType="application/vnd.google-apps.spreadsheet"'
		if title:
			q += ' and name = "{}"'.format(title)
		
		params = {
			'q': q,
			'pageSize': 1000,
			'supportsAllDrives': True,
			'includeItemsFromAllDrives': True,
		}
		
		while page_token is not None:
			if page_token:
				params['pageToken'] = page_token
			
			res = self.request('get', url, params=params).json()
			files.extend(res['files'])
			page_token = res.get('nextPageToken', None)
		
		return files
	
	def open(self, title):
		"""Opens a spreadsheet.

		:param title: A title of a spreadsheet.
		:type title: str

		:returns: a :class:`~gspread.models.Spreadsheet` instance.

		If there's more than one spreadsheet with same title the first one
		will be opened.

		:raises gspread.SpreadsheetNotFound: if no spreadsheet with
																				 specified `title` is found.

		>>> c = gspread.authorize(credentials)
		>>> c.open('My fancy spreadsheet')

		"""
		try:
			properties = finditem(
				lambda x: x['name'] == title,
				self.list_spreadsheet_files(title)
			)
			
			# Drive uses different terminology
			properties['title'] = properties['name']
			
			return Spreadsheet(self, properties)
		except StopIteration:
			raise SpreadsheetNotFound
	
	def open_by_key(self, key):
		"""Opens a spreadsheet specified by `key`.

		:param key: A key of a spreadsheet as it appears in a URL in a browser.
		:type key: str

		:returns: a :class:`~gspread.models.Spreadsheet` instance.

		>>> c = gspread.authorize(credentials)
		>>> c.open_by_key('0BmgG6nO_6dprdS1MN3d3MkdPa142WFRrdnRRUWl1UFE')

		"""
		return Spreadsheet(self, {'id': key})
	
	def open_by_url(self, url):
		"""Opens a spreadsheet specified by `url`.

		:param url: URL of a spreadsheet as it appears in a browser.
		:type url: str

		:returns: a :class:`~gspread.models.Spreadsheet` instance.

		:raises gspread.SpreadsheetNotFound: if no spreadsheet with
																				 specified `url` is found.

		>>> c = gspread.authorize(credentials)
		>>> c.open_by_url('https://docs.google.com/spreadsheet/ccc?key=0Bm...FE&hl')

		"""
		return self.open_by_key(extract_id_from_url(url))
	
	def openall(self, title=None):
		"""Opens all available spreadsheets.

		:param title: (optional) If specified can be used to filter
									spreadsheets by title.
		:type title: str

		:returns: a list of :class:`~gspread.models.Spreadsheet` instances.

		"""
		spreadsheet_files = self.list_spreadsheet_files(title)
		
		if title:
			spreadsheet_files = [
				spread for spread in spreadsheet_files if title == spread["name"]
			]
		
		return [
			Spreadsheet(self, dict(title=x['name'], **x))
			for x in spreadsheet_files
		]
	
	def create(self, title):
		"""Creates a new spreadsheet.

		:param title: A title of a new spreadsheet.
		:type title: str

		:returns: a :class:`~gspread.models.Spreadsheet` instance.

		.. note::

			 In order to use this method, you need to add
			 ``https://www.googleapis.com/auth/drive`` to your oAuth scope.

			 Example::

					scope = [
							'https://spreadsheets.google.com/feeds',
							'https://www.googleapis.com/auth/drive'
					]

			 Otherwise you will get an ``Insufficient Permission`` error
			 when you try to create a new spreadsheet.

		"""
		payload = {
			'name': title,
			'mimeType': 'application/vnd.google-apps.spreadsheet'
		}
		r = self.request(
			'post',
			DRIVE_FILES_API_V3_URL,
			json=payload
		)
		spreadsheet_id = r.json()['id']
		return self.open_by_key(spreadsheet_id)
	
	def copy(self, file_id, title=None, copy_permissions=False):
		"""Copies a spreadsheet.

		:param file_id: A key of a spreadsheet to copy.
		:type title: str

		:param title: (optional) A title for the new spreadsheet.
		:type title: str

		:param copy_permissions: (optional) If True, copy permissions from
					 original spreadsheet to new spreadsheet.
		:type copy_permissions: bool


		:returns: a :class:`~gspread.models.Spreadsheet` instance.

		.. versionadded:: 3.1.0

		.. note::

			 In order to use this method, you need to add
			 ``https://www.googleapis.com/auth/drive`` to your oAuth scope.

			 Example::

					scope = [
							'https://spreadsheets.google.com/feeds',
							'https://www.googleapis.com/auth/drive'
					]

			 Otherwise you will get an ``Insufficient Permission`` error
			 when you try to copy a spreadsheet.

		"""
		url = '{0}/{1}/copy'.format(
			DRIVE_FILES_API_V2_URL,
			file_id
		)
		
		payload = {
			'title': title,
			'mimeType': 'application/vnd.google-apps.spreadsheet'
		}
		params = {
			'supportsAllDrives': True
		}
		r = self.request(
			'post',
			url,
			json=payload,
			params=params
		)
		spreadsheet_id = r.json()['id']
		
		new_spreadsheet = self.open_by_key(spreadsheet_id)
		
		if copy_permissions:
			original = self.open_by_key(file_id)
			
			permissions = original.list_permissions()
			for p in permissions:
				if p.get('deleted'):
					continue
				try:
					new_spreadsheet.share(
						value=p['emailAddress'],
						perm_type=p['type'],
						role=p['role'],
						notify=False
					)
				except Exception:
					pass
		
		return new_spreadsheet
	
	def del_spreadsheet(self, file_id):
		"""Deletes a spreadsheet.

		:param file_id: a spreadsheet ID (aka file ID.)
		:type file_id: str
		"""
		url = '{0}/{1}'.format(
			DRIVE_FILES_API_V3_URL,
			file_id
		)
		
		params = {
			'supportsAllDrives': True
		}
		self.request('delete', url, params=params)
	
	def import_csv(self, file_id, data):
		"""Imports data into the first page of the spreadsheet.

		:param str data: A CSV string of data.

		Example:

		.. code::

				# Read CSV file contents
				content = open('file_to_import.csv', 'r').read()

				gc.import_csv(spreadsheet.id, content)

		.. note::

			 This method removes all other worksheets and then entirely
			 replaces the contents of the first worksheet.

		"""
		headers = {'Content-Type': 'text/csv'}
		url = '{0}/{1}'.format(DRIVE_FILES_UPLOAD_API_V2_URL, file_id)
		
		self.request(
			'put',
			url,
			data=data,
			params={
				'uploadType': 'media',
				'convert': True,
				'supportsAllDrives': True
			},
			headers=headers
		)
	
	def list_permissions(self, file_id):
		"""Retrieve a list of permissions for a file.

		:param file_id: a spreadsheet ID (aka file ID.)
		:type file_id: str
		"""
		url = '{0}/{1}/permissions'.format(DRIVE_FILES_API_V2_URL, file_id)
		
		params = {
			'supportsAllDrives': True
		}
		r = self.request('get', url, params=params)
		
		return r.json()['items']
	
	def insert_permission(
		self,
		file_id,
		value,
		perm_type,
		role,
		notify=True,
		email_message=None,
		with_link=False
	):
		"""Creates a new permission for a file.

		:param file_id: a spreadsheet ID (aka file ID.)
		:type file_id: str
		:param value: user or group e-mail address, domain name
									or None for 'default' type.
		:type value: str, None
		:param perm_type: (optional) The account type.
					 Allowed values are: ``user``, ``group``, ``domain``,
					 ``anyone``
		:type perm_type: str
		:param role: (optional) The primary role for this user.
					 Allowed values are: ``owner``, ``writer``, ``reader``
		:type str:

		:param notify: (optional) Whether to send an email to the target user/domain.
		:type notify: str
		:param email_message: (optional) An email message to be sent if notify=True.
		:type email_message: str

		:param with_link: (optional) Whether the link is required for this permission to be active.
		:type with_link: bool

		Examples::

				# Give write permissions to otto@example.com

				gc.insert_permission(
						'0BmgG6nO_6dprnRRUWl1UFE',
						'otto@example.org',
						perm_type='user',
						role='writer'
				)

				# Make the spreadsheet publicly readable

				gc.insert_permission(
						'0BmgG6nO_6dprnRRUWl1UFE',
						None,
						perm_type='anyone',
						role='reader'
				)

		"""
		
		url = '{0}/{1}/permissions'.format(DRIVE_FILES_API_V2_URL, file_id)
		
		payload = {
			'value': value,
			'type': perm_type,
			'role': role,
			'withLink': with_link
		}
		
		params = {
			'sendNotificationEmails': notify,
			'emailMessage': email_message,
			'supportsAllDrives': 'true'
		}
		
		self.request(
			'post',
			url,
			json=payload,
			params=params
		)
	
	def remove_permission(self, file_id, permission_id):
		"""Deletes a permission from a file.

		:param file_id: a spreadsheet ID (aka file ID.)
		:type file_id: str
		:param permission_id: an ID for the permission.
		:type permission_id: str
		"""
		url = '{0}/{1}/permissions/{2}'.format(
			DRIVE_FILES_API_V2_URL,
			file_id,
			permission_id
		)
		
		params = {
			'supportsAllDrives': True
		}
		self.request('delete', url, params=params)
