# -*- coding: utf-8 -*-

"""
gspread
~~~~~~~

Google Spreadsheets client library.

"""


__version__ = '3.4.2'
__author__ = 'Anton Burnashev'
__edited_by__ = 'Thang Nguyen <tan@vn.sateraito.co.jp> - 2020-02-23'


from .client import Client
from .models import Spreadsheet, Worksheet, Cell

from .exceptions import (
    GSpreadException,
    SpreadsheetNotFound,
    NoValidUrlKeyFound,
    IncorrectCellLabel,
    WorksheetNotFound,
    CellNotFound
)


def authorize(credentials, client_class=Client):
    """Login to Google API using OAuth2 credentials.
    This is a shortcut function which
    instantiates `client_class`.
    By default :class:`gspread.client.Client` is used.

    :returns: `client_class` instance.
    """

    client = client_class(auth=credentials)
    return client

def authorizeByToken(access_token, quotaUser=None, client_class=Client):
    """Fetch data to Google API using Access token Oauth2.
    This is a shortcut function which
    instantiates `client_class`.
    By default :class:`gspread.client.Client` is used.

    :returns: `client_class` instance.
    """
    client = client_class(access_token=access_token, quotaUser=quotaUser)
    return client
