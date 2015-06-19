# Copyright (c) 2015 Sanghyuck Lee <shlee322@elab.kr>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Swift Checksum Middleware

Supported Algorithms : md5, sha1, sha224, sha256, sha384, sha512

Swift Checksum Middleware은 Object들의 Checksum을 확인할 수 있는 미들웨어입니다.

전체 혹은 Range를 설정하여 부분 체크썸을 확인할 수 있으며 DLO, SLO의 체크썸도
정상적으로 획득 할 수 있습니다.

Object GET Request의 query parameter에 checksum={algorithm1,algorithm2...}를 
덧붙여 요청을 보내면 text/plain 형태로 해당 알고리즘 순서대로 한 라인씩
나오게 됩니다. 지원하지 않는 알고리즘의 경우 해당 라인은 빈 라인으로 나옵니다

Response 헤더에 X-Object-Checksum이 추가되며 해당 내용은 request의 checksum과 동일
합니다.

For Request example::

    GET /v1/{account}/{container}/{object}?checksum=md5,test,sha1

For Response example::

    a3c6ea066140e2d37f6cd598201366d8

    54e52511cf1a5f365066824175a9f72c89a397b9

Swift Checksum Middleware를 사용하기 위해서는 proxy server와 object server의
pipeline를 수정해야 하며 DLO, SLO 보다 앞에 checksum 미들웨어가 위치해야 합니다.

For proxy-server.conf example::

    [pipeline:main]
    pipeline =  ... checksum ... dlo slo ... proxy-server

    [filter:checksum]
    use = egg:swift-checksum#swiftchecksum
    default = proxy
    # Option
    # hash_func_factory = sanghyuck.swift.utils:hash_funcs
    # skip_func_factory = sanghyuck.swift.utils:skip_funcs
    # skip_request_params = multipart-manifest
    # skip_request_headers = Range
    # skip_response_headers = X-Object-Meta-NotUsedChecksum


For object-server.conf example:

    [pipeline:main]
    pipeline =  ... checksum ... object-server

    [filter:checksum]
    use = egg:swift-checksum#swiftchecksum
    default = object
    # Option
    # hash_func_factory = sanghyuck.swift.utils:hash_funcs
    # skip_func_factory = sanghyuck.swift.utils:skip_funcs
    # skip_request_params = multipart-manifest
    # skip_request_headers = Range
    # skip_response_headers = X-Object-Meta-NotUsedChecksum

hash_func_factory example:

    def hash_func_factory(conf):
        def hash_func(algorithm, data):
            if algorithm == 'md4':
                return md4(data)
            return None
        return hash_func

skip_func_factory example:

    def skip_func_factory(conf):
        def skip_func(req, resp):
            return req.params.get('skip_test') is not None
        return skip_func

"""

import hashlib
from swift.common.swob import wsgify, Response
from swift.common.http import is_success
from swift.common.utils import get_logger, split_path


hash_funcs = {
    'md5': lambda data: hashlib.md5(data).hexdigest(),
    'sha1': lambda data: hashlib.sha1(data).hexdigest(),
    'sha224': lambda data: hashlib.sha224(data).hexdigest(),
    'sha256': lambda data: hashlib.sha256(data).hexdigest(),
    'sha384': lambda data: hashlib.sha384(data).hexdigest(),
    'sha512': lambda data: hashlib.sha512(data).hexdigest()
}


class ChecksumMiddleware(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='swift-checksum')

        self.hash_func = self._load_func(conf.get('hash_func_factory'))
        self.skip_func = self._load_func(conf.get('skip_func_factory'))
        self.skip_request_params = self._get_skip_info('skip_request_params', '')
        self.skip_request_headers = self._get_skip_info('skip_request_headers', '')
        self.skip_response_headers = self._get_skip_info('skip_response_headers', '')

    def _load_func(self, name):
        if not name:
            return None

        func = None

        module, factory = name.rsplit(':', 1)
        try:
            factory = getattr(__import__(module, globals()), factory)
            func = factory(self.conf)
        except Exception as e:
            self.logger.exception(e)

        return func

    def _get_skip_info(self, name, default=''):
        return [info.strip() for info in self.conf.get(name, default).split(',')]

    def request_checksum(self, req):
        resp = req.get_response(self.app)
        if not self.is_checksum_success(req, resp) and self.check_skip(req, resp):
            return resp, None

        return resp, req.params['checksum'].split(',')

    @staticmethod
    def is_checksum_success(req, resp):
        try:
            split_path(req.path_info, 4, 4, True)
            return is_success(resp.status_int) and req.method == 'GET' and req.params.get('checksum', None) is not None
        except ValueError:
            return False

    def check_skip(self, req, resp):
        for name in self.skip_request_params:
            if name in req.params:
                return True

        for name in self.skip_request_headers:
            if name in req.headers:
                return True

        for name in self.skip_response_headers:
            if name in resp.headers:
                return True

        return self.skip_func and self.skip_func(req, resp)

    def create_checksum(self, algorithms, data):
        checksum = []
        for hash_algorithm in algorithms:
            if self.hash_func:
                data = self.hash_func(hash_algorithm, data)
                if data is not None:
                    checksum.append(data)
                    continue

            if hash_algorithm in hash_funcs:
                hash_func = hash_funcs[hash_algorithm]
                checksum.append(hash_func(data))
            else:
                self.logger.info('Not Found Hash Algorithm - %s' % hash_algorithm)
                checksum.append('')

        return Response(body='\n'.join(checksum), headers={
            'Content-Type': 'text/plain',
            'X-Object-Checksum': ','.join(algorithms)
        })


def _set_filter_conf(conf, name, value):
    data = conf.get(name)
    if data:
        conf.set(name,  data + ', ' + value)
    else:
        conf.set(name, value)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    default_conf = conf.get('default')
    if default_conf == 'proxy':
        _set_filter_conf(conf, 'skip_response_headers', 'X-Object-Checksum')
    elif default_conf == 'object':
        _set_filter_conf(conf, 'skip_request_params', 'skip_request_params')

    def checksum_filter_factory(app):
        return ChecksumMiddleware(app, conf)
    return checksum_filter_factory

