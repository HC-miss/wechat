import os
from tornado import web, ioloop, httpserver, gen, httpclient
from tornado import options
from urllib.parse import quote
import xmltodict
import hashlib
import time
import json

WECHAT_TOKEN = 'hcc'
WECHAT_APPID = 'wxd8c6f5599d23d156'
WECHAT_APPSECRET = '7e3511de68ede82950fd711a9589e9e3'
REDIRECT_URI = 'http://123.207.74.43/power/'


def robot(message):
    key = {
        "reqType": 0,
        "perception": {
            "inputText": {
                "text": message
            },
        },
        "userInfo": {
            "apiKey": "d8e65ae8e55f4d48ab7bec9eb0b87f2d",
            "userId": "333507"
        }
    }
    url = "http://openapi.tuling123.com/openapi/api/v2"
    body = json.dumps(key)
    req = httpclient.HTTPRequest(url, method="POST", body=body,)
    return req


class AccessToken(object):
    __access_token = None
    __expires_in = 0
    __create_time = 0

    @classmethod
    @gen.coroutine
    def get_access_token(cls):
        if time.time() > (cls.__expires_in - 200) + cls.__create_time:
            yield cls.update_access_token()
            raise gen.Return(cls.__access_token)
        else:
            raise gen.Return(cls.__access_token)

    @classmethod
    @gen.coroutine
    def update_access_token(cls):
        url = 'https://api.weixin.qq.com/cgi-bin/token?'\
        'grant_type=client_credential&appid=%s&secret=%s' % (WECHAT_APPID, WECHAT_APPSECRET)
        client = httpclient.AsyncHTTPClient()
        resp = yield client.fetch(url)
        data = json.loads(resp.body.decode('utf-8'))
        if 'errcode' in data:
            raise Exception('Wechat server error')
        else:
            cls.__access_token = data['access_token']
            cls.__expires_in = data['expires_in']
            cls.__create_time = time.time()


class Wechat(web.RequestHandler):
    def prepare(self):
        signature = self.get_argument('signature')
        timestamp = self.get_argument('timestamp')
        nonce = self.get_argument('nonce')
        # echostr = self.get_argument('echostr') Avoid getting parameters and resulting exceptions
        list1 = [WECHAT_TOKEN, timestamp, nonce]
        list1.sort()
        sign = hashlib.sha1(''.join(list1).encode('utf-8')).hexdigest()
        if sign != signature:
            self.send_error(403)

    def get(self):
        echostr = self.get_argument('echostr')
        self.write(echostr)

    @gen.coroutine
    def post(self, *args, **kwargs):
        xml_data = self.request.body
        dict_data = xmltodict.parse(xml_data)
        msg_type = dict_data['xml']['MsgType']
        if msg_type == 'text':
            content = dict_data['xml']['Content']
            req = robot(content)
            client = httpclient.AsyncHTTPClient()
            response = yield client.fetch(req)
            if response.error:
                self.send_error(500)
            else:
                data = json.loads(response.body.decode('utf-8'))
                resp_data = {
                    'xml': {
                        'ToUserName': dict_data['xml']['FromUserName'],
                        'FromUserName': dict_data['xml']['ToUserName'],
                        'CreateTime': int(time.time()),
                        'MsgType': 'text',
                        'Content': data["results"][0]["values"]["text"]
                    }
                }
                self.write(xmltodict.unparse(resp_data))
        elif msg_type == 'image':
            media_id = dict_data['xml']['MediaId']
            resp_data = {
                'xml': {
                    'ToUserName': dict_data['xml']['FromUserName'],
                    'FromUserName': dict_data['xml']['ToUserName'],
                    'CreateTime': int(time.time()),
                    'MsgType': 'image',
                    'Image': {
                        'MediaId': media_id
                    }
                }
            }
            self.write(xmltodict.unparse(resp_data))
        elif msg_type == 'voice':
            recognition = dict_data['xml']['Recognition']
            media_id = dict_data['xml']['MediaId']
            print(recognition)
            resp_data = {
                'xml': {
                    'ToUserName': dict_data['xml']['FromUserName'],
                    'FromUserName': dict_data['xml']['ToUserName'],
                    'CreateTime': int(time.time()),
                    'MsgType': 'voice',
                    'Voice': {
                        'MediaId': media_id
                    }
                }
            }
            if recognition == '授权链接':
                resp_data = {
                'xml': {
                    'ToUserName': dict_data['xml']['FromUserName'],
                    'FromUserName': dict_data['xml']['ToUserName'],
                    'CreateTime': int(time.time()),
                    'MsgType': 'text',
                    'Content': 'https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_userinfo&state=iloveu#wechat_redirect' % (WECHAT_APPID, quote(REDIRECT_URI))
                }
            }

            self.write(xmltodict.unparse(resp_data))
        elif msg_type == 'event':
            event_type = dict_data['xml']['Event']
            if event_type == 'subscribe':
                resp_data = {
                    'xml': {
                        'ToUserName': dict_data['xml']['FromUserName'],
                        'FromUserName': dict_data['xml']['ToUserName'],
                        'CreateTime': int(time.time()),
                        'MsgType': 'text',
                        'Content': 'Hello Python --Tornado'
                    }
                }
                event_key = dict_data['xml'].get('EventKey', None)
                if event_key:
                    scend_id = event_key[8:]
                    resp_data['xml']['Content'] = 'The parameter of this qr code is:%s' % scend_id
                self.write(xmltodict.unparse(resp_data))
            elif event_type == 'SCAN':
                event_key = dict_data['xml']['EventKey']
                resp_data = {
                    'xml': {
                        'ToUserName': dict_data['xml']['FromUserName'],
                        'FromUserName': dict_data['xml']['ToUserName'],
                        'CreateTime': int(time.time()),
                        'MsgType': 'text',
                        'Content': 'Thank you for your attention. The parameters of your scan are:： %s' % event_key
                    }
                }
                self.write(xmltodict.unparse(resp_data))
            elif event_type == 'unsubscribe':
                resp_data = {
                    'xml': {
                        'ToUserName': dict_data['xml']['FromUserName'],
                        'FromUserName': dict_data['xml']['ToUserName'],
                        'CreateTime': int(time.time()),
                        'MsgType': 'text',
                        'Content': 'Bey --Tornado'
                    }
                }
                self.write(xmltodict.unparse(resp_data))
            else: # Other events
                resp_data = {
                    'xml': {
                        'ToUserName': dict_data['xml']['FromUserName'],
                        'FromUserName': dict_data['xml']['ToUserName'],
                        'CreateTime': int(time.time()),
                        'MsgType': 'text',
                        'Content': 'The universal response'
                    }
                }
                self.write(xmltodict.unparse(resp_data))
        else:
            resp_data = {
                'xml': {
                    'ToUserName': dict_data['xml']['FromUserName'],
                    'FromUserName': dict_data['xml']['ToUserName'],
                    'CreateTime': int(time.time()),
                    'MsgType': 'text',
                    'Content': 'The universal response'
                }
            }
            self.write(xmltodict.unparse(resp_data))


class GetPower(web.RequestHandler):
    @gen.coroutine
    def get(self, *args, **kwargs):
        state = self.get_argument('state')
        print(state)
        code = self.get_argument('code') # Can only be used once, 5 minutes is not used automatically expired.
        url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code' % (WECHAT_APPID, WECHAT_APPSECRET, code)
        client = httpclient.AsyncHTTPClient()
        resp = yield client.fetch(url)
        dict_data = json.loads(resp.body.decode('utf-8'))
        if 'errcode' in dict_data:
            self.write('An exception has occurred: %s' % dict_data['errmsg'])
        else:
            access_token = dict_data['access_token']
            refresh_token = dict_data['refresh_token'] # Refresh access_token
            expire_in = dict_data['expire_in']
            openid = dict_data['openid']
            scope = dict_data['scope']
            get_info_url = 'https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s&lang=zh_CN' % (access_token, openid)
            info_resp = yield client.fetch(get_info_url)
            info_data = json.loads(info_resp.body.decode('utf-8'))
            self.render('index.html', info=info_data)


class Qrcode(web.RequestHandler):
    @gen.coroutine
    def get(self, *args, **kwargs):
        scene_id = self.get_argument('sid')
        try:
            access_token = yield AccessToken.get_access_token() # 此处需要加yield
        except Exception as e:
            self.write('Server error : ' % e)
        else:
            url = 'https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=%s' % access_token
            client = httpclient.AsyncHTTPClient()
            req_data = {"action_name": "QR_LIMIT_SCENE", "action_info": {"scene": {"scene_id": scene_id}}}
            req = httpclient.HTTPRequest(url, method='POST', body=json.dumps(req_data))
            resp = yield client.fetch(req)
            dict_data = json.loads(resp.body.decode('utf-8'))
            if 'errcode' in dict_data:
                self.write('Get qrcode failed')
            else:
                ticket = dict_data['ticket']
                self.write('<img src="https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=%s"/></br>' % ticket)
                self.write('<p>%s</p>' % dict_data['url'])


def main():
    options.define('port', default=8000, type=int, help='Test server connect...')
    options.parse_command_line()
    app = web.Application([
        (r'/wechat/', Wechat),
        (r'/qrcode', Qrcode),
        (r'/power/', GetPower),
    ], template_path=os.path.join(os.getcwd(), 'templates'))
    server = httpserver.HTTPServer(app)
    server.bind(options.options.port)
    server.start(1)
    print('Server start')
    ioloop.IOLoop.current().start()


if __name__ == '__main__':
    main()
