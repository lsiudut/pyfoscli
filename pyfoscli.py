#!/usr/bin/env python3

import urllib
import urllib.request
import logging

import xml.etree.ElementTree as ET

from copy import copy

class FoscamException(Exception):
    pass

class Foscam(object):
    baseurl = 'http://{host}:{port}/cgi-bin/CGIProxy.fcgi'

    def __init__(self, host, port, usr, pwd):
        self._url = Foscam.baseurl.format(
            host = str(host),
            port = str(port)
        )

        self._credentials = {
            'usr': str(usr),
            'pwd': str(pwd),
        }

        self.get_dev_state()

    def _build_request(self, **params):
        urn = urllib.parse.urlencode(params)
        logging.debug("urn={}".format(urn))
        req = urllib.request.Request("{}?{}".format(self._url, urn))
        return req

    def _get(self, **params):
        _params = copy(params)
        _params.update(self._credentials)
        req = urllib.request.urlopen(
            self._build_request(**_params)
        )
        logging.debug("ret code = {}".format(req.getcode()))
        ret_string = req.read().decode()
        ret_xml = ET.fromstring(ret_string)
        logging.debug("ret string = {}".format(ret_string))
        result = None
        params = {}
        try:
            for child in ret_xml.iter():
                logging.debug("{}={}".format(child.tag, child.text))
                if child.tag == 'result':
                    result = int(child.text)
                else:
                    params[child.tag] = child.text
            logging.info('result = 0'.format(result))
            if result != 0:
                raise FoscamException("result != 0")
            return result, params
        except Exception as e:
            logging.exception("Unexpected result: {}".format(e))
            sys.exit(1)
        except FoscamException as e:
            logging.exception("Foscam Exception: {}".format(e))
            sys.exit(1)

    def login(self):
        return self._get(
            cmd = 'logIn'
        )

    def get_dev_state(self):
        return self._get(
            cmd = 'getDevState'
        )
        return ret

    def set_system_time(self, time_source='0', ntp_server='Auto', time_format='1', time_zone='-3600'):
        return self._get(
            cmd = 'setSystemTime',
            timeSource = time_source,
            ntpServer = ntp_server,
            timeFormat = time_format,
            timeZone = time_zone
        )
        return ret

    # this fucker may timeout
    def set_p2p_enable(self, enable=0):
        return self._get(
            cmd = 'setP2PEnable',
            enable = str(enable)
        )
        return ret

    def set_motion_detect_config(self, enable=0):
        return self._get(
            cmd = 'setMotionDetectConfig',
            isEnable = str(enable)
        )

    def set_dev_name(self, name):
        return self._get(
            cmd = 'setDevName',
            devName = name
        )

    def set_upnp_config(self, enable=0):
        return self._get(
            cmd = 'setUPnPConfig',
            isEnable = str(enable)
        )

    def set_ddns_config(self, enable=0, host_name=None, ddns_server=None, user=None, password=None):
        params = {
            'cmd': 'setDDNSConfig',
            'isEnable': enable,
        }
        if host_name is not None and ddns_server is not None and user is not None and password is not None:
            if not ddns_server in [0, 1, 2, 3]:
                raise FoscamException(
                    "Wrong DDNS server\n"
                    "Refer to documentation to check supported values"
                )
            params.update({
                'hostName': host_name,
                'ddnsServer': ddns_server,
                'user':  user,
                'password': password,
            })

        return self._get(**params)

    def change_password(self, usr_name, old_pwd, new_pwd):
        return self._get(
            cmd = 'changePassword',
            usrName = usr_name,
            oldPwd = old_pwd,
            newPwd = new_pwd
        )

    def add_account(self, usr_name, usr_pwd, privilege):
        privilege_map = {
            'visitor': '0',
            'operator': '1',
            'administrator': '2',
        }
        return self._get(
            cmd = 'addAccount',
            usrName = usr_name,
            usrPwd = usr_pwd,
            privilege = privilege
        )

    def enable_onvif_agent(self):
        return self._get(
            cmd = 'EnableOnvifAgent'
        )

    def disable_onvif_agent(self):
        return self._get(
            cmd = 'DisableOnvifAgent'
        )

    def get_port_info(self):
        return self._get(
            cmd = 'getPortInfo'
        )

    def set_port_info(self, web_port=88, media_port=88, https_port=None, onvif_port=None, rtsp_port=None):
        params = {
            'cmd': 'setPortInfo',
            'webPort': web_port,
            'mediaPort': media_port,
        }
        if https_port is not None:
            params['httpsPort'] = https_port
        if onvif_port is not None:
            params['onvifPort'] = onvif_port
        if rtsp_port is not None:
            params['rtspPort'] = rtsp_port

        return self._get(**params)

    def set_video_stream_param(self, stream_type, resolution, bit_rate, frame_rate, gop, isvbr):
        return self._get(
            cmd = 'setVideoStreamParam',
            streamType = stream_type,
            resolution = resolution,
            bitRate = bit_rate,
            frameRate = frame_rate,
            GOP = gop,
            isVBR = isvbr
        )

    def set_main_video_stream_type(self, stream_type):
        return self._get(
            cmd = 'setMainVideoStreamType',
            streamType = stream_type
        )

    def get_product_onvif_flag(self):
        return self._get(
            cmd = 'getProductOnvifFlag'
        )

    def _refresh_ports(self):
        ret, params = self.get_port_info()
        mapping = {
            'webPort': 'web_port',
            'mediaPort': 'media_port',
            'httpsPort': 'https_port',
            'rtspPort': 'rtsp_port',
            'onvifPort': 'onvif_port',
        }
        new_ports = { mapping[k]: int(v) for (k, v) in params.items() if k in mapping.keys() }

        if 'onvif_port' in new_ports and new_ports['onvif_port'] == 0:
            logging.debug("refreshing ovinf_port")
            new_ports['onvifPort'] = 888
        if 'rtsp_port' in new_ports and new_ports['rtsp_port'] == 0:
            logging.debug("refreshing rtsp_port")
            new_ports['rtspPort'] = 554

        self.set_port_info(**new_ports)


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Foscam Cmd Client')
    parser.add_argument('-H', dest='host', nargs='?', required=True, const=str)
    parser.add_argument('-p', dest='port', nargs='?', default=88, const=int)
    parser.add_argument('-u', dest='user', nargs='?', default='admin', const=str)
    parser.add_argument('-P', dest='password', nargs='?', default='', const=str)
    parser.add_argument('-n', dest='name', nargs='?', default=None)
    parser.add_argument('--skip-basics', dest='skip', action='store_true')
    parser.add_argument('--change-password', dest='chpw', nargs=2, metavar=('user', 'password'), default=None)
    parser.add_argument('--add-account', dest='addacc', nargs=3, metavar=('user', 'password', 'privilege'), default=None)
    args = parser.parse_args()

    logging.getLogger().setLevel(logging.DEBUG)
    foscam = Foscam(args.host, args.port, args.user, args.password)
    if not args.skip:
        foscam.set_system_time()
        foscam.set_motion_detect_config(enable=0)
        foscam.set_upnp_config(enable=0)
        foscam.set_ddns_config(enable=0)
        foscam.set_p2p_enable(enable=0)
        foscam.set_video_stream_param(0, 0, 2*1024*1024, 20, 20, 0)
        foscam.set_main_video_stream_type(0)
        try:
            if int(foscam.get_product_onvif_flag()[1]['onvifFlag']) == 1:
                foscam.enable_onvif_agent()
                foscam.set_port_info(web_port=88, media_port=88, https_port=443, onvif_port=888, rtsp_port=554)
        except Exception as e:
            logging.exception("Setting onvif failed : {}".format(str(e)))
    if args.name is not None:
        foscam.set_dev_name(args.name)
    if args.addacc:
        user, pwd, privilege = args.addacc
        foscam.add_account(user, pwd, privilege)
    if args.chpw:
        user, pwd = args.chpw
        foscam.change_password(user, args.password, pwd)
