#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from services.auth_service import NetEaseAuthService


class NetEaseEmailAuth(NetEaseAuthService):
    pass


if __name__ == '__main__':
    import json
    auth = NetEaseEmailAuth()
    print(json.dumps(auth.get_state_snapshot(), ensure_ascii=False, indent=2))
