"""Pair of real database identities and a mutable panel boundary for public delivery."""

import copy
import json

from app.database.models import SubscriptionPublicLink
from app.external.remnawave_api import RemnaWaveAPIError
from app.services.bs_public_link_tokens import hash_public_token, new_public_token, public_subscription_url
from tests.database.test_bs_subscription_delivery_postgres import FakePanel, seed


class PublicPanel(FakePanel):
    def __init__(self, subscription, account):
        super().__init__(subscription, account)
        self.users[1000].username = 'test-primary'
        self.revoked = []
        self.fail_before = set()
        self.lose_reply = set()
        self.no_op = set()
        self.fake_ack = set()
        self.formats = []
        self.html = False
        self.encrypted = []

    async def encrypt_happ_crypto_link(self, url):
        self.encrypted.append(url)
        return 'happ://crypt4/combined-new'

    async def get_public_subscription_response(self, short_uuid, *, headers, client_type=None):
        self.requests.append((short_uuid, headers))
        self.formats.append(client_type)
        user = next((u for u in self.users.values() if u.short_uuid == short_uuid), None)
        if user is None:
            return 404, '', {}
        hwid = headers.get('x-hwid')
        if hwid and self.auto_register:
            if (
                hwid not in self.devices[user.id]
                and user.hwid_device_limit
                and len(self.devices[user.id]) >= user.hwid_device_limit
            ):
                return 200, '', {'x-hwid-limit': 'true'}
            self.devices[user.id].add(hwid)
        if self.html:
            return 200, '<html>Primary-only import page</html>', {'content-type': 'text/html'}
        name = 'Ordinary' if user.id == 1000 else 'BS'
        address = 'ordinary.example' if user.id == 1000 else 'bs.example'
        body = f'vless://{user.vless_uuid}@{address}:443#{name}'
        content_type = 'text/plain'
        if client_type in ('json', 'v2ray-json'):
            body = json.dumps(
                [
                    {
                        'remarks': name,
                        'outbounds': [
                            {
                                'protocol': 'vless',
                                'settings': {
                                    'vnext': [{'address': address, 'users': [{'id': user.vless_uuid}]}],
                                },
                            }
                        ],
                    }
                ]
            )
            content_type = 'application/json'
        return (
            200,
            body,
            {
                'x-hwid-active': 'true',
                'content-type': content_type,
                'subscription-userinfo': f'download=42; total={user.traffic_limit_bytes}',
            },
        )

    async def revoke_user_subscription(self, panel_id, new_short_uuid=None, *, enrich_happ=True):
        assert enrich_happ is False  # Never encrypt or publish a direct BS URL.
        self.revoked.append((panel_id, new_short_uuid))
        if panel_id in self.fail_before:
            raise RemnaWaveAPIError('unavailable before key rotation')
        user = self.users[panel_id]
        if panel_id in self.no_op:
            return user
        target = copy.copy(user) if panel_id in self.fake_ack else user
        target.short_uuid = new_short_uuid
        target.vless_uuid = f'rotated-{new_short_uuid}'
        if panel_id in self.lose_reply:
            self.lose_reply.remove(panel_id)
            raise RemnaWaveAPIError('reply lost after key rotation')
        return target


async def seed_public(db, *, enabled=True):
    user, subscription, account, _ = await seed(db)
    token = new_public_token()
    link = SubscriptionPublicLink(
        subscription_id=subscription.id,
        token_hash=hash_public_token(token),
        enabled=enabled,
        primary_id=subscription.remnawave_id,
        primary_short_uuid=subscription.remnawave_short_uuid,
        secondary_id=account.remnawave_id,
        secondary_short_uuid=account.remnawave_short_uuid,
    )
    subscription.subscription_url = public_subscription_url(token)
    subscription.subscription_crypto_link = 'happ://crypt4/combined-test'
    db.add(link)
    await db.commit()
    return user, subscription, account, link, token, PublicPanel(subscription, account)
