#!/usr/bin/env python3
"""8.4.5.4-C.2 unit tests: offline, no broker, no secrets or credentials imported."""
from __future__ import annotations

import inspect
import json
import pathlib
import socket
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import fase8_4_5_4c2_clientes_mqtt as mod


def mapping():
    base = {**{user: set(v) for user, v in mod.p4b.audit1.LEGACY_BASE.items()},
            'device-sensor02': {'write lab/sensors/sensor02/#',
                                'read bus/sensors/sensor02/#'}}
    return mod.p4b.permissions(base)


def example_state():
    pol = mapping()
    roles = [{'rolename': 'admin-role', 'acls': []}]
    clients = [{'username': mod.p4b.ADMIN,
                'roles': [{'rolename': 'admin-role'}]}]
    for user in mod.ACCOUNTS:
        roles.append({'rolename': mod.p4b.role_name(user), 'acls': [
            {'acltype': acltype, 'topic': topic, 'allow': True, 'priority': 10}
            for acltype, topic in pol[user]]})
        client = {'username': user, 'disabled': False,
                  'roles': [{'rolename': mod.p4b.role_name(user)}]}
        if user in mod.ID_MAP:
            client['clientid'] = mod.ID_MAP[user]
        clients.append(client)
    return {'defaultACLAccess': {k: False for k in mod.p4b.DEFAULTS},
            'clients': clients, 'roles': roles, 'groups': []}


class Tests(unittest.TestCase):
    def validate(self, data):
        with patch.object(mod.p2, 'check_regular', return_value=json.dumps(data).encode()):
            mod.validate_preview(pathlib.Path('/unused'), mapping())

    def test_policy_lab_is_dynamic(self):
        self.assertEqual(mod.client_policy('lab'), 'cli-dinamico')

    def test_sensor_requires_fixed(self):
        self.assertEqual(mod.client_policy('device-sensor02'), 'id-vinculado')

    def test_bridge_pinned(self):
        self.assertEqual(mod.ID_MAP['bridge'], 'rust-server-bridge-local')

    def test_sensor_id_temporary(self):
        self.assertEqual(mod.ID_MAP['device-sensor02'], 'phase8454c2-sensor02')

    def test_no_real_credentials(self):
        self.assertFalse(any('password' in v for v in mod.ID_MAP.values()))

    def test_revoked_not_in_policy(self):
        self.assertNotIn('device-sensor01', mod.ACCOUNTS)

    def test_no_unknown_account(self):
        with self.assertRaises(mod.Block): mod.client_policy('device-sensor01')

    def test_bounded_loopback_port(self):
        self.assertEqual((mod.HOST, mod.PORT), ('127.0.0.1', 8895))

    def test_valid_state(self):
        self.validate(example_state())

    def test_lab_absent_id_valid(self):
        data = example_state(); data['clients'][1]['clientid'] = ''
        self.validate(data)

    def test_reject_lab_bound_id(self):
        data = example_state(); data['clients'][1]['clientid'] = 'lab-real'
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_sensor_missing_id(self):
        data = example_state(); data['clients'][3].pop('clientid')
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_sensor_wrong_id(self):
        data = example_state(); data['clients'][3]['clientid'] = 'sensor-real'
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_bridge_wrong_id(self):
        data = example_state(); data['clients'][2]['clientid'] = 'lab84-bridge'
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_default_allow(self):
        data = example_state(); data['defaultACLAccess']['subscribe'] = True
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_default_nonboolean(self):
        data = example_state(); data['defaultACLAccess']['subscribe'] = 0
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_default_extra(self):
        data = example_state(); data['defaultACLAccess']['unknown'] = False
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_admin_added(self):
        data = example_state(); data['clients'].append({'username': 'admin2'})
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_revoked(self):
        data = example_state(); data['clients'].append({'username': 'device-sensor01'})
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_lab_group(self):
        data = example_state(); data['clients'][1]['groups'] = [{'groupname': 'admin'}]
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_extra_group(self):
        data = example_state(); data['groups'] = [{'groupname': 'evil'}]
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_extra_role(self):
        data = example_state(); data['roles'].append({'rolename': 'super-admin', 'acls': []})
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_superadmin_on_sensor(self):
        data = example_state(); data['clients'][3]['roles'].append({'rolename': 'admin-role'})
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_wide_acl(self):
        data = example_state(); data['roles'][1]['acls'].append(
            {'acltype': 'subscribePattern', 'topic': '#', 'allow': True})
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_deny_mismatch(self):
        data = example_state(); data['roles'][3]['acls'][0]['allow'] = False
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_duplicate_acl(self):
        data = example_state(); data['roles'][1]['acls'].append(data['roles'][1]['acls'][0])
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_disabled(self):
        data = example_state(); data['clients'][1]['disabled'] = True
        with self.assertRaises(mod.Block): self.validate(data)

    def test_reject_malformed_json(self):
        with patch.object(mod.p2, 'check_regular', return_value=b'{'):
            with self.assertRaises(mod.Block): mod.validate_preview(pathlib.Path('/u'), mapping())

    def test_reject_incorrect_mapping(self):
        data = example_state()
        bad = mapping(); bad['bridge'] = tuple()
        with patch.object(mod.p2, 'check_regular', return_value=json.dumps(data).encode()):
            with self.assertRaises(mod.Block): mod.validate_preview(pathlib.Path('/u'), bad)

    def test_dyn_change_allowlist(self):
        with self.assertRaises(mod.Block):
            mod.dyn_change(pathlib.Path('/u'), 'deleteClient', 'lab')

    def test_dyn_change_blocks_bridge(self):
        with self.assertRaises(mod.Block):
            mod.dyn_change(pathlib.Path('/u'), 'disableClient', 'bridge')

    def test_dyn_change_blocks_revoked(self):
        with self.assertRaises(mod.Block):
            mod.dyn_change(pathlib.Path('/u'), 'enableClient', 'device-sensor01')

    def test_dyn_change_requires_password(self):
        with self.assertRaises(mod.Block):
            mod.dyn_change(pathlib.Path('/u'), 'setClientPassword', 'lab')

    def test_dyn_change_blocks_short_password(self):
        with self.assertRaises(mod.Block):
            mod.dyn_change(pathlib.Path('/u'), 'setClientPassword', 'lab', password='tiny')

    def test_dyn_change_blocks_newline(self):
        with self.assertRaises(mod.Block):
            mod.dyn_change(pathlib.Path('/u'), 'setClientPassword', 'lab', password='A'*63+'\n')

    def test_dyn_change_password_not_in_argv(self):
        with patch.object(mod.p4b, 'call') as call:
            secret = 'a' * 64
            mod.dyn_change(pathlib.Path('/u'), 'setClientPassword', 'lab', password=secret)
            args = call.call_args.args[0]
            self.assertNotIn(secret, args)
            self.assertEqual(call.call_args.kwargs['input_text'], secret+'\n'+secret+'\n')

    def test_dyn_change_disable(self):
        with patch.object(mod.p4b, 'call') as call:
            mod.dyn_change(pathlib.Path('/u'), 'disableClient', 'lab')
            self.assertEqual(call.call_args.args[0][-2:], ['disableClient', 'lab'])

    def test_dyn_change_enable(self):
        with patch.object(mod.p4b, 'call') as call:
            mod.dyn_change(pathlib.Path('/u'), 'enableClient', 'device-sensor02')
            self.assertEqual(call.call_args.args[0][-2:], ['enableClient', 'device-sensor02'])

    def test_no_password_when_disabling(self):
        with self.assertRaises(mod.Block):
            mod.dyn_change(pathlib.Path('/u'), 'disableClient', 'lab', password='a' * 64)

    def test_private_opts_permissions(self):
        with tempfile.TemporaryDirectory() as t:
            root = pathlib.Path(t)
            ca = root / 'ca.crt'
            path = mod.private_opts(root, ca, 'lab', 'a'*64, mod.LAB_IDS[0], 'lab-a')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIn(b'-i phase8454c2-cli-a', path.read_bytes())
            self.assertNotIn(b'8883', path.read_bytes())

    def test_private_opts_blocks_revoked(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(mod.Block):
                mod.private_opts(pathlib.Path(t), pathlib.Path('/ca'), 'device-sensor01',
                                 'a'*64, 'id', 'lab')

    def test_private_opts_blocks_bad_label(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(mod.Block):
                mod.private_opts(pathlib.Path(t), pathlib.Path('/ca'), 'lab',
                                 'a'*64, 'id', '../../secrets')

    def test_ping_session(self):
        tls = Mock()
        with patch.object(mod.p4b, 'read_packet', return_value=(0xd0, b'')):
            mod.ping_session(tls)
        tls.sendall.assert_called_once_with(b'\xc0\x00')

    def test_ping_session_wrong_packet(self):
        tls = Mock()
        with patch.object(mod.p4b, 'read_packet', return_value=(0x20, b'')):
            with self.assertRaises(mod.Block): mod.ping_session(tls)

    def test_session_kick_eof(self):
        tls = Mock(); tls.recv.return_value = b''
        mod.expect_session_kicked(tls)

    def test_session_kick_disconnect_packet(self):
        tls = Mock(); tls.recv.return_value = b'\xe0'
        mod.expect_session_kicked(tls)

    def test_session_kick_no_ack(self):
        tls = Mock(); tls.recv.return_value = b'\xd0'
        with self.assertRaises(mod.Block): mod.expect_session_kicked(tls)

    def test_session_kick_timeout_not_success(self):
        tls = Mock(); tls.recv.side_effect = socket.timeout()
        with self.assertRaises(mod.Block): mod.expect_session_kicked(tls)

    def test_session_kick_reset(self):
        tls = Mock(); tls.recv.side_effect = ConnectionResetError()
        mod.expect_session_kicked(tls)

    def test_preflight_requires_no_listener(self):
        with patch.object(mod.p4c, 'verify_branch'), \
             patch.object(mod.p4b, 'preflight', return_value=mapping()), \
             patch.object(mod.p3, 'available', return_value=True), \
             patch.object(mod.c1, 'listener_absent', return_value=False):
            with self.assertRaises(mod.Block):
                mod.preflight(*[pathlib.Path('/x')]*5)

    def test_preflight_valid(self):
        with patch.object(mod.p4c, 'verify_branch'), \
             patch.object(mod.p4b, 'preflight', return_value=mapping()), \
             patch.object(mod.p3, 'available', return_value=True), \
             patch.object(mod.c1, 'listener_absent', return_value=True):
            self.assertEqual(mod.preflight(*[pathlib.Path('/x')]*5), mapping())

    def test_no_8883_8884_controls(self):
        source = inspect.getsource(mod.run)
        self.assertIn('c1.broker_for_bridge(cfg, PORT)', source)
        self.assertIn('p3.probe_original()', source)
        self.assertIn('p2.verify(snapshot, plugin)', source)
        self.assertIn("if user != 'lab':", source)

    def test_no_snapshot_rewrite(self):
        source = inspect.getsource(mod.run)
        self.assertNotIn('phase2.restore(', source)
        self.assertNotIn('os.replace(', source)
        self.assertNotIn('git ', source)

    def test_inventory_static(self):
        with patch.object(mod.p2, 'check_regular', return_value=(
            b'MqttOptions::new("rust-server-bridge-local", "localhost", broker.port())'
            b'options.set_credentials("bridge", password)')):
            mod.inventory(pathlib.Path('/u'))

    def test_inventory_mutated_fails(self):
        with patch.object(mod.p2, 'check_regular', return_value=b'changed'):
            with self.assertRaises(mod.Block): mod.inventory(pathlib.Path('/u'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
