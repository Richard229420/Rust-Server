#!/usr/bin/env python3
"""Testes unitarios sem broker e sem efeitos nas credenciais reais."""
from __future__ import annotations
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fase8_4_4_online as phase


class DummySocket:
    def __init__(self, data):
        self.data = bytearray(data)
        self.sent = []
        self.closed = False
    def recv(self, n):
        response = self.data[:n]
        del self.data[:n]
        return bytes(response)
    def sendall(self, data):
        self.sent.append(data)
    def settimeout(self, t):
        pass
    def close(self):
        self.closed = True


class Tests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='fase844-offline-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.base = self.home / 'settings'
        self.base.mkdir(mode=0o700)
        self.root = self.base / 'phase8-4-2-lab'
        self.root.mkdir(mode=0o700)
        for d in ('clients', 'pki'):
            (self.root / d).mkdir(mode=0o700)
        for module in (phase, phase.lab):
            p = mock.patch.object(module, 'ROOT', self.root)
            p.start()
            self.addCleanup(p.stop)
        for username, (_, clientid) in phase.lab.CLIENTS.items():
            phase.lab.safe_write(self.root / 'clients' / (username + '.opts'),
                                 phase.lab.secure_client_options(username, clientid, 'mock-secret-123'))

    def opts(self):
        return phase.load_options(phase.USERNAME)

    def test_opcoes_privadas_validas(self):
        values = self.opts()
        self.assertEqual(values['-u'], phase.USERNAME)
        self.assertEqual(values['-p'], '8884')

    def test_rejeita_porta_errada(self):
        path = self.root / 'clients' / (phase.USERNAME + '.opts')
        path.write_text(path.read_text().replace('-p 8884', '-p 8883'))
        with self.assertRaises(phase.Failure):
            self.opts()

    def test_rejeita_symlink_e_permissoes(self):
        path = self.root / 'clients' / (phase.USERNAME + '.opts')
        path.chmod(0o644)
        with self.assertRaises(phase.lab.Abort):
            self.opts()
        path.chmod(0o600)
        path.rename(path.with_suffix('.orig'))
        path.symlink_to(path.with_suffix('.orig'))
        with self.assertRaises(phase.lab.Abort):
            self.opts()

    def test_rejeita_username_alheio(self):
        path = self.root / 'clients' / (phase.USERNAME + '.opts')
        path.write_text(path.read_text().replace('-u device-sensor01', '-u device-sensor02'))
        with self.assertRaises(phase.Failure):
            self.opts()

    def test_encode_lengths(self):
        self.assertEqual(phase.encode_length(0), b'\x00')
        self.assertEqual(phase.encode_length(127), b'\x7f')
        self.assertEqual(phase.encode_length(128), b'\x80\x01')
        with self.assertRaises(phase.Failure):
            phase.encode_length(-1)

    def test_packet_connect_without_password_in_argv(self):
        options = self.opts()
        plain = DummySocket(b'')
        tls = DummySocket(b'\x20\x02\x00\x00')
        context = mock.Mock()
        context.wrap_socket.return_value = tls
        with mock.patch.object(phase.socket, 'create_connection', return_value=plain), \
             mock.patch.object(phase.ssl, 'create_default_context', return_value=context):
            self.assertIs(phase.connect_mqtt(options), tls)
        sent = b''.join(tls.sent)
        self.assertIn(b'lab84-sensor01', sent)
        self.assertIn(b'device-sensor01', sent)
        self.assertTrue(context.check_hostname)
        context.wrap_socket.assert_called_once_with(plain, server_hostname='localhost')

    def test_rejeicao_so_com_connack_explicito(self):
        options = self.opts()
        for data, accepted in ((b'\x20\x02\x00\x05', True),
                               (b'\x20\x02\x00\x00', False),
                               (b'', False)):
            with self.subTest(data=data):
                plain = DummySocket(b'')
                tls = DummySocket(data)
                context = mock.Mock(wrap_socket=mock.Mock(return_value=tls))
                with mock.patch.object(phase.socket, 'create_connection', return_value=plain), \
                     mock.patch.object(phase.ssl, 'create_default_context', return_value=context):
                    if accepted:
                        self.assertIsNone(phase.connect_mqtt(options, allowed=False))
                    else:
                        with self.assertRaises(phase.Failure):
                            phase.connect_mqtt(options, allowed=False)

    def test_marcador_privado_nao_repetivel(self):
        self.assertIsNone(phase.read_state())
        phase.write_state('prepared')
        path = phase.state_file()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(phase.read_state(), 'prepared')
        phase.write_state('completed')
        self.assertEqual(phase.read_state(), 'completed')
        self.assertNotIn('password', path.read_text())

    def test_marcador_malformado(self):
        phase.lab.safe_write(phase.state_file(), json.dumps({'phase': '8.4.4', 'port': 8883}))
        with self.assertRaises(phase.Failure):
            phase.read_state()

    def test_senha_de_rotacao_nao_em_argv(self):
        ctrl = self.root / 'admin.opts'
        phase.lab.safe_write(ctrl, 'mock-admin')
        proc = mock.Mock(returncode=0, stdout='ok', stderr='')
        with mock.patch.object(phase.subprocess, 'run', return_value=proc) as call:
            phase.run_control(ctrl, 'setClientPassword', phase.USERNAME, input_text='NEW\nNEW\n')
        argv = call.call_args.args[0]
        self.assertNotIn('NEW', ' '.join(argv))
        self.assertEqual(call.call_args.kwargs['input'], 'NEW\nNEW\n')
        self.assertIn('-o', argv)

    def test_senha_pendente_privada(self):
        path = phase.pending_options('mock-new-secret')
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertIn('mock-new-secret', path.read_text())
        self.assertNotIn('8883', path.read_text())

    def test_snapshot_privado_antes_de_mutacoes(self):
        phase.lab.safe_write(self.root / 'dynamic-security.json', '{"clients": []}')
        dest = phase.snapshot_lab()
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o700)
        self.assertEqual(len(list(dest.iterdir())), 4)
        for item in dest.iterdir():
            self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o600)
        with self.assertRaises(phase.Failure):
            phase.snapshot_lab()

    def test_snapshot_rejeita_estado_malformado(self):
        phase.lab.safe_write(self.root / 'dynamic-security.json', 'broken-json')
        with self.assertRaises(ValueError):
            phase.snapshot_lab()
        self.assertFalse((self.root / 'backup-fase8-4-4').exists())

    def test_publicacao_e_entrega_qos1(self):
        pub = DummySocket(b'\x40\x02\x00\x09')
        topic = 'lab/sensors/sensor02/telemetry'
        body = phase.mqtt_utf8(topic) + b'data-payload'
        sub = DummySocket(phase.packet(0x30, body))
        phase.publish_qos1(pub, sub, 'data-payload')
        self.assertTrue(pub.sent)


if __name__ == '__main__':
    unittest.main(verbosity=2)
