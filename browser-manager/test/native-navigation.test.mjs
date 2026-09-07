import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

test('native Back reads retain one subscription through registration timeout and read errors', {
  skip: process.platform !== 'linux',
}, async () => {
  // No X display, actual accessibility bus, browser, or profile is involved. Exercise the
  // production Python reader's lifetime: last-client teardown caused Chrome's key-handler crash.
  const fixture = String.raw`
import runpy
import sys
from types import SimpleNamespace

counts = {'session': 0, 'bus': 0, 'register': 0, 'state': 0}
class Object:
    def __init__(self, kind):
        self.kind, self.object_path = kind, '/' + kind
    def GetAddress(self, **kwargs):
        return 'private-test-bus'
    def GetConnectionUnixProcessID(self, *args, **kwargs):
        return 42
    def GetChildren(self, **kwargs):
        return {'root': [('owned', '/app')], 'app': [('owned', '/frame')],
                'frame': [('owned', '/back')]}.get(self.kind, [])
    def RegisterEvent(self, event, properties, owner, **kwargs):
        assert event == 'window:activate' and owner == 'owned'
        counts['register'] += 1
        raise TimeoutError('Response lost after subscription was installed')
    def GetRoleName(self, **kwargs):
        return 'frame' if self.kind == 'frame' else 'push button'
    def GetAttributes(self, **kwargs):
        return {'class': 'BrowserRootView' if self.kind == 'frame' else 'BackForwardButton'}
    def GetState(self, **kwargs):
        if self.kind == 'frame':
            return [1 << 1]
        counts['state'] += 1
        if counts['state'] == 2:
            raise RuntimeError('Transient toolbar failure')
        return [(1 << 8) | (1 << 24)]
    def Get(self, *args, **kwargs):
        return 'Back'
class Bus:
    def get_object(self, name, path):
        return Object(path.rsplit('/', 1)[-1])
    def close(self):
        raise AssertionError('Read failure must never close the accessibility connection')
def session():
    counts['session'] += 1
    return Bus()
def connection(address):
    assert address == 'private-test-bus'
    counts['bus'] += 1
    return Bus()
sys.modules['dbus'] = SimpleNamespace(SessionBus=session,
    bus=SimpleNamespace(BusConnection=connection), Array=lambda value, **kwargs: value)
Reader = runpy.run_path(sys.argv[1])['NavigationReader']
reader = Reader(42)
assert reader.read() is None
retained_bus = reader.bus
assert reader.read() is True
assert reader.read() is None
assert reader.read() is True
assert reader.bus is retained_bus
assert counts == {'session': 1, 'bus': 1, 'register': 1, 'state': 3}, counts
assert Reader(43).read() is None
assert counts['register'] == 1, 'A different PID must never subscribe'
print('lifetime checks passed')
`;
  const { stdout } = await promisify(execFile)('/usr/bin/python3', [
    '-c', fixture, fileURLToPath(new URL('../lib/native-navigation.py', import.meta.url)),
  ], { timeout: 5000, maxBuffer: 16 * 1024 });
  assert.equal(stdout.trim(), 'lifetime checks passed');
});
