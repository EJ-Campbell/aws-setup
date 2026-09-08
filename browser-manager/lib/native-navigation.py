"""Read one owned Chromium toolbar; never inspect web documents or perform UI actions."""
import json
import sys

import dbus

ACCESSIBLE = 'org.a11y.atspi.Accessible'
PROPERTIES = 'org.freedesktop.DBus.Properties'
NATIVE_CONTAINERS = {
    'BrowserRootView', 'NonClientView', 'BrowserFrameViewLinux',
    'BrowserView', 'TopContainerView', 'ToolbarView',
}


def navigation(pid, bus, subscriptions):
    daemon = bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
    root = bus.get_object('org.a11y.atspi.Registry', '/org/a11y/atspi/accessible/root')
    applications = []
    for name, path in root.GetChildren(dbus_interface=ACCESSIBLE, timeout=.3):
        owner = daemon.GetConnectionUnixProcessID(name, dbus_interface='org.freedesktop.DBus', timeout=.3)
        if int(owner) == pid:
            applications.append((str(name), str(path)))
    if len(applications) != 1:
        return None
    name, path = applications[0]
    registry = bus.get_object('org.a11y.atspi.Registry', '/org/a11y/atspi/registry')
    # Chromium defers active-window state until a reader subscribes. Keep this connection alive:
    # last-client teardown can erase Chromium's key-listener iterator during a re-entrant key event.
    if name not in subscriptions:
        # RegisterEvent is not idempotent; a timeout may still have installed the subscription.
        subscriptions.add(name)
        registry.RegisterEvent('window:activate', dbus.Array([], signature='s'), name,
                               dbus_interface='org.a11y.atspi.Registry', timeout=.3)
    app = bus.get_object(name, path)
    frames = []
    for child, subpath in app.GetChildren(dbus_interface=ACCESSIBLE, timeout=.3):
        obj = bus.get_object(str(child), str(subpath))
        if obj.GetRoleName(dbus_interface=ACCESSIBLE, timeout=.3) != 'frame':
            continue
        if obj.GetAttributes(dbus_interface=ACCESSIBLE, timeout=.3).get('class') != 'BrowserRootView':
            continue
        if int(obj.GetState(dbus_interface=ACCESSIBLE, timeout=.3)[0]) & (1 << 1):
            frames.append(obj)
    if len(frames) != 1:
        return None
    queue, visited, buttons = [frames[0]], set(), []
    while queue and len(visited) < 64:
        obj = queue.pop(0)
        if obj.object_path in visited:
            continue
        visited.add(obj.object_path)
        kind = str(obj.GetAttributes(dbus_interface=ACCESSIBLE, timeout=.3).get('class', ''))
        if kind == 'BackForwardButton':
            label = obj.Get(ACCESSIBLE, 'Name', dbus_interface=PROPERTIES, timeout=.3)
            if label == 'Back' and obj.GetRoleName(dbus_interface=ACCESSIBLE, timeout=.3) == 'push button':
                state = int(obj.GetState(dbus_interface=ACCESSIBLE, timeout=.3)[0])
                buttons.append(bool(state & (1 << 8) and state & (1 << 24)))  # ENABLED and SENSITIVE
        if kind in NATIVE_CONTAINERS:
            for child, subpath in obj.GetChildren(dbus_interface=ACCESSIBLE, timeout=.3):
                queue.append(bus.get_object(str(child), str(subpath)))
    # Never accept a partial or ambiguous tree. Changed Chrome UI/localization remains unknown.
    return buttons[0] if not queue and len(buttons) == 1 else None


class NavigationReader:
    """Own one bus connection until the parent stops it after Chromium exits."""

    def __init__(self, pid):
        self.pid = pid
        self.session = None
        self.bus = None
        self.subscriptions = set()

    def read(self):
        try:
            if self.session is None:
                self.session = dbus.SessionBus()
            if self.bus is None:
                launcher = self.session.get_object('org.a11y.Bus', '/org/a11y/bus')
                address = launcher.GetAddress(dbus_interface='org.a11y.Bus', timeout=.3)
                self.bus = dbus.bus.BusConnection(str(address))
            return navigation(self.pid, self.bus, self.subscriptions)
        except Exception:
            # Ordinary metadata failures must never close or replace a subscribed connection.
            return None


if __name__ == '__main__':
    reader = NavigationReader(int(sys.argv[1]))
    for request in sys.stdin:
        result = reader.read() if request == 'read\n' else None
        print(json.dumps({'canGoBack': result}), flush=True)
