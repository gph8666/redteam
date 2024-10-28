from evdev import InputDevice, ecodes
import os

# Iterate through all /dev/input/eventX devices
for device_path in os.listdir('/dev/input/'):
    if 'event' in device_path:
        try:
            device = InputDevice(f'/dev/input/{device_path}')
            print(f"Testing device: {device.name} at /dev/input/{device_path}")
            for event in device.read_loop():
                if event.type == ecodes.EV_KEY:
                    print(f"Detected key event from {device_path}")
                    break  # Stop after detecting a valid key event
        except OSError:
            pass  # Skip if device can't be opened
