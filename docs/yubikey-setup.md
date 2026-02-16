ssh-agent-guard uses YubiKey HMAC-Challenge slots for physical
confirmation of signing requests.  Two slots are used:

- **Slot 2** (default) — touch confirmation.  A fixed challenge is sent
  to the YubiKey; the user must physically touch the key to generate a
  response.  Used when a local display is active.
- **Slot 1** (default) — PIN confirmation.  The user's PIN is sent as
  the HMAC challenge; no touch required.  Used when no local display is
  active (remote sessions via tmux popup).

Slot numbers are configurable via the `confirm.touch.slot` and
`confirm.pin.slot` policy fields.  See ssh-agent-guard-policy(5).

### Linux permissions

`ykchalresp` and `ykinfo` communicate with the YubiKey over USB HID via
libusb.  This requires udev rules granting access to Yubico devices
(vendor ID 1050):

```bash
# NixOS (configuration.nix)
services.udev.packages = [ pkgs.yubikey-personalization ];

# Debian/Ubuntu
sudo apt install yubikey-personalization

# Manual udev rule
SUBSYSTEM=="usb", ATTRS{idVendor}=="1050", MODE="0660", GROUP="plugdev"
```

### Programming HMAC slots

Use `ykman` to program the HMAC-Challenge slots:

```bash
# Slot 2: touch confirmation (requires physical touch)
ykman otp chalresp --touch --generate 2

# Slot 1: PIN confirmation (no touch, responds immediately)
ykman otp chalresp --generate 1
```

### Registering the expected response

After programming the slots, generate and store the expected HMAC
response so the guard can verify the YubiKey's identity:

```bash
# Get YubiKey serial number
SERIAL=$(ykinfo -s | grep -o '[0-9]*')

# Generate expected response for slot 2 (touch — tap the key)
# Uses the challenge from your policy (default: "deadbeef")
RESPONSE=$(ykchalresp -2 deadbeef)

# Store it
mkdir -p ~/.local/state/ssh-ag/confirm
echo "$RESPONSE" > ~/.local/state/ssh-ag/confirm/${SERIAL}.response
```

For PIN confirmation (slot 1), response files use different naming;
the `ssh-ag-confirm` script handles this automatically.

The challenge string and slot numbers are configurable in the policy
file's `confirm:` section.  See ssh-agent-guard-policy(5).
