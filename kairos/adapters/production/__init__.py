"""Production channels (Phase 3): FUSE driver, mitmproxy addon, vsock control.

Design-only until the simulation path lands its benchmark numbers. Each module
here implements EventSource/Effector against real OS channels; the core above
the abstraction is unchanged (4.2).
"""