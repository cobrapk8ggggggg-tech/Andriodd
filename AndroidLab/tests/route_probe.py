"""CI-only deterministic origin; not present in the production worker image."""
def request(flow):
    if flow.request.host == 'zeus-probe.invalid' and flow.request.port == 8091:
        flow.request.host='127.0.0.1'
