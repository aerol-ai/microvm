# v1 path-prefix constant for the Python SDK. Mirrors the prefix exported by
# pkg/api/v1/dto.go::PathPrefix on the server. When a new wire version
# lands, a sibling microvm/_internal/api/vN/paths.py will export its own
# PATH_PREFIX, and the MicroVM(api_version=...) option selects which one to
# use.
PATH_PREFIX = "/v1"
