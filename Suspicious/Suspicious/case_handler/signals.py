# Intentionally empty.
#
# The previous on_case_created receiver incremented a Prometheus counter
# imported from api.metrics, which has been removed along with the in-app
# monitoring stack. Re-add a receiver here if/when a new metrics backend
# is introduced.
