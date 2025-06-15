This lightweight webhook is used to forward Splunk alerts from the container to the VM host. It's part of the alert actions in Splunk, allowing external systems (like my SOAR tool) to act on triggered events.

The webhook.py script runs directly on the host machine (not inside the Docker container), listening on port 8080.

Inside Splunk (running in Docker), each alert sends an HTTP POST request to http://172.17.0.1:8080 — which routes to the host via Docker's default gateway.

This setup allows alerts to be forwarded securely from within the container without exposing the webhook to the broader network.

This method keeps things simple, isolated within the LAN, and avoids opening additional public ports.