Cloud Run Proxy (Node.js)
This Node.js script acts as a local HTTP proxy that securely forwards requests to a Google Cloud Run service, automatically handling OpenID Connect (OIDC) token authentication. It's designed to simplify local development and testing with Cloud Run services that require OIDC-authenticated access.

Features
OIDC Token Management: Automatically fetches and refreshes OIDC identity tokens using Google's Application Default Credentials (ADC).

Transparent Proxying: Forwards incoming HTTP requests to your specified Cloud Run service URL.

Header Propagation: Copies most headers from the client's request to the Cloud Run service, ensuring proper request context.

Host Header Override: Correctly sets the Host header for the Cloud Run service.

Custom Authorization Header: Allows specifying a custom header name for the OIDC bearer token, useful for services that expect a different header than Authorization.

User-Agent Customization: Prepends a custom User-Agent string to outgoing requests.

Redirect Handling: Rewrites Location headers in redirects to point back to the local proxy address.

Graceful Shutdown: Handles SIGINT and SIGTERM signals for clean server termination.

Prerequisites
Before you can use this proxy, you'll need:

Node.js (v14 or higher): Ensure Node.js is installed on your system.

Google Cloud SDK (gcloud): Install and configure the Google Cloud SDK.

Authenticated gcloud CLI: Your gcloud CLI must be authenticated with credentials that have permission to create OIDC tokens for your Cloud Run service.

Run gcloud auth application-default login to set up Application Default Credentials. This proxy relies on these credentials to obtain the necessary OIDC tokens.

Access to a Cloud Run Service: You need the URL of a deployed Cloud Run service configured to require authentication.

Installation
Clone the repository (or copy the files):

git clone [https://github.com/your-repo/cloud-run-oidc-proxy-node.git](https://github.com/your-repo/cloud-run-oidc-proxy-node.git)
cd cloud-run-oidc-proxy-node

(Replace your-repo with your actual repository details if applicable)

Install dependencies:

npm install

Usage
Run the proxy script from your terminal:

node cloud-run-oidc-proxy.js --host <CLOUD_RUN_SERVICE_URL> [options]

Arguments and Options
--host <CLOUD_RUN_SERVICE_URL> (Required):
The full URL of your Cloud Run service (e.g., https://your-service-xxxx.run.app). This URL is also used as the audience (aud) for the OIDC token.

--bind <host:port> (Optional):
The local address and port on which the proxy server will listen.

Default: 127.0.0.1:8080

Example: --bind 0.0.0.0:3000 (to listen on all interfaces on port 3000)

--prepend-user-agent (Optional):
If present, the proxy will prepend its own User-Agent string (cloud-run-oidc-proxy-nodejs/1.0.0) to any existing User-Agent header from the client.

Default: true (if flag is present) / false (if flag is omitted or --no-prepend-user-agent is used)

--no-prepend-user-agent (Optional):
Explicitly disables the prepending of the proxy's User-Agent string.

--authorization-header <header-name> (Optional):
Specifies the name of the HTTP header to use for sending the Bearer OIDC token to the Cloud Run service.

Default: X-Serverless-Authorization (matches the Go Cloud Run Proxy behavior)

Example: --authorization-header Authorization (to use the standard Authorization header)

Examples
Basic Usage:
Proxy requests from http://127.0.0.1:8080 to your Cloud Run service at https://my-service-xxxx.run.app.

node cloud-run-oidc-proxy.js --host [https://my-service-xxxx.run.app](https://my-service-xxxx.run.app)

Custom Bind Address:
Proxy requests from http://localhost:3000.

node cloud-run-oidc-proxy.js --host [https://my-service-xxxx.run.app](https://my-service-xxxx.run.app) --bind 127.0.0.1:3000

Using Standard Authorization Header:
If your Cloud Run service expects the token in the Authorization header.

node cloud-run-oidc-proxy.js --host [https://my-service-xxxx.run.app](https://my-service-xxxx.run.app) --authorization-header Authorization

After starting the proxy, you can make requests to http://<your-bind-address>:<your-bind-port> (e.g., http://127.0.0.1:8080/my-endpoint), and the proxy will handle the authentication and forwarding to your Cloud Run service.

Authentication
This proxy leverages the google-auth-library to obtain OIDC tokens. It primarily relies on Google Application Default Credentials (ADC). This means:

It will automatically look for credentials in your environment.

The most common way to set this up locally is by running gcloud auth application-default login.

Ensure the authenticated principal has the roles/run.viewer role (or equivalent custom role) on the Cloud Run service, and the Service Account Token Creator role if your Cloud Run service is configured to use a specific service account that requires token creation permissions.
