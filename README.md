Cloud Run Node Proxy
This Node.js script acts as a lightweight proxy for invoking IAM-protected Google Cloud Run services. It automatically handles OIDC (OpenID Connect) token generation and refreshing using your gcloud application default credentials or a service account, ensuring secure communication with your Cloud Run services without needing to manually manage authentication tokens.

The proxy reads a request payload from its standard input (stdin), forwards it to the specified Cloud Run service with the necessary OIDC Authorization header, and then writes the service's response to its standard output (stdout). Error messages and debugging information are printed to standard error (stderr).

Features
Automatic OIDC Token Management: Fetches and refreshes OIDC tokens transparently.

Secure Invocation: Adds a Bearer token to the Authorization header for IAM-protected Cloud Run services.

Simple Interface: Reads from stdin and writes to stdout, making it easy to integrate with other command-line tools or scripts.

Error Handling: Provides informative error messages for authentication failures or network issues.

Prerequisites
Before using this proxy, ensure you have the following installed:

Node.js: Version 14 or higher is recommended.

npm (Node Package Manager): Usually comes bundled with Node.js.

Google Cloud SDK (gcloud): Used for fetching application default credentials.

Authenticate your gcloud CLI:

gcloud auth application-default login


Alternatively, you can set the GOOGLE_APPLICATION_CREDENTIALS environment variable to the path of a service account key file.

Installation
Save the script: Save the provided Node.js code into a file named cloud-run-oidc-proxy.js.

Install dependencies: Navigate to the directory where you saved cloud-run-oidc-proxy.js in your terminal and install the required Node.js package:

npm install google-auth-library


Usage
The proxy expects the target Cloud Run service URL as its first command-line argument. It reads your raw request body in JSON format from its standard input (stdin). Once stdin is closed (e.g., after a pipe sends all its data), it will send the accumulated data as a POST request to your Cloud Run service, setting the Content-Type header to application/json.

node cloud-run-oidc-proxy.js <YOUR_CLOUD_RUN_SERVICE_URL>


Example
This proxy is versatile and can be used with various Cloud Run services. As an example, let's consider a service deployed at https://my-tool-service-abcdefgh-uc.a.run.app that expects a JSON payload and returns a JSON response. Note that the proxy currently sends requests with a Content-Type of application/json.

You can invoke it by piping your JSON request body to it, like this:

echo '{"query": "What is the weather today?"}' | node cloud-run-oidc-proxy.js https://my-tool-service-abcdefgh-uc.a.run.app


Explanation:

echo '{"query": "What is the weather today?"}': This command outputs your JSON request body string to stdout.

|: This is a pipe, which takes the stdout of the echo command and feeds it into the stdin of the node command.

node cloud-run-oidc-proxy.js https://my-tool-service-abcdefgh-uc.a.run.app: This executes the proxy script, telling it to forward the stdin content to your Cloud Run service URL.

The proxy will then:

Fetch an OIDC token using your active gcloud credentials.

Create a POST request to https://my-tool-service-abcdefgh-uc.a.run.app.

Add the Authorization: Bearer <OIDC_TOKEN> header.

Set the Content-Type: application/json header.

Send the {"query": "What is the weather today?"} as the request body.

Receive the response from your Cloud Run service.

Print the service's response to your console (stdout).

Debugging
The proxy prints status messages and errors to stderr. You can redirect stderr to a file if you want to inspect them without cluttering your main output:

echo '{"data": "some_input"}' | node cloud-run-oidc-proxy.js https://your-service-url 2> proxy_debug.log


This will put the Cloud Run service's response on your console, and all proxy-related debug messages in proxy_debug.log.

Error Handling
If the proxy encounters an error (e.g., unable to fetch a token, network issues, or malformed JSON from Cloud Run), it will print an error message to stderr and typically exit with a non-zero status code. In some cases, it will also print a structured JSON error to stdout to signal an issue to the calling client.

Customizing Content Type
By default, the proxy sends requests with the Content-Type of application/json header. If your Cloud Run service expects a different content type (e.g., text/plain, application/xml), you will need to modify the requestOptions.headers object within the startProxy function in the cloud-run-oidc-proxy.js script to reflect the correct Content-Type for your service