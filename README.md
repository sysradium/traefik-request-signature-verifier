# Request Signature Generation in Traefik Plugin

This plugin ensures that incoming requests to Traefik are authenticated based on a signature generated using specific request parameters. The signature is crucial for verifying the integrity and authenticity of each request.

## How Signature is Generated

The signature is generated using the following steps:

1. **Select Data Based on HTTP Method:**
   - For `GET`, `HEAD`, and `DELETE` requests:
     - The signature is calculated using the raw query parameters from the URL (`r.URL.RawQuery`).
   - For `POST` and `PUT` requests:
     - The signature includes the body of the request. The body is read and drained, and its content is used in the calculation.

2. **Initialize Hashing Algorithm:**
   - SHA-256 hashing algorithm (`sha256.New()`) is used to compute the hash of the data.

3. **Append Secret Key:**
   - A secret key (`v.secretKey()`) is appended to the hash. This ensures that the signature is dependent on a secret known only to the server.

4. **Include Selected Headers:**
   - For each header specified in the configuration (`headers`):
     - The value of the header from the incoming request (`r.Header.Get(h)`) is added to the hash.

5. **Add Data:**
   - The selected data (query string or request body) is added to the hash.

6. **Generate Hexadecimal Representation:**
   - Finally, the computed hash is converted to a hexadecimal string (`%x` format) to produce the signature.

## Configuration Parameters

The plugin can be configured using the following parameters:

```yaml
headers:
  - X-Date
  - Authorization
  - APP-ID
secretKey: "test"
```

- **headers:** A list of headers whose values will be included in the signature calculation. These headers should be critical for identifying the request and ensuring its integrity.
  
- **secretKey:** A secret key appended to the hash during signature calculation. This key ensures that only requests from parties knowing this secret can generate valid signatures.
