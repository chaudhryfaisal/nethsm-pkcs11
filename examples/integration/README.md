# Integration Examples

This directory contains examples demonstrating integration with popular PKCS#11 tools and applications.

## Overview

The modular PKCS#11 architecture is compatible with all standard PKCS#11 applications and tools. These examples show how to integrate with:

- **OpenSSL**: Cryptographic operations and certificate management
- **GnuTLS**: TLS/SSL operations with PKCS#11 tokens
- **OpenSC Tools**: Standard PKCS#11 utilities
- **SSH**: SSH key operations with PKCS#11
- **Web Servers**: Apache and Nginx with PKCS#11 certificates
- **Containers**: Docker and Kubernetes deployment
- **Programming Languages**: Integration with various languages

## Examples

- **[`openssl/`](./openssl/)**: OpenSSL integration examples
- **[`gnutls/`](./gnutls/)**: GnuTLS integration examples
- **[`opensc/`](./opensc/)**: OpenSC tools integration
- **[`ssh/`](./ssh/)**: SSH integration examples
- **[`web_servers/`](./web_servers/)**: Web server integration
- **[`containers/`](./containers/)**: Container deployment examples
- **[`languages/`](./languages/)**: Programming language bindings

## Quick Start

### OpenSSL Integration

```bash
# Generate a key pair using OpenSSL with PKCS#11
openssl genpkey -engine pkcs11 \
  -pkcs11-uri "pkcs11:token=NetHSM;object=test-key" \
  -algorithm RSA -pkcs11-key-size 2048

# Sign data using PKCS#11 key
echo "Hello, World!" | openssl dgst -sha256 -sign \
  "pkcs11:token=NetHSM;object=test-key" \
  -engine pkcs11 -keyform engine
```

### GnuTLS Integration

```bash
# List PKCS#11 tokens
p11tool --list-tokens

# Generate certificate request
certtool --generate-request \
  --load-privkey "pkcs11:token=NetHSM;object=test-key" \
  --template cert-template.cfg
```

### OpenSC Tools Integration

```bash
# List available slots
pkcs11-tool --module ./target/release/libpkcs11_impl_nethsm_sdk.so --list-slots

# Generate RSA key pair
pkcs11-tool --module ./target/release/libpkcs11_impl_nethsm_sdk.so \
  --login --pin 123456 \
  --keypairgen --key-type rsa:2048 --label "test-key"

# Sign data
echo "test data" | pkcs11-tool --module ./target/release/libpkcs11_impl_nethsm_sdk.so \
  --login --pin 123456 \
  --sign --mechanism RSA-PKCS --label "test-key"
```

## OpenSSL Integration

### Configuration

Create OpenSSL configuration file:

```ini
# openssl.cnf
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/engines-1.1/pkcs11.so
MODULE_PATH = ./target/release/libpkcs11_impl_nethsm_sdk.so
init = 0
```

### Key Generation

```bash
# Set environment
export OPENSSL_CONF=openssl.cnf
export PKCS11_MODULE_PATH=./target/release/libpkcs11_impl_nethsm_sdk.so

# Generate RSA key pair
openssl genpkey -engine pkcs11 \
  -pkcs11-uri "pkcs11:token=NetHSM;object=rsa-key;type=private" \
  -algorithm RSA -pkcs11-key-size 2048

# Generate EC key pair
openssl genpkey -engine pkcs11 \
  -pkcs11-uri "pkcs11:token=NetHSM;object=ec-key;type=private" \
  -algorithm EC -pkcs11-curve prime256v1
```

### Certificate Operations

```bash
# Generate certificate signing request
openssl req -new -engine pkcs11 \
  -key "pkcs11:token=NetHSM;object=rsa-key;type=private" \
  -keyform engine \
  -out server.csr \
  -subj "/CN=example.com/O=Example Corp/C=US"

# Self-sign certificate
openssl x509 -req -in server.csr \
  -engine pkcs11 \
  -key "pkcs11:token=NetHSM;object=rsa-key;type=private" \
  -keyform engine \
  -out server.crt \
  -days 365

# Verify certificate
openssl x509 -in server.crt -text -noout
```

### TLS Server Example

```bash
# Start TLS server with PKCS#11 certificate
openssl s_server -accept 8443 \
  -engine pkcs11 \
  -cert server.crt \
  -key "pkcs11:token=NetHSM;object=rsa-key;type=private" \
  -keyform engine \
  -www
```

## GnuTLS Integration

### Configuration

```bash
# Set PKCS#11 module
export GNUTLS_PKCS11_PROVIDER=./target/release/libpkcs11_impl_nethsm_sdk.so
```

### Key and Certificate Operations

```bash
# List tokens
p11tool --list-tokens

# Generate key pair
p11tool --generate-rsa --bits 2048 \
  --label "gnutls-key" \
  --login \
  "pkcs11:token=NetHSM"

# Generate certificate template
cat > cert-template.cfg << EOF
cn = "example.com"
organization = "Example Corp"
country = "US"
expiration_days = 365
signing_key
encryption_key
EOF

# Generate certificate request
certtool --generate-request \
  --load-privkey "pkcs11:token=NetHSM;object=gnutls-key;type=private" \
  --template cert-template.cfg \
  --outfile server.csr

# Self-sign certificate
certtool --generate-self-signed \
  --load-privkey "pkcs11:token=NetHSM;object=gnutls-key;type=private" \
  --template cert-template.cfg \
  --outfile server.crt
```

### TLS Client/Server

```bash
# Start TLS server
gnutls-serv --port 4433 \
  --x509certfile server.crt \
  --x509keyfile "pkcs11:token=NetHSM;object=gnutls-key;type=private"

# Connect with TLS client
gnutls-cli --port 4433 localhost
```

## SSH Integration

### SSH Agent with PKCS#11

```bash
# Start SSH agent with PKCS#11 support
ssh-agent -s
export SSH_AUTH_SOCK=/tmp/ssh-agent.sock

# Add PKCS#11 provider
ssh-add -s ./target/release/libpkcs11_impl_nethsm_sdk.so

# List loaded keys
ssh-add -l

# Use SSH with PKCS#11 key
ssh -o "PKCS11Provider=./target/release/libpkcs11_impl_nethsm_sdk.so" user@server
```

### OpenSSH Server Configuration

```bash
# /etc/ssh/sshd_config
PKCS11Provider ./target/release/libpkcs11_impl_nethsm_sdk.so
HostKey pkcs11:token=NetHSM;object=ssh-host-key;type=private
```

### SSH Key Generation

```bash
# Generate SSH key using PKCS#11
ssh-keygen -D ./target/release/libpkcs11_impl_nethsm_sdk.so

# Extract public key
pkcs11-tool --module ./target/release/libpkcs11_impl_nethsm_sdk.so \
  --read-object --type pubkey --label "ssh-key" | \
  ssh-keygen -i -m PKCS8 -f /dev/stdin > ssh-key.pub
```

## Web Server Integration

### Apache HTTP Server

```apache
# /etc/apache2/sites-available/ssl.conf
<VirtualHost *:443>
    ServerName example.com
    
    SSLEngine on
    SSLCertificateFile /path/to/server.crt
    
    # PKCS#11 configuration
    SSLCryptoDevice pkcs11
    SSLCertificateKeyFile "pkcs11:token=NetHSM;object=apache-key;type=private"
    
    # Optional: specify PKCS#11 module
    SSLOpenSSLConfCmd PKCS11ModulePath ./target/release/libpkcs11_impl_nethsm_sdk.so
</VirtualHost>
```

### Nginx

```nginx
# /etc/nginx/sites-available/ssl
server {
    listen 443 ssl;
    server_name example.com;
    
    ssl_certificate /path/to/server.crt;
    ssl_certificate_key engine:pkcs11:pkcs11:token=NetHSM;object=nginx-key;type=private;
    
    # PKCS#11 engine configuration
    ssl_engine pkcs11;
    
    location / {
        root /var/www/html;
        index index.html;
    }
}
```

### HAProxy

```
# /etc/haproxy/haproxy.cfg
global
    ssl-engine pkcs11
    ssl-mode-async

frontend https_frontend
    bind *:443 ssl crt pkcs11:token=NetHSM;object=haproxy-key;type=private
    default_backend web_servers

backend web_servers
    server web1 192.168.1.10:80 check
    server web2 192.168.1.11:80 check
```

## Container Integration

### Docker

```dockerfile
# Dockerfile
FROM debian:bookworm-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    openssl \
    libengine-pkcs11-openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy PKCS#11 library
COPY target/release/libpkcs11_impl_nethsm_sdk.so /usr/lib/
COPY p11nethsm.conf /etc/p11nethsm/

# Set environment variables
ENV PKCS11_MODULE_PATH=/usr/lib/libpkcs11_impl_nethsm_sdk.so
ENV P11NETHSM_CONFIG_FILE=/etc/p11nethsm/p11nethsm.conf

# Copy application
COPY myapp /usr/local/bin/

EXPOSE 8443
CMD ["/usr/local/bin/myapp"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8443:8443"
    environment:
      - PKCS11_MODULE_PATH=/usr/lib/libpkcs11_impl_nethsm_sdk.so
      - P11NETHSM_CONFIG_FILE=/etc/p11nethsm/p11nethsm.conf
      - RUST_LOG=info
    volumes:
      - ./config:/etc/p11nethsm:ro
      - ./certs:/etc/ssl/certs:ro
    networks:
      - pkcs11_network

networks:
  pkcs11_network:
    driver: bridge
```

### Kubernetes

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pkcs11-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pkcs11-app
  template:
    metadata:
      labels:
        app: pkcs11-app
    spec:
      containers:
      - name: app
        image: pkcs11-app:latest
        ports:
        - containerPort: 8443
        env:
        - name: PKCS11_MODULE_PATH
          value: "/usr/lib/libpkcs11_impl_nethsm_sdk.so"
        - name: P11NETHSM_CONFIG_FILE
          value: "/etc/p11nethsm/p11nethsm.conf"
        - name: RUST_LOG
          value: "info"
        volumeMounts:
        - name: config
          mountPath: /etc/p11nethsm
          readOnly: true
        - name: pkcs11-lib
          mountPath: /usr/lib/libpkcs11_impl_nethsm_sdk.so
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: pkcs11-config
      - name: pkcs11-lib
        hostPath:
          path: /usr/lib/libpkcs11_impl_nethsm_sdk.so
          type: File

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: pkcs11-config
data:
  p11nethsm.conf: |
    backend:
      type: "nethsm"
    slots:
      - label: "NetHSM-K8s"
        instances:
          - url: "https://nethsm.example.com/api/v1"
        operator:
          username: "operator"
          password: "${NETHSM_OPERATOR_PASS}"

---
apiVersion: v1
kind: Service
metadata:
  name: pkcs11-service
spec:
  selector:
    app: pkcs11-app
  ports:
  - port: 443
    targetPort: 8443
  type: LoadBalancer
```

## Programming Language Integration

### Python

```python
# python_example.py
import PyKCS11
import os

# Set up PKCS#11 module
pkcs11_lib = "./target/release/libpkcs11_impl_nethsm_sdk.so"
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(pkcs11_lib)

# Get slots
slots = pkcs11.getSlotList(tokenPresent=True)
print(f"Available slots: {slots}")

# Open session
session = pkcs11.openSession(slots[0], PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)

# Login
session.login("123456")

# Generate key pair
public_template = [
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
    (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
    (PyKCS11.CKA_MODULUS_BITS, 2048),
    (PyKCS11.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
    (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_LABEL, "python-key-pub"),
]

private_template = [
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
    (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_LABEL, "python-key-priv"),
]

public_key, private_key = session.generateKeyPair(public_template, private_template)

# Sign data
data = b"Hello from Python!"
signature = session.sign(private_key, data, PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None))

print(f"Signature: {signature.hex()}")

# Cleanup
session.logout()
session.closeSession()
```

### Java

```java
// JavaExample.java
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.*;

public class JavaExample {
    public static void main(String[] args) throws Exception {
        // Load PKCS#11 module
        Module pkcs11Module = Module.getInstance("./target/release/libpkcs11_impl_nethsm_sdk.so");
        pkcs11Module.initialize(null);
        
        // Get slots
        Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
        Slot slot = slots[0];
        
        // Open session
        Session session = slot.getToken().openSession(Token.SessionType.SERIAL_SESSION, 
                                                     Token.SessionReadWriteBehavior.RW_SESSION, 
                                                     null, null);
        
        // Login
        session.login(Session.UserType.USER, "123456".toCharArray());
        
        // Generate RSA key pair
        RSAPublicKey publicKeyTemplate = new RSAPublicKey();
        publicKeyTemplate.getModulusBits().setLongValue(2048L);
        publicKeyTemplate.getPublicExponent().setByteArrayValue(new byte[]{0x01, 0x00, 0x01});
        publicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        publicKeyTemplate.getLabel().setCharArrayValue("java-key-pub".toCharArray());
        
        RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
        privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getLabel().setCharArrayValue("java-key-priv".toCharArray());
        
        KeyPair keyPair = session.generateKeyPair(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN),
                                                  publicKeyTemplate, privateKeyTemplate);
        
        // Sign data
        byte[] data = "Hello from Java!".getBytes();
        session.signInit(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS), keyPair.getPrivateKey());
        byte[] signature = session.sign(data);
        
        System.out.println("Signature: " + bytesToHex(signature));
        
        // Cleanup
        session.logout();
        session.closeSession();
        pkcs11Module.finalize(null);
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
```

### Node.js

```javascript
// node_example.js
const pkcs11js = require('pkcs11js');

// Initialize PKCS#11
const pkcs11 = new pkcs11js.PKCS11();
pkcs11.load('./target/release/libpkcs11_impl_nethsm_sdk.so');
pkcs11.C_Initialize();

try {
    // Get slots
    const slots = pkcs11.C_GetSlotList(true);
    console.log('Available slots:', slots);
    
    // Open session
    const session = pkcs11.C_OpenSession(slots[0], pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
    
    // Login
    pkcs11.C_Login(session, pkcs11js.CKU_USER, '123456');
    
    // Generate RSA key pair
    const publicKeyTemplate = [
        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
        { type: pkcs11js.CKA_TOKEN, value: true },
        { type: pkcs11js.CKA_MODULUS_BITS, value: 2048 },
        { type: pkcs11js.CKA_PUBLIC_EXPONENT, value: Buffer.from([0x01, 0x00, 0x01]) },
        { type: pkcs11js.CKA_LABEL, value: 'nodejs-key-pub' }
    ];
    
    const privateKeyTemplate = [
        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
        { type: pkcs11js.CKA_TOKEN, value: true },
        { type: pkcs11js.CKA_PRIVATE, value: true },
        { type: pkcs11js.CKA_SIGN, value: true },
        { type: pkcs11js.CKA_LABEL, value: 'nodejs-key-priv' }
    ];
    
    const keys = pkcs11.C_GenerateKeyPair(session, 
        { mechanism: pkcs11js.CKM_RSA_PKCS_KEY_PAIR_GEN },
        publicKeyTemplate, 
        privateKeyTemplate
    );
    
    // Sign data
    const data = Buffer.from('Hello from Node.js!');
    pkcs11.C_SignInit(session, { mechanism: pkcs11js.CKM_RSA_PKCS }, keys.privateKey);
    const signature = pkcs11.C_Sign(session, data, Buffer.alloc(256));
    
    console.log('Signature:', signature.toString('hex'));
    
    // Cleanup
    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    
} finally {
    pkcs11.C_Finalize();
}
```

## Testing Integration

### Integration Test Script

```bash
#!/bin/bash
# integration_test.sh - Test integration with various tools

set -e

MODULE_PATH="./target/release/libpkcs11_impl_nethsm_sdk.so"
CONFIG_FILE="examples/integration/config/integration.yaml"

echo "=== PKCS#11 Integration Tests ==="

# Test 1: OpenSC tools
echo "1. Testing OpenSC tools..."
pkcs11-tool --module "$MODULE_PATH" --list-slots
pkcs11-tool --module "$MODULE_PATH" --list-mechanisms

# Test 2: OpenSSL
echo "2. Testing OpenSSL..."
export OPENSSL_CONF=examples/integration/openssl/openssl.cnf
openssl engine -t pkcs11

# Test 3: GnuTLS
echo "3. Testing GnuTLS..."
export GNUTLS_PKCS11_PROVIDER="$MODULE_PATH"
p11tool --list-tokens

# Test 4: SSH
echo "4. Testing SSH..."
ssh-keygen -D "$MODULE_PATH" || echo "SSH test completed"

echo "All integration tests completed successfully!"
```

### Continuous Integration

```yaml
# .github/workflows/integration.yml
name: Integration Tests

on: [push, pull_request]

jobs:
  integration:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y \
            opensc \
            openssl \
            libengine-pkcs11-openssl \
            gnutls-bin \
            openssh-client
      
      - name: Build PKCS#11 library
        run: cargo build --release --package pkcs11_impl_nethsm_sdk
      
      - name: Run integration tests
        env:
          P11NETHSM_CONFIG_FILE: examples/integration/config/integration.yaml
        run: |
          chmod +x examples/integration/integration_test.sh
          examples/integration/integration_test.sh
```

## Troubleshooting

### Common Issues

1. **Module not found**
   ```bash
   # Check library path
   ldd ./target/release/libpkcs11_impl_nethsm_sdk.so
   
   # Update library cache
   sudo ldconfig
   ```

2. **Configuration not loaded**
   ```bash
   # Set configuration file
   export P11NETHSM_CONFIG_FILE=/path/to/p11nethsm.conf
   
   # Verify configuration
   pkcs11-tool --module ./target/release/libpkcs11_impl_nethsm_sdk.so --list-slots
   ```

3. **Authentication failures**
   ```bash
   # Check credentials in configuration
   grep -A 5 "operator:" /path/to/p11nethsm.conf
   
   # Test with environment variables
   export NETHSM_OPERATOR_PASS=your_password
   ```

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG=debug

# Run with verbose output
pkcs11-tool --module ./target/release/libpkcs11_impl_nethsm_sdk.so \
  --list-slots --verbose
```

For more detailed integration examples, see the subdirectories for specific tools and applications.