# TLS Profiles

`tls_requests` allows you to emulate specific browser TLS fingerprints by providing a `client_identifier`. This spoofing is handled automatically at the protocol level.

* * *

## Default Client Configuration

By default, the `Client` and `AsyncClient` use the following settings:

*   **Timeout:** 30 seconds.
*   **Default Profile:** `chrome_133`.
*   **Redirects:** Followed by default (max 9).
*   **HTTP/2:** Enabled (Auto-negotiation).
*   **Verification:** TLS certificate verification is enabled.

```python
import tls_requests

# Using the default profile
response = tls_requests.get("https://httpbin.org/get")

# Using a specific profile
response = tls_requests.get("https://httpbin.org/get", client_identifier="firefox_132")
```

* * *

## Supported Profiles

Below is a list of commonly used identifiers supported by the underlying TLS engine.

### Google Chrome
*   `chrome_103` through `chrome_112`
*   `chrome_116_PSK`, `chrome_116_PSK_PQ`
*   `chrome_117`
*   `chrome_120`
*   `chrome_124`
*   `chrome_131`, `chrome_131_PSK`
*   `chrome_133` (Current Default)

### Mozilla Firefox
*   `firefox_102`, `firefox_104`, `firefox_105`, `firefox_106`, `firefox_108`
*   `firefox_110`, `firefox_117`, `firefox_120`, `firefox_123`, `firefox_132`

### Apple Safari
*   `safari_15_6_1`, `safari_16_0`
*   `safari_ios_15_5`, `safari_ios_15_6`, `safari_ios_16_0`, `safari_ios_17_0` (iOS)
*   `safari_ios_18_0` (check available version)

### Opera
*   `opera_89`, `opera_90`, `opera_91`

### Mobile & Specialized
*   `zalando_ios_mobile`, `zalando_android_mobile`
*   `nike_ios_mobile`
*   `mms_ios`, `mms_ios_2`, `mms_ios_3`
*   `mesh_ios`, `mesh_android`
*   `confirmed_ios`, `confirmed_android`
*   `cloudscraper`

!!! note
    New profiles are added frequently. If an identifier is not listed here but exists in the latest `tls-client` release, it will likely work.
*   Confirmed Android 2 (`confirmed_android_2`)

#### OkHttp4

*   Android 7 (`okhttp4_android_7`)
*   Android 8 (`okhttp4_android_8`)
*   Android 9 (`okhttp4_android_9`)
*   Android 10 (`okhttp4_android_10`)
*   Android 11 (`okhttp4_android_11`)
*   Android 12 (`okhttp4_android_12`)
*   Android 13 (`okhttp4_android_13`)
