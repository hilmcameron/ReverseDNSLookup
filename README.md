# ReverseDNSLookup

This tool performs reverse IP lookups and retrieves other websites hosted on the same server. It uses the ViewDNS API for reverse IP lookups.

## Features

- Validate IP addresses
- Perform reverse IP lookups
- Retrieve other websites hosted on the same server
- Asynchronous operations for better performance
- Logging for better traceability

## Requirements

- Python 3.7+
- `aiohttp`
- `requests`

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/ip-reverse-lookup.git
    cd ip-reverse-lookup
    ```

2. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

3. Replace `Your-Api-Key-Here` in the code with your ViewDNS API key.

## Usage

```sh
python ip_reverse_lookup.py <IP_ADDRESS> [--all]
```