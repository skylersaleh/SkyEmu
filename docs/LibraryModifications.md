# Library modifications

## curl (v8.5)
    - commented out find_package(OpenSSL) & removed OpenSSL::* prefixes since we link with our own OpenSSL
