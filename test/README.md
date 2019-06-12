# Testing the Permissin plugin

## TLS

There are prepared certifictes in the `certs` directory. Here are some commands for testing:

    # test with valid certificate
    curl -k --cert certs/greg.crt --key certs/greg.key https://localhost:2015/tmp/

    # test with invalid certificate
    curl -k --cert certs/fakegreg.crt --key certs/fakegreg.key https://localhost:2015/tmp/
