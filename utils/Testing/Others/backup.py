def genSelfCert(subject, key: bytes, cert_type='signed'):
    # Check the Certification type from the request
    cert_type = cert_type.upper()
    if cert_type not in ['SELF', 'SIGNED', 'CSR']:
        return (False, "", "{} Invalid type of certificate".format(cert_type))

    # Classify the certificate request type:

    if cert_type == 'SIGNED':

        # Set the crypto Engine as the certificate issuer
        # CHANGE-JAMCH: At initialization
        result, issuer, status = load_entity(CA_issuer_conf)

        # Load the CA private key from 'CA_private_key_path)
        result, CA_private_key, status = load_CA_Key(CA_private_key_path)
        if not result:
            return (False, "", status)

        signing_key = CA_private_key

    else:
        signing_key = key
        issuer = subject

    # Building Certificate:
    cert = x509.CertificateBuilder()
    cert = cert.subject_name(subject)
    cert = cert.issuer_name(issuer)
    cert = cert.public_key(key.public_key())
    cert = cert.serial_number(x509.random_serial_number())
    cert = cert.not_valid_before(datetime.datetime.utcnow())
    cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_period))
    cert = cert.sign(signing_key, hashes.SHA256(), backend)

    if isinstance(cert, x509.Certificate):
        return (True, cert.public_bytes(serialization.Encoding.PEM), "OK")
    else:
        return (False, "", "Certificate could not be generated.")


def genCSR(output, entity):
    result, private_key, public_key, status = keyGenPair('RSA', 2048, 'PEM', 'SSH')
    # print("The private key is {}".format(private_key))
    outp, key = key_loader(private_key, 'private')
    # NameAttributes: Provides various details about the requester.

    # Create  the 'subject' of the certificate request
    result, subject, status = load_entity(entity)
    if not result:
        return (result, "", status)

    if output == 'SELF':
        result, x509content, status = genSelfCert(subject, key, output)
    else:
        result, x509content, status = genCSRonly(subject, key)

    return (result, x509content, status)

