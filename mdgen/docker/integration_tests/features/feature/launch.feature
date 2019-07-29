Feature: The java app

  Background:
    Given the java app exists
    And the login credentials exist

  Scenario: Launching the java app
    When I run the java executable with no parameters
    Then I see that the application complains about missing parameters

  Scenario Outline: The proxy-node use case
    Produce signed metadata for the proxy node using a cert supplied by the verify-metadata-controller
    When I run the java executable with some appropriate parameters
    Then I see that the application outputs a file
    And the file contains the supplied saml signing certificate: "<cert>"
    And the file contains the supplied saml encryption certificate: "<cert>"
    Examples:
      | cert                                     |
      | test-hsm-generated-saml-signing-cert.pem |

  Scenario Outline: The connector node use case
    Produce signed metadata for the connector node using certificates supplied by the hub
    When I run the java executable for the "<node_type>" node and specify the "<algorithm>" algorithm using the signing cert "<signing_cert>" and the encryption cert "<encryption_cert>"
    Then I see that the application outputs a file
    And the file contains the supplied saml signing certificate: "<signing_cert>"
    And the file contains the supplied saml encryption certificate: "<encryption_cert>"
    Examples:
      | node_type | algorithm | signing_cert                        | encryption_cert                        |
      | connector | RSA       | test-supplied-saml-signing-cert.pem | test-supplied-saml-encryption-cert.pem |
