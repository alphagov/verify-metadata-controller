Feature: The java app

  Background:
    Given the java app exists
    And the login credentials exist


  Scenario: Launching the java app
    When I run the java executable with no parameters
    Then I see that the application complains about missing parameters

  Scenario: Launching the java app with decent parameters
    When I run the java executable with some appropriate parameters
    Then I see that the application outputs a file
    And the file contains the supplied saml signing certificate: 'cloudhsmkeycert.rsa.pem'
    And the file contains the supplied saml encryption certificate: 'cloudhsmkeycert.rsa.pem'

  Scenario Outline: Using the RSA algorithm on the connector node
    When I run the java executable for the "<node_type>" node and specify the "<algorithm>" algorithm using the signing cert "<signing_cert>" and the encryption cert "<encryption_cert>"
    Then I see that the application outputs a file
    And the file contains the supplied saml signing certificate: "<signing_cert>"
    And the file contains the supplied saml encryption certificate: "<encryption_cert>"
    Examples:
      | node_type | algorithm | signing_cert            | encryption_cert         |
      | connector | RSA       | cloudhsmkeycert.rsa.pem | cloudhsmkeycert.rsa.pem |
#      | proxy     | RSA       | cloudhsmkeycert.rsa.pem | cloudhsmkeycert.rsa.pem |
#      | connector | ECDSA     | cloudhsmkeycert.rsa.pem | cloudhsmkeycert.rsa.pem |
#      | proxy     | ECDSA     | cloudhsmkeycert.rsa.pem | cloudhsmkeycert.rsa.pem |

#  Scenario: Getting a signed dojamaflip
#    When I run the java executable with some appropriate parameters
#    And I request some signed something
#    Then I get a signed something