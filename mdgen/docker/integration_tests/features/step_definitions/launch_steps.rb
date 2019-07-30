require 'nokogiri'

AfterConfiguration() do
  system('rm -fr mdgen')
  system('unzip ../mdgen.zip')
end

After do
  system('rm ./metadata.xml') if File.exist? "./metadata.xml"
end

Given("the java app exists") do
  expect(File.file?("mdgen/bin/mdgen")).to be true
end

Given("the login credentials exist") do
  expect(ENV.has_key? "HSM_USER").to be true
  expect(ENV.has_key? "HSM_PASSWORD").to be true
end

When("I run the java executable with no parameters") do
  @last_output = `mdgen/bin/mdgen 2>&1`
end

When("I run the java executable with correct parameters for the proxy node") do
  @last_output = run_app("proxy", "rsa")
end

When("I run the java executable for the {string} node and specify the {string} algorithm using the signing cert {string} and the encryption cert {string}") do | node_type, algorithm, signing_cert, encryption_cert |
  @last_output = run_app_with_certs(node_type, algorithm.downcase, signing_cert, encryption_cert)
end

Then("I see that the application complains about missing parameters") do
  expect(@last_output).to include "required parameters"
end

Then("I see that the application outputs a file") do
  File.exist? "./metadata.xml"
end

Then("the file contains valid metadata") do
  # Which nodes are required?
  puts "not entirely sure how we do this, or if it's necessary"
end

Then("the file contains the supplied saml signing certificate: {string}") do | pem_file |
  expect(extracted_signing_cert).to eq stripped_pem(pem_file)
end

Then("the file contains the supplied saml encryption certificate: {string}") do | pem_file |
  expect(extracted_encryption_cert).to eq stripped_pem(pem_file)
end

private
def run_app(node_type, algorithm)
  `java -classpath '/opt/cloudhsm/java/*:mdgen/lib/*' uk.gov.ida.mdgen.MetadataGenerator #{node_type} ../test/#{node_type}.yml ../test/test-metadata-signing-cert.pem --hsm-saml-signing-cert-file ../test/test-hsm-generated-saml-signing-cert.pem --hsm-saml-signing-key-label this-is-a-cloudhsmtool-thing --hsm-metadata-signing-key-label this-is-a-cloudhsmtool-thing --output ./metadata.xml 2>&1`
end

def run_app_with_certs(node_type, algorithm, signing_cert, encryption_cert)
  `java -classpath '/opt/cloudhsm/java/*:mdgen/lib/*' uk.gov.ida.mdgen.MetadataGenerator #{node_type} ../test/#{node_type}.yml ../test/test-metadata-signing-cert.pem --supplied-saml-signing-cert-file ../test/#{signing_cert} --supplied-saml-encryption-cert-file ../test/#{encryption_cert} --algorithm #{algorithm} --hsm-metadata-signing-key-label this-is-a-cloudhsmtool-thing --output ./metadata.xml 2>&1`
end

def stripped_pem(pem_file)
  File.read("../test/#{pem_file}")
      .sub!("-----BEGIN CERTIFICATE-----", "")
      .sub!("-----END CERTIFICATE-----", "")
      .gsub!("\n", "")
end

def extracted_signing_cert
  extract_node '//md:KeyDescriptor[@use="signing"]'
end

def extracted_encryption_cert
  extract_node '//md:KeyDescriptor[@use="encryption"]'
end

def extract_node(xpath)
  metadata = File.read("./metadata.xml")
  xml = Nokogiri::XML(metadata)
  xml.at_xpath(xpath).text.gsub!("\n", "")
rescue
  "node not found: #{xpath}"
end