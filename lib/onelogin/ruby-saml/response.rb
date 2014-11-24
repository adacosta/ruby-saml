require "xml_security"
require "time"
require "nokogiri"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    class Response < SamlMessage
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
      DSIG      = "http://www.w3.org/2000/09/xmldsig#"
      ENCRYPTED_DATA_XMLNS = "http://www.w3.org/2001/04/xmlenc#"
      AES_256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"

      # TODO: This should probably be ctor initialized too... WDYT?
      attr_accessor :settings
      attr_accessor :errors

      attr_reader :options
      attr_reader :response
      attr_reader :document

      def initialize(response, options = {})
        @errors = []
        raise ArgumentError.new("Response cannot be nil") if response.nil?
        @options  = options
        @response = decode_raw_saml(response)
        @document = XMLSecurity::SignedDocument.new(@response, @errors)
      end

      def is_valid?
        validate
      end

      def validate!
        validate(false)
      end

      def errors
        @errors
      end

      # The value of the user identifier as designated by the initialization request response
      def name_id
        @name_id ||= begin
          node = xpath_first_from_signed_assertion('/a:Subject/a:NameID')
          node.nil? ? nil : node.text
        end
      end

      def sessionindex
        @sessionindex ||= begin
          node = xpath_first_from_signed_assertion('/a:AuthnStatement')
          node.nil? ? nil : node.attributes['SessionIndex']
        end
      end

      # Returns OneLogin::RubySaml::Attributes enumerable collection.
      # All attributes can be iterated over +attributes.each+ or returned as array by +attributes.all+
      #
      # For backwards compatibility ruby-saml returns by default only the first value for a given attribute with
      #    attributes['name']
      # To get all of the attributes, use:
      #    attributes.multi('name')
      # Or turn off the compatibility:
      #    OneLogin::RubySaml::Attributes.single_value_compatibility = false
      # Now this will return an array:
      #    attributes['name']
      def attributes
        @attr_statements ||= begin
          attributes = Attributes.new

          stmt_element = xpath_first_from_signed_assertion('/a:AttributeStatement')
          return attributes if stmt_element.nil?

          stmt_element.elements.each do |attr_element|
            name  = attr_element.attributes["Name"]
            values = attr_element.elements.collect{|e|
              # SAMLCore requires that nil AttributeValues MUST contain xsi:nil XML attribute set to "true" or "1"
              # otherwise the value is to be regarded as empty.
              ["true", "1"].include?(e.attributes['xsi:nil']) ? nil : e.text.to_s
            }

            attributes.add(name, values)
          end

          attributes
        end
      end

      # When this user session should expire at latest
      def session_expires_at
        @expires_at ||= begin
          node = xpath_first_from_signed_assertion('/a:AuthnStatement')
          parse_time(node, "SessionNotOnOrAfter")
        end
      end

      # Checks the status of the response for a "Success" code
      def success?
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.attributes["Value"] == "urn:oasis:names:tc:SAML:2.0:status:Success"
        end
      end

      def status_message
        @status_message ||= begin
          node = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusMessage", { "p" => PROTOCOL, "a" => ASSERTION })
          node.text if node
        end
      end

      # Conditions (if any) for the assertion to run
      def conditions
        @conditions ||= xpath_first_from_signed_assertion('/a:Conditions')
      end

      def not_before
        @not_before ||= parse_time(conditions, "NotBefore")
      end

      def not_on_or_after
        @not_on_or_after ||= parse_time(conditions, "NotOnOrAfter")
      end

      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:Response/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node ||= xpath_first_from_signed_assertion('/a:Issuer')
          node.nil? ? nil : node.text
        end
      end

      private

      def encrypted_assertions
        nokogiri_xml_document.xpath('//saml:EncryptedAssertion', 'saml' => ASSERTION)
      end

      def nokogiri_xml_document
        @nokogiri_xml_document ||= Nokogiri::XML(@response)
      end

      def has_encrypted_assertions?
        encrypted_assertions.size > 0
      end

      def decrypt_assertion_aes_256_cbc(encrypted_assertion)
        aes_256_cbc = OpenSSL::Cipher::AES.new(256, :CBC)
        aes_256_cbc.decrypt
        aes_256_cbc.key = decrypted_assertion_cipher_key(encrypted_assertion)
        encrypted_assertion_value = encrypted_assertion_value(encrypted_assertion)

        # Have to call 2x otherwise decryption doesn't happen; update mutates self
        # Ruby OpenSSL bug? view source for http://www.ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/Cipher.html#method-i-update
        aes_256_cbc.update(encrypted_assertion_value)
        plain = aes_256_cbc.update(encrypted_assertion_value)
        plain_chars = plain.chars.to_a
        # The first 32B contain the last (of the decrypted string) 4B + 28B of junk, without the IV.
        end_chars = plain_chars.shift(4)
        junk_chars = plain_chars.shift(28)
        plain_chars.push end_chars
        plain_chars.join ''
      end

      def encrypted_assertion_symmetric_encryption_method(encrypted_assertion)
        encrypted_assertion.xpath(
          '//saml:EncryptedAssertion/xml_enc:EncryptedData/xml_enc:EncryptionMethod',
          'saml' => ASSERTION,
          'xml_enc' => ENCRYPTED_DATA_XMLNS
        ).first
      end

      def encrypted_assertion_encrypted_cipher_key_value_base64(encrypted_assertion)
        encrypted_assertion.xpath(
          '//saml:EncryptedAssertion/xml_enc:EncryptedData/dsig:KeyInfo/xml_enc:EncryptedKey/xml_enc:CipherData/xml_enc:CipherValue',
          'saml' => ASSERTION,
          'xml_enc' => ENCRYPTED_DATA_XMLNS,
          'dsig' => DSIG
        ).first
      end

      def encrypted_assertion_value_base64(encrypted_assertion)
        encrypted_assertion.xpath(
          '//saml:EncryptedAssertion/xml_enc:EncryptedData/xml_enc:CipherData/xml_enc:CipherValue',
          'saml' => ASSERTION,
          'xml_enc' => ENCRYPTED_DATA_XMLNS,
          'dsig' => DSIG
        ).first
      end

      def encrypted_assertion_value(encrypted_assertion)
        Base64.decode64(encrypted_assertion_value_base64(encrypted_assertion).text)
      end

      def encrypted_assertion_encrypted_cipher_key_value(encrypted_assertion)
        Base64.decode64(encrypted_assertion_encrypted_cipher_key_value_base64(encrypted_assertion).text)
      end

      def decrypted_assertion_cipher_key(encrypted_assertion)
        raise("settings.private_key must be set to decrypt assertion!") unless settings.private_key
        key = OpenSSL::PKey::RSA.new(settings.private_key)
        key.private_decrypt(encrypted_assertion_encrypted_cipher_key_value(encrypted_assertion))
      end

      def decrypt_assertions_in_document
        encrypted_assertions.each do |encrypted_assertion|
          decrypt_assertion(encrypted_assertion)
        end
      end

      def encryption_algorithm(encrypted_assertion)
        encryption_method = encrypted_assertion_symmetric_encryption_method(encrypted_assertion)
        encryption_method.attributes["Algorithm"].value
      end

      def decrypt_assertion(encrypted_assertion)
        case encryption_algorithm(encrypted_assertion)
        when AES_256_CBC
          decrypted_assertion = decrypt_assertion_aes_256_cbc(encrypted_assertion)
          replace_encrypted_assertion_with_decrypted_assertion(encrypted_assertion, decrypted_assertion)
          # NOTE: detect and raise on decryption failure?
        else
          raise("Only AES-256-CBC is implemented")
        end
      end

      def replace_encrypted_assertion_with_decrypted_assertion(encrypted_assertion, decrypted_assertion)
        parent = encrypted_assertion.parent
        encrypted_assertion.remove
        parent.add_child(decrypted_assertion)
        # update document to look as if the EncryptedAssertion was always there as an Assertion
        @document = XMLSecurity::SignedDocument.new(nokogiri_xml_document.root.to_xml, @errors)
      end

      def validate(soft = true)
        decrypt_assertions_in_document if has_encrypted_assertions?
        valid_saml?(document, soft) &&
        validate_response_state(soft) &&
        validate_conditions(soft) &&
        validate_issuer(soft) &&
        document.validate_document(get_fingerprint, soft) &&
        validate_success_status(soft)
      end

      def validate_success_status(soft = true)
        if success?
          true
        else
          soft ? false : validation_error(status_message)
        end
      end

      def validate_structure(soft = true)
        Dir.chdir(File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'schemas'))) do
          @schema = Nokogiri::XML::Schema(IO.read('saml-schema-protocol-2.0.xsd'))
          @xml = Nokogiri::XML(self.document.to_s)
        end
        if soft
          @schema.validate(@xml).map{
            @errors << "Schema validation failed";
            return false
          }
        else
          @schema.validate(@xml).map{ |error| @errors << "#{error.message}\n\n#{@xml.to_s}";
            validation_error("#{error.message}\n\n#{@xml.to_s}")
          }
        end
      end

      def validate_response_state(soft = true)
        if response.empty?
          return soft ? false : validation_error("Blank response")
        end

        if settings.nil?
          return soft ? false : validation_error("No settings on response")
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          return soft ? false : validation_error("No fingerprint or certificate on settings")
        end

        true
      end

      def xpath_first_from_signed_assertion(subelt=nil)
        node = REXML::XPath.first(document, "/p:Response/a:Assertion[@ID='#{document.signed_element_id}']#{subelt}", { "p" => PROTOCOL, "a" => ASSERTION })
        node ||= REXML::XPath.first(document, "/p:Response[@ID='#{document.signed_element_id}']/a:Assertion#{subelt}", { "p" => PROTOCOL, "a" => ASSERTION })
        node
      end

      def get_fingerprint
        if settings.idp_cert
          cert = OpenSSL::X509::Certificate.new(settings.idp_cert)
          Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(":")
        else
          settings.idp_cert_fingerprint
        end
      end

      def validate_conditions(soft = true)
        return true if conditions.nil?
        return true if options[:skip_conditions]

        now = Time.now.utc

        if not_before && (now + (options[:allowed_clock_drift] || 0)) < not_before
          @errors << "Current time is earlier than NotBefore condition #{(now + (options[:allowed_clock_drift] || 0))} < #{not_before})"
          return soft ? false : validation_error("Current time is earlier than NotBefore condition")
        end

        if not_on_or_after && now >= not_on_or_after
          @errors << "Current time is on or after NotOnOrAfter condition (#{now} >= #{not_on_or_after})"
          return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
        end

        true
      end

      def validate_issuer(soft = true)
        return true if settings.idp_entity_id.nil?

        unless URI.parse(issuer) == URI.parse(settings.idp_entity_id)
          return soft ? false : validation_error("Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>")
        end
        true
      end

      def parse_time(node, attribute)
        if node && node.attributes[attribute]
          Time.parse(node.attributes[attribute])
        end
      end
    end
  end
end
