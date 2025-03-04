# frozen_string_literal: true

module Webpush
  module Encryption
    extend self

    # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
    def encrypt(message, p256dh, auth)
      assert_arguments(message, p256dh, auth)
      # Following RFC8291, messages can't be longer than 3993 bytes long
      # so encrypted message do not exceed 4096 bytes
      raise ArgumentError, "message is too big" if message.bytesize > 3993

      group_name = 'prime256v1'
      salt = Random.new.bytes(16)

      server = OpenSSL::PKey::EC.generate(group_name)
      server_public_key_bn = server.public_key.to_bn

      group = OpenSSL::PKey::EC::Group.new(group_name)
      client_public_key_bn = OpenSSL::BN.new(Webpush.decode64(p256dh), 2)
      client_public_key = OpenSSL::PKey::EC::Point.new(group, client_public_key_bn)

      shared_secret = server.dh_compute_key(client_public_key)

      client_auth_token = Webpush.decode64(auth)

      info = "WebPush: info\0" + client_public_key_bn.to_s(2) + server_public_key_bn.to_s(2)
      content_encryption_key_info = "Content-Encoding: aes128gcm\0"
      nonce_info = "Content-Encoding: nonce\0"

      prk = HKDF.new(shared_secret, salt: client_auth_token, algorithm: 'SHA256', info: info).next_bytes(32)

      content_encryption_key = HKDF.new(prk, salt: salt, info: content_encryption_key_info).next_bytes(16)

      nonce = HKDF.new(prk, salt: salt, info: nonce_info).next_bytes(12)

      ciphertext = encrypt_payload(message, content_encryption_key, nonce)
      # This should never happen if message length <= 3993
      raise ArgumentError, "encrypted payload is too big" if ciphertext.bytesize > 4096

      serverkey16bn = convert16bit(server_public_key_bn)
      # According to RFC8188, the final record can be smaller than the record size
      # RFC8291 requires encrypted messages to be at most 4096. And the example set the
      # RS to 4096. RS can be smaller to 4096 but hardcoding is also following the specs.
      # We set RS=4096 to allow testing with the RFC example.
      rs = 4096

      aes128gcmheader = "#{salt}" + [rs].pack('N*') + [serverkey16bn.bytesize].pack('C*') + serverkey16bn

      aes128gcmheader + ciphertext
    end
    # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

    private

    def encrypt_payload(plaintext, content_encryption_key, nonce)
      # RFC8291 requires the padding delimiter to be 0x02
      plaintext = plaintext + "\x02"
      cipher = OpenSSL::Cipher.new('aes-128-gcm')
      cipher.encrypt
      cipher.key = content_encryption_key
      cipher.iv = nonce
      text = cipher.update(plaintext)
      e_text = text + cipher.final
      e_tag = cipher.auth_tag

      e_text + e_tag
    end

    def convert16bit(key)
      [key.to_s(16)].pack('H*')
    end

    def assert_arguments(message, p256dh, auth)
      raise ArgumentError, 'message cannot be blank' if blank?(message)
      raise ArgumentError, 'p256dh cannot be blank' if blank?(p256dh)
      raise ArgumentError, 'auth cannot be blank' if blank?(auth)
    end

    def blank?(value)
      value.nil? || value.empty?
    end
  end
end
