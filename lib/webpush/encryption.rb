# frozen_string_literal: true

module Webpush
  module Encryption
    extend self

    # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
    def encrypt(message, p256dh, auth)
      assert_arguments(message, p256dh, auth)
      puts "Encrypting #{message} with #{p256dh} and #{auth}"

      group_name = 'prime256v1'
      salt = Random.new.bytes(16)
      puts "Salt: #{Webpush.encode64(salt)}"

      server = OpenSSL::PKey::EC.generate(group_name)
      server_public_key_bn = server.public_key.to_bn

      group = OpenSSL::PKey::EC::Group.new(group_name)
      client_public_key_bn = OpenSSL::BN.new(Webpush.decode64(p256dh), 2)
      client_public_key = OpenSSL::PKey::EC::Point.new(group, client_public_key_bn)

      shared_secret = server.dh_compute_key(client_public_key)
      puts "Shared secret: #{Webpush.encode64(shared_secret)}"

      client_auth_token = Webpush.decode64(auth)

      info = "WebPush: info\0" + client_public_key_bn.to_s(2) + server_public_key_bn.to_s(2)
      content_encryption_key_info = "Content-Encoding: aes128gcm\0"
      nonce_info = "Content-Encoding: nonce\0"

      prk = HKDF.new(shared_secret, salt: client_auth_token, algorithm: 'SHA256', info: info).next_bytes(32)
      puts "PRK: #{Webpush.encode64(prk)}"

      content_encryption_key = HKDF.new(prk, salt: salt, info: content_encryption_key_info).next_bytes(16)
      puts "CEK: #{Webpush.encode64(content_encryption_key)}"

      nonce = HKDF.new(prk, salt: salt, info: nonce_info).next_bytes(12)
      puts "Nonce: #{Webpush.encode64(nonce)}"

      ciphertext = encrypt_payload(message, content_encryption_key, nonce)
      puts "Encrypted paylaod: #{Webpush.encode64(ciphertext)}"

      serverkey16bn = convert16bit(server_public_key_bn)
      rs = 4096 # ciphertext.bytesize
      raise ArgumentError, "encrypted payload is too big" if rs > 4096

      aes128gcmheader = "#{salt}" + [rs].pack('N*') + [serverkey16bn.bytesize].pack('C*') + serverkey16bn
      puts "Header: #{Webpush.encode64(aes128gcmheader)}"
      puts "RS: #{Webpush.encode64([rs].pack('N*'))}"
      puts "serverkeybn: #{Webpush.encode64([serverkey16bn.bytesize].pack('C*'))}"
      puts "serverkey16bn: #{Webpush.encode64(serverkey16bn)}"

      ciphertext = aes128gcmheader + ciphertext
      puts "Ciphertext: #{Webpush.encode64(ciphertext)}"

      ciphertext
    end
    # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

    private

    def encrypt_payload(plaintext, content_encryption_key, nonce)
      plaintext = plaintext + "\x02"
      puts "Encrypting #{Webpush.encode64(plaintext)}"
      cipher = OpenSSL::Cipher.new('aes-128-gcm')
      cipher.encrypt
      cipher.key = content_encryption_key
      cipher.iv = nonce
      text = cipher.update(plaintext)
      #padding = cipher.update("\2\0")
      #e_text = text + padding + cipher.final
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
