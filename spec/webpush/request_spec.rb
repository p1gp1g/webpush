require 'spec_helper'

describe LegacyWebpush::Request do
  describe '#headers' do
    let(:request) { build_request(vapid: vapid_options) }

    it { expect(request.headers['Content-Type']).to eq('application/octet-stream') }
    it { expect(request.headers['Ttl']).to eq('2419200') }
    it { expect(request.headers['Urgency']).to eq('normal') }

    describe 'from :message' do
      it 'inserts encryption headers for valid payload' do
        allow(LegacyWebpush::Encryption).to receive(:encrypt).and_return(ciphertext: 'encrypted', server_public_key: 'server_public_key', salt: 'salt')
        request = build_request(message: "Hello")

        expect(request.headers['Content-Encoding']).to eq("aesgcm")
        expect(request.headers['Encryption']).to eq("salt=c2FsdA")
        expect(request.headers['Crypto-Key']).to eq("dh=c2VydmVyX3B1YmxpY19rZXk;p256ecdsa="+vapid_options[:public_key].delete('='))
      end
    end

    describe 'from :api_key' do
      def build_request_with_api_key(endpoint, options = {})
        subscription = {
          endpoint: endpoint,
          keys: {
            p256dh: 'p256dh',
            auth: 'auth'
          }
        }
        request = LegacyWebpush::Request.new(message: "", subscription: subscription, vapid: {}, **options)
      end

      it 'inserts Authorization header when api_key present, and endpoint is for Chrome\'s non-standards-compliant GCM endpoints' do
        request = build_request_with_api_key('https://gcm-http.googleapis.com/gcm/xyz', api_key: "api_key")

        expect(request.headers['Authorization']).to eq("key=api_key")
      end

      it 'does not insert Authorization header for Chrome\'s new standards-compliant endpoints, even if api_key is present' do
        request = build_request_with_api_key('https://fcm.googleapis.com/fcm/send/ABCD1234', api_key: "api_key")

        expect(request.headers['Authorization']).to be_nil
      end

      it 'does not insert Authorization header when endpoint is not for Chrome, even if api_key is present' do
        request = build_request_with_api_key('https://some.random.endpoint.com/xyz', api_key: "api_key")

        expect(request.headers['Authorization']).to be_nil
      end

      it 'does not insert Authorization header when api_key blank' do
        request = build_request_with_api_key("endpoint", api_key: nil)

        expect(request.headers['Authorization']).to be_nil

        request = build_request_with_api_key("endpoint", api_key: "")

        expect(request.headers['Authorization']).to be_nil

        request = build_request_with_api_key("endpoint")

        expect(request.headers['Authorization']).to be_nil
      end
    end

    describe 'from :ttl' do
      it 'can override Ttl with :ttl option with string' do
        request = build_request(ttl: '300', vapid: vapid_options)

        expect(request.headers['Ttl']).to eq('300')
      end

      it 'can override Ttl with :ttl option with fixnum' do
        request = build_request(ttl: 60 * 5)

        expect(request.headers['Ttl']).to eq('300')
      end
    end

    describe 'from :urgency' do
      it 'can override Urgency with :urgency option' do
        request = build_request(urgency: 'high', vapid: vapid_options)

        expect(request.headers['Urgency']).to eq('high')
      end
    end
  end

  describe '#build_vapid_headers' do
    it 'returns hash of VAPID headers' do
      time = Time.at(1476150897)
      jwt_payload = {
        aud: 'https://fcm.googleapis.com',
        exp: time.to_i + 24 * 60 * 60,
        sub: 'mailto:sender@example.com',
      }
      jwt_header_fields = { 'typ' => 'JWT' }

      vapid_key = LegacyWebpush::VapidKey.from_keys(vapid_public_key, vapid_private_key)
      expect(Time).to receive(:now).and_return(time)
      expect(LegacyWebpush::VapidKey).to receive(:from_keys).with(vapid_public_key, vapid_private_key).and_return(vapid_key)
      expect(JWT).to receive(:encode).with(jwt_payload, vapid_key.curve, 'ES256', jwt_header_fields).and_return('jwt.encoded.payload')

      request = build_request(vapid: vapid_options)
      headers = request.build_vapid_headers
      # headers = LegacyWebpush::Request.headers({
      #   audience: 'https://fcm.googleapis.com',
      #   subject: 'mailto:sender@example.com',
      #   public_key: vapid_public_key,
      #   private_key: vapid_private_key
      # })

      expect(headers['Authorization']).to eq('WebPush jwt.encoded.payload')
      expect(headers['Crypto-Key']).to eq('p256ecdsa=' + vapid_public_key.delete('='))
    end

    it 'supports PEM format' do
      pem = LegacyWebpush::VapidKey.new.to_pem
      expect(LegacyWebpush::VapidKey).to receive(:from_pem).with(pem).and_call_original
      request = build_request(vapid: { subject: "mailto:sender@example.com", pem: pem })
      request.build_vapid_headers
    end
  end

  describe '#body' do
    it 'extracts :ciphertext from the :payload argument' do
      allow(LegacyWebpush::Encryption).to receive(:encrypt).and_return(ciphertext: 'encrypted')

      request = build_request(message: 'Hello', vapid: vapid_options)

      expect(request.body).to eq('encrypted')
    end

    it 'is empty string when no :ciphertext' do
      request = build_request(payload: {})

      expect(request.body).to eq('')
    end

    it 'is empty string when no :payload' do
      request = build_request

      expect(request.body).to eq('')
    end
  end

  def build_request(options = {})
    subscription = {
      endpoint: endpoint,
      keys: {
        p256dh: 'p256dh',
        auth: 'auth'
      }
    }
    LegacyWebpush::Request.new(message: "", subscription: subscription, vapid: vapid_options, **options)
  end

  def endpoint
    'https://fcm.googleapis.com/gcm/send/subscription-id'
  end
end
