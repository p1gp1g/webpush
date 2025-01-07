namespace :webpush do
  desc 'Generate VAPID public/private key pair'
  task :generate_keys do
    require 'legacy-webpush'

    LegacyWebpush.generate_key.tap do |keypair|
      puts <<-KEYS
Generated VAPID keypair:
Public  -> #{keypair.public_key}
Private -> #{keypair.private_key}
      KEYS
    end
  end
end
