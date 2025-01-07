#!/bin/sh

find -type f \( -not -name "*.md" -a -not -name "*.sh" \) -exec sed -i -e 's/Webpush/LegacyWebpush/g' -e 's/LegacyLegacy/Legacy/g' -e '/require .webpush/ s/webpush/legacy-webpush/' {} \;
sed -i -e '/spec.name/ s/"webpush/"legacy-webpush/' webpush.gemspec
git mv lib/webpush.rb lib/legacy-webpush.rb
git mv lib/webpush/ lib/legacy-webpush/
