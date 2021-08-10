# frozen_string_literal: true

require 'omniauth/strategies/oauth2'
require 'securerandom'
require 'base64'
require 'pry'

module OmniAuth
  module Strategies
    # https://developer.sberbank.ru/doc/v3/sbbol
    class Sberbusiness < OmniAuth::Strategies::OAuth2
      class NoRawData < StandardError; end

      API_VERSION = '1.0'

      DEFAULT_SCOPE = 'openid inn email'

      option :name, 'sberbusiness'

      option :test, false

      option :client_options,
             site: 'https://fintech.sberbank.ru:9443',
             token_url: 'https://fintech.sberbank.ru:9443/ic/sso/api/v2/oauth/token',
             authorize_url: 'https://sbi.sberbank.ru:9443/ic/sso/api/v2/oauth/authorize',
             user_info_path: '/ic/sso/api/v2/oauth/user-info',
             client_info_path: '/api/v1/client-info'

      option :authorize_options, %i[scope response_type client_type client_id state nonce]

      option :redirect_url, nil

      uid { raw_info['sub'].to_s }

      def client
        change_links if options.test
        super
      end

      # https://github.com/intridea/omniauth/wiki/Auth-Hash-Schema
      info do
        {
          name: raw_info['name'],
          org_full_name: raw_info['orgFullName'],
          org_name: raw_info['OrgName'],
          org_kpp: raw_info['orgKpp'],
          org_ogrn: raw_info['orgOgrn'],
          org_actual_address: raw_info['orgActualAddress'],
          org_juridical_address: raw_info['orgJuridicalAddress'],
          phone_number: raw_info['phone_number'],
          email: raw_info['email'],
          accounts: raw_info['accounts'],
          id: raw_info['sub'],
          inn: raw_info['inn'],
          bank: raw_info['terBank'],
          org_id: raw_info['orgId'],
          org_id_hash: raw_info['HashOrgId'],
          provider: options.name
        }
      end

      extra do
        if options.test
          {
            'raw_info' => raw_info,
            'credentials' => credentials
          }
        else
          { 'raw_info' => raw_info }
        end
      end

      def raw_info
        access_token.options[:mode] = :header
        @raw_info ||= begin
          result = access_token.get(options.client_options['user_info_path'], headers: info_headers).body
          # декодируем ответ:
          decoded_data = result.split('.').map { |code| decrypt(code) rescue {}}
          result = decoded_data.reduce(:merge)
          # здесь нужен скоп специальный, а на тесте мы его задать не можем
          return result unless options.test

          org_info = access_token.get(options.client_options['client_info_path'], headers: info_headers).body
          result.merge(client_info: org_info.force_encoding('UTF-8'))
        end
      end

      def decrypt(msg)
        JSON.parse(Base64.urlsafe_decode64(msg).force_encoding(Encoding::UTF_8))
      end

      def authorize_params
        # add links in options
        change_links if options.test

        super.tap do |params|
          %w[state scope response_type client_type client_id nonce].each do |v|
            next unless request.params[v]

            params[v.to_sym] = request.params[v]
          end
          params[:scope] ||= DEFAULT_SCOPE
          params[:nonce] = SecureRandom.hex(16)
        end
      end

      private

      def params
        {
          fields: info_options,
          lang: lang_option,
          https: https_option,
          v: API_VERSION
        }
      end

      def change_links
        options.client_options[:site] = options.client_options[:test_site] ||
                                        'https://edupirfintech.sberbank.ru:9443'
        options.client_options[:token_url] = options.client_options[:test_token_url] ||
                                             'https://edupirfintech.sberbank.ru:9443/ic/sso/api/v1/oauth/token'
        options.client_options[:authorize_url] = options.client_options[:test_authorize_url] ||
                                                 'https://edupir.testsbi.sberbank.ru:9443/ic/sso/api/v2/oauth/authorize'
        options.client_options[:user_info_path] = options.client_options[:test_user_info_path] ||
                                                  '/ic/sso/api/v1/oauth/user-info'
        options.client_options[:client_info_path] = options.client_options[:test_client_info_path] ||
                                                    '/fintech/api/v1/client-info'
      end

      def callback_url
        options.redirect_url || (full_host + script_name + callback_path)
      end

      def info_options
        fields = %w[
          sub family_name given_name middle_name birthdate email phone_number
          address_reg identification inn snils gender
        ]
        fields.concat(options[:info_fields].split(',')) if options[:info_fields]
        fields.join(',')
      end

      def lang_option
        options[:lang] || ''
      end

      def https_option
        options[:https] || 0
      end

      def location
        country = raw_info.fetch('country', {})['title']
        city = raw_info.fetch('city', {})['title']
        @location ||= [country, city].compact.join(', ')
      end

      def callback_phase
        super
      rescue NoRawData => e
        fail!(:no_raw_data, e)
      end

      def info_headers
        {
          'Authorization' => "Bearer #{access_token.token}"
        }
      end

      def rquid
        @rquid ||= SecureRandom.hex(16)
      end
    end
  end
end
