# frozen_string_literal: true

require 'omniauth/strategies/oauth2'
require 'securerandom'
require 'base64'

module OmniAuth
  module Strategies
    class Sberbusiness < OmniAuth::Strategies::OAuth2
      class NoRawData < StandardError; end

      API_VERSION = '1.0'

      DEFAULT_SCOPE = 'openid inn email'

      option :name, 'sberbusiness'

      option :client_options,
             site: 'https://edupirfintech.sberbank.ru:9443', # 'https://edupir.testsbi.sberbank.ru:9443', # 'https://sbi.sberbank.ru:9443',
             token_url: 'https://edupirfintech.sberbank.ru:9443/ic/sso/api/v2/oauth/token', # https://edupirfintech.sberbank.ru:9443 https://sbi.sberbank.ru:9443/ic/sso/api/v2/oauth/token
             authorize_url: 'https://edupir.testsbi.sberbank.ru:9443/ic/sso/api/v2/oauth/authorize'
             # 'https://edupir.testsbi.sberbank.ru:9443/ic/sso/api/v2/oauth/authorize' # 'https://sbi.sberbank.ru:9443/ic/sso/api/v2/oauth/authorize'

      option :authorize_options, %i[scope response_type client_type client_id state nonce]

      option :redirect_url, nil

      uid { raw_info['sub'].to_s }

      # https://github.com/intridea/omniauth/wiki/Auth-Hash-Schema
      info do
        {
          name: raw_info['name'],
          orgFullName: raw_info['orgFullName'],
          OrgName: raw_info['OrgName'],
          orgKpp: raw_info['orgKpp'],
          orgOgrn: raw_info['orgOgrn'],
          orgActualAddress: raw_info['orgActualAddress'],
          orgJuridicalAddress: raw_info['orgJuridicalAddress'],
          phone_number: raw_info['phone_number'],
          email: raw_info['email'],
          accounts: raw_info['accounts'],
          id: raw_info['sub'],
          inn: raw_info['inn'],
          client_host: raw_info['state'],
          provider: 'sberbusiness'
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      # https://developer.sberbank.ru/doc/v1/sberbank-id/datareq
      def raw_info
        access_token.options[:mode] = :header
        @raw_info ||= begin
          state = request.params['state']
          result = access_token.get('/ic/sso/api/v2/oauth/user-info', headers: info_headers).body
          # декодируем ответ:
          decoded_data = result.split('.').map { |code| decrypt(code) rescue {}}
          result = decoded_data.reduce(:merge)
          result['state'] = state
          result
        end
      end

      def decrypt(msg)
        JSON.parse(Base64.urlsafe_decode64(msg).force_encoding(Encoding::UTF_8))
      end

      # https://developer.sberbank.ru/doc/v1/sberbank-id/authcodereq
      def authorize_params
        super.tap do |params|
          %w[state scope response_type client_type client_id nonce].each do |v|
            next unless request.params[v]

            params[v.to_sym] = request.params[v]
          end
          params[:scope] ||= DEFAULT_SCOPE
          # if you want redirect to other host and save old host
          state = session['omniauth.origin'] || env['HTTP_REFERER']
          params[:state] = state
          session['omniauth.state'] = state
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

      def callback_url
        options.redirect_url || (full_host + script_name + callback_path)
      end

      def info_options
        # https://developer.sberbank.ru/doc/v1/sberbank-id/dataanswerparametrs
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
