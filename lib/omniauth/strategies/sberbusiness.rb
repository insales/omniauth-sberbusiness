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
             client_info_path: '/fintech/api/v1/client-info'

      option :authorize_options, %i[scope response_type client_type client_id state nonce]

      option :redirect_url, nil

      uid { user_info['sub'].to_s }

      def client
        change_links if options.test
        change_auth_link_when_token if request.params['userType'] == 'Token'
        client = super
        logger = ActiveSupport::TaggedLogging.new(Rails.logger)
        logger.push_tags('Sberbusiness Auth')
        client.connection.response :logger, logger, { bodies: true, log_level: :debug }
        client
      end

      # https://github.com/intridea/omniauth/wiki/Auth-Hash-Schema
      info do
        {
          name: user_info['name'],
          org_full_name: user_info['orgFullName'],
          org_name: user_info['OrgName'],
          org_kpp: user_info['orgKpp'],
          org_ogrn: user_info['orgOgrn'],
          org_actual_address: user_info['orgActualAddress'],
          org_juridical_address: user_info['orgJuridicalAddress'],
          phone_number: user_info['phone_number'],
          email: user_info['email'],
          accounts: user_info['accounts'],
          id: user_info['sub'],
          inn: user_info['inn'],
          bank: user_info['terBank'],
          org_id: user_info['orgId'],
          org_id_hash: user_info['HashOrgId'],
          provider: options.name
        }
      end

      extra do
        {
          'credentials' => credentials,
          'user_info' => user_info,
          'client_info' => client_info,
          'sbbol_headers' => sbbol_headers,
          'sbbol_signature' => sbbol_signature
        }
      end

      def client_info
        return unless options.scope.include? 'GET_CLIENT_ACCOUNTS'

        access_token.options[:mode] = :header
        client_info_path = options.client_options['client_info_path']
        JSON.parse(access_token.get(client_info_path, headers: info_headers).body.force_encoding('UTF-8'))
      end

      def raw_info
        access_token.options[:mode] = :header
        @raw_info ||= begin
          result = access_token.get(options.client_options['user_info_path'], headers: info_headers).body
          data = result.split('.')
          raise 'Raw data size error' if data.length != 3

          data
        end
      end

      def sbbol_headers
        @sbbol_headers ||= begin
          return if raw_info[0].blank?

          decrypt(raw_info[0])
        end
      end

      def user_info
        @user_info ||= begin
          return if raw_info[1].blank?

          decrypt(raw_info[1])
        end
      end

      def sbbol_signature
        @sbbol_signature ||= begin
          return if raw_info[2].blank?

          raw_info[2]
        end
      end

      def decrypt(msg)
        JSON.parse(Base64.urlsafe_decode64(msg).force_encoding(Encoding::UTF_8))
      end

      def authorize_params
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
        return options.redirect_url + query_string if options.redirect_url.present?

        full_host + script_name + callback_path + query_string
      end

      def query_string
        redirect_uri = URI(options.redirect_url)
        redirect_params = Rack::Utils.parse_nested_query(redirect_uri.query)
        params = request.params.except('state', 'nonce', 'code', *redirect_params.keys)
        return '' if params.empty?

        (redirect_params.empty? ? '?' : '&') + params.to_query
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

      def change_auth_link_when_token
        options.client_options[:authorize_url] = "http://localhost:#{request.params['callbackPort']}/ic/sso/api/v2/oauth/authorize"
      end
    end
  end
end
